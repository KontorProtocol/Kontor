use anyhow::Result;
use bitcoin::TxOut;
use bitcoin::consensus::encode::serialize as serialize_tx;
use bitcoin::key::Secp256k1;
use bitcoin::taproot::TaprootBuilder;
use indexer::database::types::OpResultId;
use indexer::test_utils;
use indexer::{bitcoin_client::client::RegtestRpc, runtime};
use indexer_types::{
    ComposeQuery, Inst, InstructionQuery, Insts, RevealParticipantQuery, RevealQuery, serialize,
};
use testlib::*;

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/token/wit",
);

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn test_native_token_attach_contract() -> Result<()> {
    let secp = Secp256k1::new();

    let rt = runtime.reg_tester().unwrap();

    let identity = rt.identity().await?;
    let buyer_identity = rt.identity().await?;
    let seller_address = identity.address;
    let keypair = identity.keypair;
    let (out_point, utxo_for_output) = identity.next_funding_utxo;
    let buyer_x_only = buyer_identity.x_only_public_key();

    let (internal_key, _parity) = keypair.x_only_public_key();

    let attach_inst = Inst::Call {
        gas_limit: 50_000,
        contract: runtime::token::address().into(),
        nonce: None,
        expr: token::wave::attach_call_expr(0, 2u64.try_into().unwrap()),
    };

    let detach_inst = Inst::Call {
        gas_limit: 50_000,
        contract: runtime::token::address().into(),
        nonce: None,
        expr: token::wave::detach_call_expr(),
    };

    let query = ComposeQuery::builder()
        .instructions(vec![
            InstructionQuery::builder()
                .address(seller_address.to_string())
                .x_only_public_key(internal_key.to_string())
                .funding_utxo_ids(format!("{}:{}", out_point.txid, out_point.vout))
                .insts(Insts::single(attach_inst.clone()))
                .chained_insts(Insts::single(detach_inst.clone()))
                .build(),
        ])
        .sat_per_vbyte(2)
        .envelope(600)
        .build();

    let compose_outputs = rt.compose(query).await?;

    let mut commit_transaction = compose_outputs.commit_transaction;
    let mut reveal_transaction = compose_outputs.reveal_transaction;
    let tap_script = compose_outputs.per_participant[0]
        .commit_tap_leaf_script
        .script
        .clone();
    let chained_tap_script = compose_outputs.per_participant[0]
        .chained_tap_leaf_script
        .as_ref()
        .unwrap()
        .script
        .clone();

    let commit_prevout = TxOut {
        value: utxo_for_output.value,
        script_pubkey: seller_address.script_pubkey(),
    };

    test_utils::sign_key_spend(
        &secp,
        &mut commit_transaction,
        &[commit_prevout],
        &keypair,
        0,
        None,
    )?;

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .map_err(|e| anyhow::anyhow!("Failed to add leaf: {}", e))?
        .finalize(&secp, internal_key)
        .map_err(|e| anyhow::anyhow!("Failed to finalize Taproot tree: {:?}", e))?;

    test_utils::sign_script_spend(
        &secp,
        &taproot_spend_info,
        &tap_script,
        &mut reveal_transaction,
        &[commit_transaction.output[0].clone()],
        &keypair,
        0,
    )?;

    let commit_tx_hex = hex::encode(serialize_tx(&commit_transaction));
    let reveal_tx_hex = hex::encode(serialize_tx(&reveal_transaction));

    let chained_script_data_bytes = serialize(&detach_inst)?;

    let reveal_query = RevealQuery {
        commit_tx_hex: reveal_tx_hex.clone(),
        sat_per_vbyte: 2,
        participants: vec![
            RevealParticipantQuery::builder()
                .address(seller_address.to_string())
                .x_only_public_key(internal_key.to_string())
                .commit_vout(0)
                .commit_script_data(chained_script_data_bytes)
                .build(),
        ],
        op_return_data: Some(serialize(&vec![(
            0,
            indexer_types::OpReturnData::PubKey(buyer_x_only),
        )])?),
        envelope: None,
    };

    let detach_outputs = rt.compose_reveal(reveal_query).await?;
    let mut detach_transaction = detach_outputs.transaction;

    assert_eq!(detach_transaction.input.len(), 1);
    assert_eq!(
        detach_transaction.input[0].previous_output.txid,
        reveal_transaction.compute_txid()
    );

    let chained_taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, chained_tap_script.clone())
        .map_err(|e| anyhow::anyhow!("Failed to add leaf: {}", e))?
        .finalize(&secp, internal_key)
        .map_err(|e| anyhow::anyhow!("Failed to finalize Taproot tree: {:?}", e))?;

    test_utils::sign_script_spend(
        &secp,
        &chained_taproot_spend_info,
        &chained_tap_script,
        &mut detach_transaction,
        &[reveal_transaction.output[0].clone()],
        &keypair,
        0,
    )?;

    let detach_tx_hex = hex::encode(serialize_tx(&detach_transaction));

    let result = rt
        .mempool_accept_result(&[
            commit_tx_hex.clone(),
            reveal_tx_hex.clone(),
            detach_tx_hex.clone(),
        ])
        .await?;

    assert_eq!(result.len(), 3, "Expected three transaction results");
    assert!(result[0].allowed, "Commit transaction was rejected");
    assert!(result[1].allowed, "Reveal transaction was rejected");
    assert!(result[2].allowed, "Detach transaction was rejected");

    let bitcoin_client = rt.bitcoin_client().await;
    bitcoin_client.send_raw_transaction(&commit_tx_hex).await?;
    bitcoin_client.send_raw_transaction(&reveal_tx_hex).await?;
    bitcoin_client
        .generate_to_address(1, &seller_address.to_string())
        .await?;
    let reveal_txid = reveal_transaction.compute_txid().to_string();
    let id = OpResultId::builder().txid(reveal_txid.clone()).build();

    rt.wait_for_txids(&[reveal_txid]).await?;
    let attach_result = rt
        .kontor_client()
        .await
        .result(&id)
        .await?
        .ok_or(anyhow::anyhow!("Could not find op result"))?;

    let transfer =
        token::wave::attach_parse_return_expr(&attach_result.value.expect("Expected value"))?;

    let utxo_id = format!("{}:{}", reveal_transaction.compute_txid(), 0);

    assert_eq!(transfer.src, internal_key.to_string());
    assert_eq!(transfer.dst, utxo_id);

    let balance = token::balance(runtime, &utxo_id).await?;
    assert_eq!(balance, Some(2u64.try_into().unwrap()));

    let buyer_balance_before = token::balance(runtime, &buyer_x_only.to_string())
        .await?
        .unwrap_or(0u64.try_into().unwrap());

    let bitcoin_client = rt.bitcoin_client().await;
    bitcoin_client.send_raw_transaction(&detach_tx_hex).await?;
    bitcoin_client
        .generate_to_address(1, &seller_address.to_string())
        .await?;

    let detach_txid = detach_transaction.compute_txid().to_string();
    let id = OpResultId::builder().txid(detach_txid.clone()).build();

    rt.wait_for_txids(&[detach_txid]).await?;
    let detach_result = rt
        .kontor_client()
        .await
        .result(&id)
        .await?
        .ok_or(anyhow::anyhow!("Could not find op result"))?;

    let transfer =
        token::wave::detach_parse_return_expr(&detach_result.value.expect("Expected value"))?;

    assert_eq!(transfer.src, utxo_id);
    assert_eq!(transfer.dst, buyer_x_only.to_string());

    let buyer_balance_after = token::balance(runtime, &buyer_x_only.to_string())
        .await?
        .unwrap();
    assert_eq!(
        buyer_balance_after - buyer_balance_before,
        2u64.try_into().unwrap()
    );

    Ok(())
}
