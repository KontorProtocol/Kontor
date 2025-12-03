use anyhow::Result;
use bitcoin::TxOut;
use bitcoin::consensus::encode::serialize as serialize_tx;
use bitcoin::key::Secp256k1;
use bitcoin::taproot::TaprootBuilder;
use indexer::api::compose::{ComposeQuery, InstructionQuery, RevealParticipantQuery, RevealQuery};
use indexer::bitcoin_client::client::RegtestRpc;
use indexer::database::types::OpResultId;
use indexer::test_utils;
use indexer_types::{Inst, serialize};
use testlib::*;

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../native-contracts/token/wit",
);

pub async fn test_compose_token_attach_and_detach(
    runtime: &mut Runtime,
    reg_tester: &mut RegTester,
) -> Result<()> {
    let secp = Secp256k1::new();

    let mut identity = reg_tester.identity().await?;
    reg_tester
        .instruction(&mut identity, Inst::Issuance)
        .await?;

    let seller_address = identity.address;
    let keypair = identity.keypair;
    let (internal_key, _parity) = keypair.x_only_public_key();
    let (out_point, utxo_for_output) = identity.next_funding_utxo;

    let buyer_identity = reg_tester.identity().await?;

    let attach_inst = Inst::Call {
        gas_limit: 50_000,
        contract: indexer_types::ContractAddress {
            name: "token".to_string(),
            height: 0,
            tx_index: 0,
        },
        expr: format!(
            "{}({})",
            "attach",
            [
                stdlib::wasm_wave::to_string(&stdlib::wasm_wave::value::Value::from(0)).unwrap(),
                stdlib::wasm_wave::to_string(&stdlib::wasm_wave::value::Value::from(
                    Decimal::from(2)
                ))
                .unwrap()
            ]
            .join(", ")
        ),
    };

    let detach_inst = Inst::Call {
        gas_limit: 50_000,
        contract: indexer_types::ContractAddress {
            name: "token".to_string(),
            height: 0,
            tx_index: 0,
        },
        expr: "detach()".to_string(),
    };

    let query = ComposeQuery::builder()
        .instructions(vec![
            InstructionQuery::builder()
                .address(seller_address.to_string())
                .x_only_public_key(internal_key.to_string())
                .funding_utxo_ids(format!("{}:{}", out_point.txid, out_point.vout))
                .instruction(attach_inst.clone())
                .chained_instruction(detach_inst.clone())
                .build(),
        ])
        .sat_per_vbyte(2)
        .envelope(600)
        .build();

    let compose_outputs = reg_tester.compose(query).await?;

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
            indexer_types::OpReturnData::PubKey(buyer_identity.x_only_public_key()),
        )])?),
        envelope: None,
    };

    let detach_outputs = reg_tester.compose_reveal(reveal_query).await?;
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

    let result = reg_tester
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

    let bitcoin_client = reg_tester.bitcoin_client().await;
    bitcoin_client.send_raw_transaction(&commit_tx_hex).await?;
    bitcoin_client.send_raw_transaction(&reveal_tx_hex).await?;
    bitcoin_client
        .generate_to_address(1, &seller_address.to_string())
        .await?;
    let id = OpResultId::builder()
        .txid(reveal_transaction.compute_txid().to_string())
        .build();

    reg_tester.wait_next_block().await?;
    let attach_result = reg_tester
        .kontor_client()
        .await
        .result(&id)
        .await?
        .ok_or(anyhow::anyhow!("Could not find op result"))?;

    let attach_result: Result<token::Transfer, testlib::Error> =
        stdlib::wasm_wave::wasm::WasmValue::unwrap_result(
            &stdlib::wasm_wave::from_str::<stdlib::wasm_wave::value::Value>(
                &stdlib::wasm_wave::value::Type::result(
                    Some(<token::Transfer>::wave_type()),
                    Some(<testlib::Error>::wave_type()),
                ),
                &attach_result.value.expect("Expected value"),
            )
            .unwrap(),
        )
        .map(|v| v.unwrap().into_owned().into())
        .map_err(|e| e.unwrap().into_owned().into());
    let transfer = attach_result?;

    let utxo_id = format!("{}:{}", reveal_transaction.compute_txid(), 0);

    assert_eq!(transfer.src, internal_key.to_string());
    assert_eq!(transfer.dst, utxo_id);

    let balance = token::balance(runtime, &utxo_id).await?;
    assert_eq!(balance, Some(Decimal::from(2)));

    bitcoin_client.send_raw_transaction(&detach_tx_hex).await?;

    bitcoin_client
        .generate_to_address(1, &seller_address.to_string())
        .await?;

    let id = OpResultId::builder()
        .txid(detach_transaction.compute_txid().to_string())
        .build();

    reg_tester.wait_next_block().await?;
    let detach_result = reg_tester
        .kontor_client()
        .await
        .result(&id)
        .await?
        .ok_or(anyhow::anyhow!("Could not find op result"))?;

    let detach_result: Result<token::Transfer, testlib::Error> =
        stdlib::wasm_wave::wasm::WasmValue::unwrap_result(
            &stdlib::wasm_wave::from_str::<stdlib::wasm_wave::value::Value>(
                &stdlib::wasm_wave::value::Type::result(
                    Some(<token::Transfer>::wave_type()),
                    Some(<testlib::Error>::wave_type()),
                ),
                &detach_result.value.expect("Expected value"),
            )
            .unwrap(),
        )
        .map(|v| v.unwrap().into_owned().into())
        .map_err(|e| e.unwrap().into_owned().into());
    let transfer = detach_result?;

    assert_eq!(transfer.src, utxo_id);
    assert_eq!(transfer.dst, buyer_identity.x_only_public_key().to_string());

    let balance = token::balance(runtime, &buyer_identity.x_only_public_key().to_string()).await?;
    assert_eq!(balance, Some(Decimal::from(2)));

    Ok(())
}

#[testlib::test(contracts_dir = "test-contracts", mode = "regtest")]
async fn test_native_token_attach_contract_regtest() -> Result<()> {
    test_compose_token_attach_and_detach(runtime, &mut reg_tester).await
}
