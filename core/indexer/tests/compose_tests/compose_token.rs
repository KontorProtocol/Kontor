use anyhow::Result;
use bitcoin::TxOut;
use bitcoin::consensus::encode::serialize as serialize_tx;
use bitcoin::key::Secp256k1;
use bitcoin::taproot::TaprootBuilder;
use indexer::api::compose::{ComposeQuery, InstructionQuery, RevealParticipantQuery, RevealQuery};
use indexer::bitcoin_client::client::RegtestRpc;
use indexer::reactor::types::Op;
use indexer::test_utils;
use indexer_types::{ContractAddress, Inst, OpReturnData, serialize};
use testlib::RegTester;

pub async fn test_compose_token_attach_and_detach(reg_tester: &mut RegTester) -> Result<()> {
    let secp = Secp256k1::new();

    let mut identity = reg_tester.identity().await?;
    reg_tester
        .instruction(&mut identity, Inst::Issuance)
        .await?;

    let seller_address = identity.address;
    let keypair = identity.keypair;
    let (internal_key, _parity) = keypair.x_only_public_key();
    let (out_point, utxo_for_output) = identity.next_funding_utxo;

    let attach_inst = Inst::Call {
        gas_limit: 50_000,
        contract: ContractAddress {
            name: "token".to_string(),
            height: 0,
            tx_index: 0,
        },
        expr: "attach(0, 10)".to_string(),
    };

    let detach_inst = Inst::Call {
        gas_limit: 50_000,
        contract: ContractAddress {
            name: "token".to_string(),
            height: 0,
            tx_index: 0,
        },
        expr: "detach()".to_string(),
    };

    let query = ComposeQuery::builder()
        .instructions(vec![InstructionQuery {
            address: seller_address.to_string(),
            x_only_public_key: internal_key.to_string(),
            funding_utxo_ids: format!("{}:{}", out_point.txid, out_point.vout),
            script_data: attach_inst.clone(),
        }])
        .sat_per_vbyte(2)
        .envelope(600)
        .chained_script_data(detach_inst.clone())
        .build();

    let compose_outputs = reg_tester.compose(query).await?;

    let mut commit_transaction = compose_outputs.commit_transaction;
    let mut reveal_transaction = compose_outputs.reveal_transaction;
    let tap_script = compose_outputs.per_participant[0].commit.tap_script.clone();
    let chained_tap_script = compose_outputs.per_participant[0]
        .chained
        .as_ref()
        .unwrap()
        .tap_script
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
        participants: vec![RevealParticipantQuery {
            address: seller_address.to_string(),
            x_only_public_key: internal_key.to_string(),
            commit_vout: 0,
            commit_script_data: chained_script_data_bytes,
            envelope: None,
        }],
        op_return_data: Some(serialize(&OpReturnData::PubKey(internal_key))?),
        envelope: None,
        chained_script_data: None,
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
    bitcoin_client.send_raw_transaction(&detach_tx_hex).await?;
    bitcoin_client
        .generate_to_address(1, &seller_address.to_string())
        .await?;

    let attach_ops = reg_tester.transaction_hex_inspect(&reveal_tx_hex).await?;
    assert_eq!(attach_ops.len(), 1, "Expected one op in reveal transaction");
    if let Op::Call { expr, .. } = &attach_ops[0].op {
        assert_eq!(expr, "attach(0, 10)", "Expected attach(0, 10) call");
    } else {
        panic!("Expected Call op for attach(), got {:?}", attach_ops[0].op);
    }
    assert!(
        attach_ops[0].result.is_some(),
        "Expected attach() to have a result"
    );

    let ops = reg_tester.transaction_hex_inspect(&detach_tx_hex).await?;
    assert_eq!(ops.len(), 1, "Expected one op in detach transaction");
    if let Op::Call { expr, .. } = &ops[0].op {
        assert_eq!(expr, "detach()", "Expected detach() call");
    } else {
        panic!("Expected Call op for detach(), got {:?}", ops[0].op);
    }
    assert!(
        ops[0].result.is_some(),
        "Expected detach() to have a result"
    );

    Ok(())
}
