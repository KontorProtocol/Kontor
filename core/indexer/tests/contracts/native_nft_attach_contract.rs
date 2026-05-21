use anyhow::Result;
use bitcoin::TxOut;
use bitcoin::consensus::encode::serialize as serialize_tx;
use bitcoin::key::Secp256k1;
use bitcoin::taproot::TaprootBuilder;
use indexer::database::types::OpResultId;
use indexer::test_utils;
use indexer::{bitcoin_client::client::RegtestRpc, runtime};
use indexer_types::{
    ComposeQuery, Inst, InstKind, InstructionQuery, Insts, PaymentIntent, RevealParticipantQuery,
    RevealQuery, serialize,
};
use testlib::*;

import!(
    name = "nft",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/nft/wit",
);

#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn test_native_nft_attach_contract() -> Result<()> {
    let secp = Secp256k1::new();

    let mut rt = runtime.reg_tester().unwrap();

    let mut identity = rt.identity().await?;
    let buyer_identity = rt.identity().await?;
    let seller_address = identity.address.clone();
    let keypair = identity.keypair;
    let buyer_x_only = buyer_identity.x_only_public_key();

    let (internal_key, _parity) = keypair.x_only_public_key();

    // Pre-mint an NFT to the seller via a raw instruction. We mint with the
    // seller's `reg_tester::Identity` directly so the same identity (and its
    // funding UTXO) can drive the subsequent Bitcoin attach/detach flow. The
    // host-side `nft::mint(runtime, &signer, ...)` helper requires a `Signer`
    // registered in the regtest runtime's identity map, which doesn't match
    // an identity popped via `rt.identity()`, hence the raw Inst here.
    let nft_id = "attach-nft-1".to_string();
    let file_id = "attach_nft_file_1";
    let attributes = vec![
        nft::Attribute {
            key: "name".to_string(),
            value: "Attachable NFT".to_string(),
        },
        nft::Attribute {
            key: "series".to_string(),
            value: "attach-test".to_string(),
        },
    ];
    let file_descriptor = test_utils::make_descriptor(
        file_id.to_string(),
        vec![1u8; 32],
        16,
        10,
        format!("{file_id}.txt"),
    );
    let mint_inst = Inst {
        payment: PaymentIntent::self_pay(50_000),
        kind: InstKind::Call {
            contract: runtime::nft::address().into(),
            expr: nft::wave::mint_call_expr(&nft_id, attributes, file_descriptor),
        },
    };
    rt.instruction(&mut identity, mint_inst).await?;
    // The mint is a `Call` op, so `rt.instruction` batches it via consensus
    // without mining a Bitcoin block — leaving the mint's commit/reveal txs
    // unconfirmed in the mempool. `identity.next_funding_utxo` now points at
    // the mint-commit's change output, which is also unconfirmed. The
    // attach/detach flow below builds a Bitcoin tx chain rooted on that
    // funding UTXO; if it stays unconfirmed, acceptance depends on
    // cross-node mempool propagation timing (flaky on slower CI runners).
    // Mine a block so the mint is confirmed and the funding UTXO is solid.
    rt.mine(1).await?;

    let seller_signer_id = rt
        .get_signer_id(&internal_key.to_string())
        .await?
        .expect("seller signer_id");
    let info_after_mint = nft::get_info(runtime, &nft_id)
        .await?
        .expect("nft should exist after mint");
    assert_eq!(info_after_mint.owner, HolderRef::SignerId(seller_signer_id));

    let (out_point, utxo_for_output) = identity.next_funding_utxo.clone();

    let attach_inst = Inst {
        payment: PaymentIntent::self_pay(50_000),
        kind: InstKind::Call {
            contract: runtime::nft::address().into(),
            expr: nft::wave::attach_call_expr(&nft_id, 0),
        },
    };

    let detach_inst = Inst {
        payment: PaymentIntent::self_pay(50_000),
        kind: InstKind::Call {
            contract: runtime::nft::address().into(),
            expr: nft::wave::detach_call_expr(&nft_id),
        },
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
        sat_per_vbyte: Some(2),
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
        nft::wave::attach_parse_return_expr(&attach_result.value.expect("Expected value"))?;

    let utxo_id = format!("{}:{}", reveal_transaction.compute_txid(), 0);

    assert_eq!(transfer.nft_id, nft_id);
    assert_eq!(transfer.src, HolderRef::SignerId(seller_signer_id));
    let utxo_ref = OutPoint {
        txid: reveal_transaction.compute_txid().to_string(),
        vout: 0,
    };
    assert_eq!(transfer.dst, HolderRef::Utxo(utxo_ref.clone()));

    let info_after_attach = nft::get_info(runtime, &nft_id)
        .await?
        .expect("nft should still exist after attach");
    assert_eq!(info_after_attach.owner, HolderRef::Utxo(utxo_ref));

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
        nft::wave::detach_parse_return_expr(&detach_result.value.expect("Expected value"))?;

    assert_eq!(transfer.nft_id, nft_id);
    assert_eq!(transfer.src.to_string(), utxo_id);
    let buyer_signer_id = rt
        .get_signer_id(&buyer_x_only.to_string())
        .await?
        .expect("buyer signer_id");
    assert_eq!(transfer.dst, HolderRef::SignerId(buyer_signer_id));

    let info_after_detach = nft::get_info(runtime, &nft_id)
        .await?
        .expect("nft should still exist after detach");
    assert_eq!(
        info_after_detach.owner,
        HolderRef::SignerId(buyer_signer_id)
    );

    Ok(())
}
