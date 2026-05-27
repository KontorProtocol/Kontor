use anyhow::Result;
use bitcoin::TxOut;
use bitcoin::consensus::encode::serialize as serialize_tx;
use bitcoin::key::Secp256k1;
use bitcoin::taproot::TaprootBuilder;
use indexer::database::types::OpResultId;
use indexer::test_utils;
use indexer::{bitcoin_client::client::RegtestRpc, runtime};
use indexer_types::{
    CommitSource, Inst, InstKind, Insts, Reveal, RevealOutput, RevealOutputInfo, RevealParticipant,
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

    // Revoke / self round-trip: one identity attaches the asset to a UTXO
    // and immediately detaches it back. Under the Sponsor + ctx.payer()
    // model the detach has no Sponsor and the seller signs the escrow
    // input, so the default payer = signer = seller, and the asset
    // returns to the seller. See task #34 for the swap-path companion
    // (cross-input Sponsor → payer = buyer).
    let identity = rt.identity().await?;
    let seller_address = identity.address;
    let keypair = identity.keypair;
    let (out_point, utxo_for_output) = identity.next_funding_utxo;

    let (internal_key, _parity) = keypair.x_only_public_key();

    let attach_inst = Inst {
        gas_limit: 50_000,
        kind: InstKind::Call {
            contract: runtime::token::address().into(),
            expr: token::wave::attach_call_expr(0, 2u64.try_into().unwrap()),
        },
    };

    let detach_inst = Inst {
        gas_limit: 50_000,
        kind: InstKind::Call {
            contract: runtime::token::address().into(),
            expr: token::wave::detach_call_expr(),
        },
    };

    // Build the seller's attach + chained-detach reveal under the v2
    // API. Single Build participant carrying the attach inst; the
    // chained envelope (escrow committing to detach) and the Change to
    // the seller go in extra_outputs.
    let reveal = Reveal::builder()
        .sat_per_vbyte(2)
        .participants(vec![
            RevealParticipant::builder()
                .x_only_public_key(internal_key.to_string())
                .commit_insts(Insts::single(attach_inst.clone()))
                .commit_source(CommitSource::build(&seller_address, [out_point]))
                .build(),
        ])
        .extra_outputs(vec![
            RevealOutput::chained_envelope(Insts::single(detach_inst.clone()), 600, internal_key),
            RevealOutput::change(&seller_address.script_pubkey()),
        ])
        .build();

    let compose_outputs = rt.compose(reveal).await?;

    let mut commit_transaction = compose_outputs.commits[0].transaction.clone();
    let mut reveal_transaction = compose_outputs.reveal.transaction.clone();
    let reveal_psbt = bitcoin::Psbt::deserialize(&hex::decode(
        &compose_outputs.reveal.psbt_hex,
    )?)?;
    let (tap_script, _) =
        indexer::test_utils::participant_tap_script(&reveal_psbt.inputs[0])?;
    // The chained leaf lives in the reveal's output_info: position 0 of
    // the reveal tx is the ChainedEnvelope we declared in extra_outputs.
    let RevealOutputInfo::ChainedEnvelope { tap_leaf_script, .. } =
        &compose_outputs.reveal.output_info[0]
    else {
        panic!("output 0 should be ChainedEnvelope");
    };
    let chained_tap_script = tap_leaf_script.script.clone();

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

    // Detach reveal under v2: single Existing participant (spending the
    // attach reveal's escrow output via the chained detach leaf), with
    // a paired Change output back to the seller. The seller's signer
    // signs the detach, no Sponsor, so ctx.payer() defaults to the
    // seller — asset returns to them.
    let detach_reveal = Reveal::builder()
        .sat_per_vbyte(2)
        .participants(vec![
            RevealParticipant::builder()
                .x_only_public_key(internal_key.to_string())
                .commit_insts(Insts::single(detach_inst.clone()))
                .output(RevealOutput::change(&seller_address.script_pubkey()))
                .commit_source(CommitSource::existing(
                    bitcoin::OutPoint {
                        txid: reveal_transaction.compute_txid(),
                        vout: 0,
                    },
                    reveal_transaction.output[0].clone(),
                ))
                .build(),
        ])
        .build();

    let detach_outputs = rt.compose_reveal(detach_reveal).await?;
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
    assert!(
        result[0].allowed,
        "Commit transaction was rejected: {:?}",
        result[0].reject_reason
    );
    assert!(
        result[1].allowed,
        "Reveal transaction was rejected: {:?}",
        result[1].reject_reason
    );
    assert!(
        result[2].allowed,
        "Detach transaction was rejected: {:?}",
        result[2].reject_reason
    );

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

    let seller_signer_id = rt
        .get_signer_id(&internal_key.to_string())
        .await?
        .expect("seller signer_id");
    assert_eq!(transfer.src, HolderRef::SignerId(seller_signer_id));
    let utxo_ref = OutPoint {
        txid: reveal_transaction.compute_txid().to_string(),
        vout: 0,
    };
    assert_eq!(transfer.dst, HolderRef::Utxo(utxo_ref.clone()));

    let balance = token::balance(runtime, HolderRef::Utxo(utxo_ref)).await?;
    assert_eq!(balance, Some(2u64.try_into().unwrap()));

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

    // The detach credited the seller in full (contract-reported `amt`).
    // We don't compare the seller's net ledger delta because the same
    // identity also paid gas for this op, which burns a small amount
    // from their balance — that gas burn is correct behaviour under the
    // new payer model and would mask the 2-token credit.
    assert_eq!(transfer.src.to_string(), utxo_id);
    assert_eq!(transfer.dst, HolderRef::SignerId(seller_signer_id));
    assert_eq!(transfer.amt, 2u64.try_into().unwrap());

    Ok(())
}
