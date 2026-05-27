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

/// Swap path: a cross-input `Sponsor` from the buyer redirects the
/// payer for the seller's detach. End-to-end, this proves both halves
/// of the redesign in one tx:
///
///   - **Routing**: `ctx.payer()` inside detach resolves to the buyer
///     (Sponsor's signer), so the asset is credited to the buyer.
///   - **Billing**: the buyer is debited for the detach's gas; the
///     seller's native balance is untouched (the Sponsor input pays).
///
/// Shape of the swap tx:
///
///   input 0 — buyer's commit, script-spent via the `Sponsor` leaf
///   input 1 — seller's attach reveal output 0, script-spent via the
///             chained detach leaf
///   output 0 — change back to buyer (the swap doesn't carry a price
///              in this test; that's the marketplace concern, not the
///              protocol concern under exercise here)
#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn test_native_token_sponsor_swap() -> Result<()> {
    let secp = Secp256k1::new();
    let rt = runtime.reg_tester().unwrap();

    // ── Phase 1: seller publishes the attach ──
    let seller_identity = rt.identity().await?;
    let seller_address = seller_identity.address.clone();
    let seller_keypair = seller_identity.keypair;
    let (seller_funding_outpoint, seller_funding_utxo) = seller_identity.next_funding_utxo.clone();
    let (seller_internal_key, _) = seller_keypair.x_only_public_key();

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

    let seller_reveal = Reveal::builder()
        .sat_per_vbyte(2)
        .participants(vec![
            RevealParticipant::builder()
                .x_only_public_key(seller_internal_key.to_string())
                .commit_insts(Insts::single(attach_inst.clone()))
                .commit_source(CommitSource::build(
                    &seller_address,
                    [seller_funding_outpoint],
                ))
                .build(),
        ])
        .extra_outputs(vec![
            RevealOutput::chained_envelope(
                Insts::single(detach_inst.clone()),
                600,
                seller_internal_key,
            ),
            RevealOutput::change(&seller_address.script_pubkey()),
        ])
        .build();

    let seller_compose = rt.compose(seller_reveal).await?;

    let mut seller_commit_tx = seller_compose.commits[0].transaction.clone();
    let mut seller_attach_reveal_tx = seller_compose.reveal.transaction.clone();
    let seller_reveal_psbt = bitcoin::Psbt::deserialize(&hex::decode(
        &seller_compose.reveal.psbt_hex,
    )?)?;
    let (seller_attach_leaf, _) =
        indexer::test_utils::participant_tap_script(&seller_reveal_psbt.inputs[0])?;
    let RevealOutputInfo::ChainedEnvelope { tap_leaf_script, .. } =
        &seller_compose.reveal.output_info[0]
    else {
        panic!("output 0 should be ChainedEnvelope");
    };
    let seller_detach_leaf = tap_leaf_script.script.clone();

    test_utils::sign_key_spend(
        &secp,
        &mut seller_commit_tx,
        &[TxOut {
            value: seller_funding_utxo.value,
            script_pubkey: seller_address.script_pubkey(),
        }],
        &seller_keypair,
        0,
        None,
    )?;

    let seller_attach_tap_info = TaprootBuilder::new()
        .add_leaf(0, seller_attach_leaf.clone())
        .map_err(|e| anyhow::anyhow!("seller attach taproot: {e}"))?
        .finalize(&secp, seller_internal_key)
        .map_err(|e| anyhow::anyhow!("seller attach finalize: {e:?}"))?;

    test_utils::sign_script_spend(
        &secp,
        &seller_attach_tap_info,
        &seller_attach_leaf,
        &mut seller_attach_reveal_tx,
        &[seller_commit_tx.output[0].clone()],
        &seller_keypair,
        0,
    )?;

    let seller_commit_tx_hex = hex::encode(serialize_tx(&seller_commit_tx));
    let seller_attach_reveal_tx_hex = hex::encode(serialize_tx(&seller_attach_reveal_tx));

    let bitcoin_client = rt.bitcoin_client().await;
    bitcoin_client
        .send_raw_transaction(&seller_commit_tx_hex)
        .await?;
    bitcoin_client
        .send_raw_transaction(&seller_attach_reveal_tx_hex)
        .await?;
    bitcoin_client
        .generate_to_address(1, &seller_address.to_string())
        .await?;

    let attach_reveal_txid = seller_attach_reveal_tx.compute_txid().to_string();
    rt.wait_for_txids(std::slice::from_ref(&attach_reveal_txid))
        .await?;

    // Sanity: the attach landed and the asset is at the escrow UTXO.
    let attach_result = rt
        .kontor_client()
        .await
        .result(&OpResultId::builder().txid(attach_reveal_txid).build())
        .await?
        .ok_or(anyhow::anyhow!("attach result missing"))?;
    let attach_transfer =
        token::wave::attach_parse_return_expr(&attach_result.value.expect("attach value"))?;
    let utxo_ref = OutPoint {
        txid: seller_attach_reveal_tx.compute_txid().to_string(),
        vout: 0,
    };
    assert_eq!(attach_transfer.dst, HolderRef::Utxo(utxo_ref.clone()));

    // ── Phase 2: buyer publishes a commit that holds the Sponsor leaf ──
    // The auto-generated reveal is discarded — we only need the commit
    // output's tap tree (which commits to the Sponsor leaf). The swap
    // tx in Phase 3 spends that output via the leaf's script path,
    // revealing the Sponsor in input 0's witness.
    let buyer_identity = rt.identity().await?;
    let buyer_address = buyer_identity.address.clone();
    let buyer_keypair = buyer_identity.keypair;
    let (buyer_funding_outpoint, buyer_funding_utxo) = buyer_identity.next_funding_utxo.clone();
    let (buyer_internal_key, _) = buyer_keypair.x_only_public_key();

    let sponsor_inst = Inst {
        gas_limit: 50_000,
        kind: InstKind::Sponsor,
    };

    let buyer_reveal = Reveal::builder()
        .sat_per_vbyte(2)
        .participants(vec![
            RevealParticipant::builder()
                .x_only_public_key(buyer_internal_key.to_string())
                .commit_insts(Insts::single(sponsor_inst.clone()))
                .commit_source(CommitSource::build(
                    &buyer_address,
                    [buyer_funding_outpoint],
                ))
                .output(RevealOutput::change(&buyer_address.script_pubkey()))
                .build(),
        ])
        .build();
    let buyer_compose = rt.compose(buyer_reveal).await?;

    let mut buyer_commit_tx = buyer_compose.commits[0].transaction.clone();
    let buyer_reveal_psbt = bitcoin::Psbt::deserialize(&hex::decode(
        &buyer_compose.reveal.psbt_hex,
    )?)?;
    let (buyer_sponsor_leaf, _) =
        indexer::test_utils::participant_tap_script(&buyer_reveal_psbt.inputs[0])?;

    test_utils::sign_key_spend(
        &secp,
        &mut buyer_commit_tx,
        &[TxOut {
            value: buyer_funding_utxo.value,
            script_pubkey: buyer_address.script_pubkey(),
        }],
        &buyer_keypair,
        0,
        None,
    )?;

    let buyer_commit_tx_hex = hex::encode(serialize_tx(&buyer_commit_tx));
    bitcoin_client
        .send_raw_transaction(&buyer_commit_tx_hex)
        .await?;
    bitcoin_client
        .generate_to_address(1, &buyer_address.to_string())
        .await?;

    // Snapshot balances right before the swap.
    let seller_signer_id = rt
        .get_signer_id(&seller_internal_key.to_string())
        .await?
        .expect("seller signer_id");
    let buyer_signer_id = rt
        .get_signer_id(&buyer_internal_key.to_string())
        .await?
        .expect("buyer signer_id");
    let seller_ref = HolderRef::SignerId(seller_signer_id);
    let buyer_ref = HolderRef::SignerId(buyer_signer_id);
    let seller_balance_before = token::balance(runtime, seller_ref.clone()).await?;
    let buyer_balance_before = token::balance(runtime, buyer_ref.clone()).await?;

    // ── Phase 3: build the 2-input swap reveal ──
    // input 0: buyer commit output 0 (reveals the Sponsor leaf)
    // input 1: seller attach reveal output 0 (reveals the detach leaf)
    let swap_reveal = Reveal::builder()
        .sat_per_vbyte(2)
        .participants(vec![
            RevealParticipant::builder()
                .x_only_public_key(buyer_internal_key.to_string())
                .commit_insts(Insts::single(sponsor_inst.clone()))
                .commit_source(CommitSource::existing(
                    bitcoin::OutPoint {
                        txid: buyer_commit_tx.compute_txid(),
                        vout: 0,
                    },
                    buyer_commit_tx.output[0].clone(),
                ))
                .output(RevealOutput::change(&buyer_address.script_pubkey()))
                .build(),
            RevealParticipant::builder()
                .x_only_public_key(seller_internal_key.to_string())
                .commit_insts(Insts::single(detach_inst.clone()))
                .commit_source(CommitSource::existing(
                    bitcoin::OutPoint {
                        txid: seller_attach_reveal_tx.compute_txid(),
                        vout: 0,
                    },
                    seller_attach_reveal_tx.output[0].clone(),
                ))
                .build(),
        ])
        .build();
    let swap_outputs = rt.compose_reveal(swap_reveal).await?;
    let mut swap_tx = swap_outputs.transaction;
    assert_eq!(swap_tx.input.len(), 2, "swap tx must have 2 inputs");

    let swap_prevouts = vec![
        buyer_commit_tx.output[0].clone(),
        seller_attach_reveal_tx.output[0].clone(),
    ];

    // Sign input 0 with the buyer keypair (Sponsor leaf).
    let buyer_sponsor_tap_info = TaprootBuilder::new()
        .add_leaf(0, buyer_sponsor_leaf.clone())
        .map_err(|e| anyhow::anyhow!("buyer sponsor taproot: {e}"))?
        .finalize(&secp, buyer_internal_key)
        .map_err(|e| anyhow::anyhow!("buyer sponsor finalize: {e:?}"))?;
    test_utils::sign_script_spend(
        &secp,
        &buyer_sponsor_tap_info,
        &buyer_sponsor_leaf,
        &mut swap_tx,
        &swap_prevouts,
        &buyer_keypair,
        0,
    )?;

    // Sign input 1 with the seller keypair (chained detach leaf).
    let seller_detach_tap_info = TaprootBuilder::new()
        .add_leaf(0, seller_detach_leaf.clone())
        .map_err(|e| anyhow::anyhow!("seller detach taproot: {e}"))?
        .finalize(&secp, seller_internal_key)
        .map_err(|e| anyhow::anyhow!("seller detach finalize: {e:?}"))?;
    test_utils::sign_script_spend(
        &secp,
        &seller_detach_tap_info,
        &seller_detach_leaf,
        &mut swap_tx,
        &swap_prevouts,
        &seller_keypair,
        1,
    )?;

    let swap_tx_hex = hex::encode(serialize_tx(&swap_tx));
    bitcoin_client.send_raw_transaction(&swap_tx_hex).await?;
    bitcoin_client
        .generate_to_address(1, &buyer_address.to_string())
        .await?;

    let swap_txid = swap_tx.compute_txid().to_string();
    rt.wait_for_txids(std::slice::from_ref(&swap_txid)).await?;

    // The detach result is on input 1, op 0 (input 0 is the Sponsor
    // directive, which short-circuits without producing a result row).
    let detach_result = rt
        .kontor_client()
        .await
        .result(
            &OpResultId::builder()
                .txid(swap_txid)
                .input_index(1)
                .op_index(0)
                .build(),
        )
        .await?
        .ok_or(anyhow::anyhow!("detach result missing"))?;
    let detach_transfer =
        token::wave::detach_parse_return_expr(&detach_result.value.expect("detach value"))?;

    // ── Routing: the Sponsor redirected the payer; asset went to buyer. ──
    assert_eq!(
        detach_transfer.src.to_string(),
        format!("{}:{}", utxo_ref.txid, utxo_ref.vout)
    );
    assert_eq!(detach_transfer.dst, buyer_ref.clone());
    assert_eq!(detach_transfer.amt, 2u64.try_into().unwrap());

    // ── Billing: seller untouched, buyer received credit (minus gas). ──
    let seller_balance_after = token::balance(runtime, seller_ref).await?;
    let buyer_balance_after = token::balance(runtime, buyer_ref).await?;
    assert_eq!(
        seller_balance_after, seller_balance_before,
        "seller's native balance must not change — buyer's Sponsor paid the detach gas"
    );
    assert!(
        buyer_balance_after > buyer_balance_before,
        "buyer's balance must grow (asset credit > gas spent): before={:?} after={:?}",
        buyer_balance_before,
        buyer_balance_after
    );

    Ok(())
}
