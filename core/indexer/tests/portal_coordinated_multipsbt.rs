use anyhow::Result;
use bitcoin::consensus::encode::serialize as serialize_tx;
use bitcoin::key::Secp256k1;
use bitcoin::transaction::Version;
use bitcoin::{Network, OutPoint, Psbt, Transaction, TxOut, absolute::LockTime};
use clap::Parser;
use indexer::config::TestConfig;
use indexer::multi_psbt_test_utils::{
    add_node_input_and_output_to_reveal_psbt, add_portal_input_and_output_to_psbt,
    add_portal_input_and_output_to_reveal_psbt, add_single_node_input_and_output_to_psbt,
    get_node_addresses, merge_node_signatures, mock_fetch_utxos_for_addresses,
    node_sign_commit_and_reveal, portal_signs_commit_and_reveal, verify_x_only_pubkeys,
};
use indexer::{bitcoin_client::Client, logging};
use rand::Rng;
use tracing::info;

/// HIGH LEVEL COMMENTS

#[tokio::test]
async fn test_portal_coordinated_commit_reveal_flow() -> Result<()> {
    // Setup
    logging::setup();
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let client = Client::new_from_config(&test_cfg)?;
    let secp = Secp256k1::new();
    let dust_limit_sat: u64 = 330;

    // Generate a random sats/vbyte
    let min_sat_per_vb: u64 = rand::rng().random_range(2..11);
    info!("Random sats/vbyte: {}", min_sat_per_vb);

    // Phase 1: Nodes sign up for agreement with address + x-only pubkey
    let (signups, _) = get_node_addresses(&secp, &test_cfg)?;

    // Phase 2: Portal fetches node utxos and constructs COMMIT PSBT using nodes' outpoints/prevouts
    let node_utxos: Vec<(OutPoint, TxOut)> = mock_fetch_utxos_for_addresses(&signups);
    info!("portal fetching node utxos and constructing commit/reveal psbts");

    let mut commit_psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;

    // Portal appends each node's input and script output; calculate node change such that each pays their own commit and reveal deltas
    let mut node_input_indices: Vec<usize> = Vec::with_capacity(signups.len());
    let mut node_script_vouts: Vec<usize> = Vec::with_capacity(signups.len());
    let mut node_reveal_fees: Vec<u64> = Vec::with_capacity(signups.len());

    for (index, node_info) in signups.iter().enumerate() {
        let (node_reveal_fee, node_input_index, node_script_vout) =
            add_single_node_input_and_output_to_psbt(
                &mut commit_psbt,
                &node_utxos,
                index,
                min_sat_per_vb,
                node_info,
                dust_limit_sat,
            )?;
        node_input_indices.push(node_input_index);
        node_script_vouts.push(node_script_vout);
        node_reveal_fees.push(node_reveal_fee);
    }

    let (portal_info, portal_change_value, portal_input_index) =
        add_portal_input_and_output_to_psbt(
            &mut commit_psbt,
            min_sat_per_vb,
            dust_limit_sat,
            &secp,
            &test_cfg,
        )?;

    // Prepare prevouts for commit signing
    let all_prevouts_c: Vec<TxOut> = commit_psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().unwrap())
        .collect();
    info!("portal finalizing commit psbt");

    // Phase 3: Portal constructs REVEAL PSBT referencing fixed commit txid
    let commit_txid = commit_psbt.unsigned_tx.compute_txid();
    let mut reveal_psbt: Psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;

    info!("portal constructing reveal psbt");
    // For each node, add script spend input and a send to node's address as output
    for (idx, node_info) in signups.iter().enumerate() {
        add_node_input_and_output_to_reveal_psbt(
            &mut reveal_psbt,
            commit_txid,
            &node_script_vouts,
            idx,
            dust_limit_sat,
            node_info,
            &commit_psbt,
        );
    }

    let nodes_length = signups.len();
    add_portal_input_and_output_to_reveal_psbt(
        &mut reveal_psbt,
        portal_change_value,
        dust_limit_sat,
        &portal_info,
        &commit_psbt,
        nodes_length,
    );

    // Phase 4: Portal sends both PSBTs to nodes; nodes sign commit input (key-spend, SIGHASH_ALL) and reveal input (script-spend, SIGHASH_ALL)
    // Each node signs asynchronously and returns only its own witnesses; portal merges them

    let (_, node_secrets) = get_node_addresses(&secp, &test_cfg)?;

    let node_sign_futs: Vec<_> = signups
        .iter()
        .enumerate()
        .map(|(index, node_info)| {
            node_sign_commit_and_reveal(
                node_info,
                index,
                (commit_psbt.clone(), reveal_psbt.clone()),
                &all_prevouts_c,
                &node_input_indices,
                min_sat_per_vb,
                &node_secrets,
            )
        })
        .collect();

    merge_node_signatures(
        node_sign_futs,
        &node_input_indices,
        &mut commit_psbt,
        &mut reveal_psbt,
    )
    .await?;

    portal_signs_commit_and_reveal(
        &mut commit_psbt,
        &mut reveal_psbt,
        &portal_info,
        &all_prevouts_c,
        portal_input_index,
        min_sat_per_vb,
        nodes_length,
    )?;

    // Phase 5: Verify the x-only pubkeys are revealed in reveal witnesses
    verify_x_only_pubkeys(&signups, &reveal_psbt, &commit_psbt, min_sat_per_vb);

    let commit_tx = commit_psbt.extract_tx()?;
    let reveal_tx = reveal_psbt.extract_tx()?;

    // Phase 6: Broadcast commit then reveal together
    let commit_hex = hex::encode(serialize_tx(&commit_tx));
    let reveal_hex = hex::encode(serialize_tx(&reveal_tx));
    let res = client
        .test_mempool_accept(&[commit_hex, reveal_hex])
        .await?;
    assert_eq!(res.len(), 2, "Expected results for both transactions");
    assert!(
        res[0].allowed,
        "Commit rejected: {:?}",
        res[0].reject_reason
    );
    assert!(
        res[1].allowed,
        "Reveal rejected: {:?}",
        res[1].reject_reason
    );

    Ok(())
}
