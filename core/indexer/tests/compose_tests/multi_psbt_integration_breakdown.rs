use anyhow::Result;
use bitcoin::TxOut;
use bitcoin::consensus::encode::serialize as serialize_tx;
use bitcoin::key::Secp256k1;
use indexer::{
    logging,
    multi_psbt_test_utils::{NodeInfo, get_node_addresses, get_portal_info, tx_vbytes},
};
use indexer_types::{Inst, serialize};
use rand::Rng;
use testlib::RegTester;
use tracing::info;

use bitcoin::{FeeRate, TapSighashType};
use indexer::api::compose::{ComposeInputs, InstructionInputs, compose};

/*
Portal entity sends out a message node entities saying "who wants to join my agreement?"

Each node that joins (3 minimum...N) sends the portal its address + x only pub key asynchronously to the portal in a period of 30 seconds.

The portal then constructs a commit transaction with inputs it fetches for each node and outputs for the reveal and for change going back to each node.
The fee for the commit/reveal is split as evenly as possible between the nodes and the portal, so when constructing the commit at each node interval we must calculate approximately how much each node fee must cover for both the commit and reveal.
This is done in a waterfall fashion: at each node interval after the nodes own input + output + dummy change, it checks the current size of the commit and the overall fee needed for the current size, how much the previous node inputs have already contribute the fee.
Then, the current node interval contributes the difference to the fee, plus an estimated fee for the reveal.

The portal adds its own inputs and outputs to the commit, also estimating how much it needs to cover the commit + reveal.

Then, the portal constructs the reveal psbt. It iterates through the nodes again and adds node inputs/outputs so the xonlypubkey of each node will be revealed in the transaction.
After this iteration, the portal adds its own inputs/outputs for its own xonlypubkey to be revealed.

The portal then sends a copy of the commit and reveal back to each node, which asynchronously add their signature to their own inputs.
The nodes send the copy of the commit and reveal with their individual sigs back to the portal, which copies the sigs over to the actual commit/reveal. Then the portal adds its own sigs.

Then the portal broadcasts the chained commit/reveal (test_mempool_accept).
*/

pub async fn test_portal_coordinated_compose_flow(reg_tester: &mut RegTester) -> Result<()> {
    // Setup
    logging::setup();
    let secp = Secp256k1::new();

    // Fee environment: choose a random integer sats/vB in [2, 15]
    let sat_per_vb: u64 = rand::rng().random_range(2..16);
    let envelope_sat: u64 = 330;

    // Participants: 3 nodes + portal
    let (signups, node_secrets) = get_node_addresses(&mut reg_tester.clone()).await?;
    let portal_info = get_portal_info(&mut reg_tester.clone()).await?;
    let mut all_participants = signups.clone();
    // Append portal as the last participant
    let portal_as_node = NodeInfo {
        address: portal_info.address.clone(),
        internal_key: portal_info.internal_key,
        next_funding_utxo: portal_info.next_funding_utxo,
    };
    all_participants.push(portal_as_node);

    let instruction_inputs: Vec<InstructionInputs> = all_participants
        .iter()
        .enumerate()
        .map(|(i, n)| {
            InstructionInputs::builder()
                .address(n.address.clone())
                .x_only_public_key(n.internal_key)
                .funding_utxos(vec![n.next_funding_utxo.clone()])
                .script_data(
                    serialize(&Inst::Publish {
                        gas_limit: 50_000,
                        name: "test".to_string(),
                        bytes: format!("compose-mpsbt-flow-data-0123456789-{}", i)
                            .as_bytes()
                            .to_vec(),
                    })
                    .unwrap(),
                )
                .build()
        })
        .collect();

    let compose_inputs = ComposeInputs::builder()
        .instructions(instruction_inputs)
        .fee_rate(FeeRate::from_sat_per_vb(sat_per_vb).unwrap())
        .envelope(envelope_sat)
        .build();

    info!(
        "compose: submitting inputs (participants={}, sat_per_vb={}, envelope={})",
        all_participants.len(),
        sat_per_vb,
        envelope_sat
    );
    let compose_outputs = compose(compose_inputs)?;
    info!(
        commit_inputs = compose_outputs.commit_transaction.input.len(),
        commit_outputs = compose_outputs.commit_transaction.output.len(),
        reveal_inputs = compose_outputs.reveal_transaction.input.len(),
        reveal_outputs = compose_outputs.reveal_transaction.output.len(),
        "compose: outputs returned"
    );

    // Sign COMMIT (key path) per-input using known prevouts from PSBT metadata
    let mut commit_tx = compose_outputs.commit_transaction.clone();
    let commit_psbt_bytes = hex::decode(&compose_outputs.commit_psbt_hex)?;
    let commit_psbt: bitcoin::Psbt = bitcoin::Psbt::deserialize(&commit_psbt_bytes)?;
    let commit_prevouts: Vec<TxOut> = commit_psbt
        .inputs
        .iter()
        .map(|inp| inp.witness_utxo.clone().expect("wutxo"))
        .collect();

    // Keys for participants in same order: nodes then portal
    for (i, _) in compose_outputs.commit_transaction.input.iter().enumerate() {
        if i < node_secrets.len() {
            let keypair = node_secrets[i].keypair;
            info!(idx = i, "sign commit: node");
            indexer::test_utils::sign_key_spend(
                &secp,
                &mut commit_tx,
                &commit_prevouts,
                &keypair,
                i,
                Some(TapSighashType::Default),
            )?;
        } else {
            // portal is last
            info!(idx = i, "sign commit: portal");
            indexer::test_utils::sign_key_spend(
                &secp,
                &mut commit_tx,
                &commit_prevouts,
                &portal_info.keypair,
                i,
                Some(TapSighashType::Default),
            )?;
        }
    }
    let commit_vb = tx_vbytes(&commit_tx);
    let commit_in_total: u64 = commit_prevouts.iter().map(|o| o.value.to_sat()).sum();
    let commit_out_total: u64 = commit_tx.output.iter().map(|o| o.value.to_sat()).sum();
    let commit_paid_total = commit_in_total.saturating_sub(commit_out_total);
    let commit_required = commit_vb.saturating_mul(sat_per_vb);
    info!(
        vbytes = commit_vb,
        paid_sat = commit_paid_total,
        required_sat = commit_required,
        in_total_sat = commit_in_total,
        out_total_sat = commit_out_total,
        "commit signed size/fees"
    );

    // Sign REVEAL (script path) per-input using tapscripts from compose outputs
    let mut reveal_tx = compose_outputs.reveal_transaction.clone();
    let commit_txid = commit_tx.compute_txid();
    let reveal_prevouts: Vec<TxOut> = reveal_tx
        .input
        .iter()
        .map(|inp| commit_tx.output[inp.previous_output.vout as usize].clone())
        .collect();
    info!(
        inputs = reveal_tx.input.len(),
        "reveal: built prevouts for signing"
    );

    for (i, p) in all_participants.iter().enumerate() {
        // Build spend info from tapscript chunk
        let tap_script = compose_outputs.per_participant[i]
            .commit_tap_script_pair
            .tap_leaf_script
            .script
            .clone();
        let tap_info = bitcoin::taproot::TaprootBuilder::new()
            .add_leaf(0, tap_script.clone())
            .expect("leaf")
            .finalize(&secp, p.internal_key)
            .expect("finalize");

        assert_eq!(reveal_tx.input[i].previous_output.txid, commit_txid);
        let keypair = if i < node_secrets.len() {
            node_secrets[i].keypair
        } else {
            portal_info.keypair
        };
        indexer::test_utils::sign_script_spend(
            &secp,
            &tap_info,
            &tap_script,
            &mut reveal_tx,
            &reveal_prevouts,
            &keypair,
            i,
        )?;
        info!(idx = i, "sign reveal: participant signed");
    }
    let reveal_vb = tx_vbytes(&reveal_tx);
    let reveal_in_total: u64 = reveal_prevouts.iter().map(|o| o.value.to_sat()).sum();
    let reveal_out_total: u64 = reveal_tx.output.iter().map(|o| o.value.to_sat()).sum();
    let reveal_paid_total = reveal_in_total.saturating_sub(reveal_out_total);
    let reveal_required = reveal_vb.saturating_mul(sat_per_vb);
    info!(
        vbytes = reveal_vb,
        paid_sat = reveal_paid_total,
        required_sat = reveal_required,
        in_total_sat = reveal_in_total,
        out_total_sat = reveal_out_total,
        "reveal signed size/fees"
    );
    info!(
        overall_paid_sat = commit_paid_total + reveal_paid_total,
        overall_required_sat = commit_required + reveal_required,
        "overall fees"
    );

    // Broadcast both
    let commit_hex = hex::encode(serialize_tx(&commit_tx));
    let reveal_hex = hex::encode(serialize_tx(&reveal_tx));
    let res = reg_tester
        .mempool_accept_result(&[commit_hex, reveal_hex])
        .await?;
    assert_eq!(res.len(), 2, "Expected results for both transactions");
    info!(
        commit_allowed = res[0].allowed,
        reveal_allowed = res[1].allowed,
        "mempool accept results"
    );
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
