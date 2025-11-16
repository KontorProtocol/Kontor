use anyhow::Result;
use bitcoin::Witness;
use bitcoin::amount::Amount;
use bitcoin::key::Secp256k1;
use bitcoin::script::Instruction;
use bitcoin::transaction::Version;
use bitcoin::{Network, OutPoint, Psbt, Sequence, Transaction, TxIn, TxOut, absolute::LockTime};
use bitcoin::{TapSighashType, consensus::encode::serialize as serialize_tx};
use futures_util::future::join_all;
use indexer::multi_psbt_test_utils::{
    build_tap_script_and_script_address_helper, estimate_single_input_single_output_reveal_vbytes,
    get_node_addresses, get_portal_info, log_node_sign_size_and_fee_breakdown,
    log_total_size_and_fee_breakdown, tx_vbytes,
};
use indexer::{logging, test_utils};
use testlib::RegTester;
use tracing::info;

#[macro_export]
macro_rules! log_portal {
    ($fmt:expr, $($args:expr),+ ) => {
        tracing::info!(target: "portal", "\x1b[32m{}\x1b[0m", format!($fmt, $($args),+));
    };
    ($fmt:expr) => {
        tracing::info!(target: "portal", "\x1b[32m{}\x1b[0m", format!($fmt));
    };
}

#[macro_export]
macro_rules! log_node {
    ($fmt:expr, $($args:expr),+ ) => {
        tracing::info!(target: "node", "\x1b[38;5;208m{}\x1b[0m", format!($fmt, $($args),+));
    };
    ($fmt:expr) => {
        tracing::info!(target: "node", "\x1b[38;5;208m{}\x1b[0m", format!($fmt));
    };
}

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

pub async fn test_portal_coordinated_commit_reveal_flow_integration(
    reg_tester: &mut RegTester,
) -> Result<()> {
    // Setup
    logging::setup();

    let secp = Secp256k1::new();

    // Fee environment
    let mp = reg_tester.mempool_info().await?;
    let min_btc_per_kvb = mp
        .mempool_min_fee_btc_per_kvb
        .max(mp.min_relay_tx_fee_btc_per_kvb);
    let min_sat_per_vb: u64 = ((min_btc_per_kvb * 100_000_000.0) / 1000.0).ceil() as u64;
    let dust_limit_sat: u64 = 330;
    info!("min_sat_per_vb={}", min_sat_per_vb);

    // Phase 1: Nodes sign up for agreement with address + x-only pubkey
    let (signups, node_secrets) = get_node_addresses(&mut reg_tester.clone()).await?;

    // Phase 2: Portal fetches node utxos and constructs COMMIT PSBT using nodes' outpoints/prevouts
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

    for (idx, s) in signups.iter().enumerate() {
        log_node!("node idx={} appending to COMMIT", idx);
        let (node_outpoint, node_prevout) = s.next_funding_utxo.clone();
        // Snapshot size before adding this node to charge full delta (non-witness + witness + optional change)
        let base_before_vb = tx_vbytes(&commit_psbt.unsigned_tx);
        let node_input_index = commit_psbt.unsigned_tx.input.len();
        commit_psbt.unsigned_tx.input.push(TxIn {
            previous_output: node_outpoint,
            script_sig: bitcoin::script::ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
        commit_psbt.inputs.push(Default::default());
        commit_psbt.inputs[node_input_index].witness_utxo = Some(node_prevout.clone());
        commit_psbt.inputs[node_input_index].tap_internal_key = Some(s.internal_key);

        // Append script output for node at the end
        let (tap_script, tap_info, script_addr) = build_tap_script_and_script_address_helper(
            s.internal_key,
            b"node-data".to_vec(),
            Network::Regtest,
        )?;

        // Estimate reveal fee the node will need to pay later (1-in script + 1-out to self)
        let reveal_vb = estimate_single_input_single_output_reveal_vbytes(
            &tap_script,
            &tap_info,
            s.address.script_pubkey().len(),
            dust_limit_sat,
        );
        let reveal_fee = reveal_vb.saturating_mul(min_sat_per_vb);
        node_reveal_fees.push(reveal_fee);
        log_node!(
            "node idx={} estimated_reveal_size={} vB; estimated_reveal_fee={} sat ",
            idx,
            reveal_vb,
            reveal_fee
        );

        let script_value = dust_limit_sat + reveal_fee;

        commit_psbt.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(script_value),
            script_pubkey: script_addr.script_pubkey(),
        });
        commit_psbt.outputs.push(Default::default());

        // Estimate full commit delta for this node (input + script output + witness + optional change)
        let mut temp = commit_psbt.unsigned_tx.clone();
        let mut dw = Witness::new();
        dw.push(vec![0u8; 65]);
        temp.input[node_input_index].witness = dw;
        temp.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: s.address.script_pubkey(),
        });
        let after_with_change_vb = tx_vbytes(&temp);
        let full_delta_vb = after_with_change_vb.saturating_sub(base_before_vb);
        let fee_full_delta = full_delta_vb.saturating_mul(min_sat_per_vb);

        let mut node_change_value = node_prevout
            .value
            .to_sat()
            .saturating_sub(script_value + fee_full_delta);

        // Include change only if above dust
        if node_change_value > dust_limit_sat {
            commit_psbt.unsigned_tx.output.push(TxOut {
                value: Amount::from_sat(node_change_value),
                script_pubkey: s.address.script_pubkey(),
            });
            commit_psbt.outputs.push(Default::default());
        } else {
            node_change_value = 0;
        }

        node_input_indices.push(node_input_index);
        // script output was appended just before optional change; so it is at len-1 if no change, or len-2 if change was added
        let script_vout = if node_change_value > 0 {
            commit_psbt.unsigned_tx.output.len() - 2
        } else {
            commit_psbt.unsigned_tx.output.len() - 1
        };
        node_script_vouts.push(script_vout);

        log_node!(
            "idx={} commit_vb_with_dummy_sig={} vB; node_delta={} vB; total_fee_paid={} sat (commit_fee={} sat, reveal_fee={} sat, buffer={} sat)",
            idx,
            tx_vbytes(&temp),
            full_delta_vb,
            node_prevout.value.to_sat() - (script_value + node_change_value),
            fee_full_delta,
            reveal_fee,
            fee_full_delta - full_delta_vb.saturating_mul(min_sat_per_vb)
        );
    }

    // Portal participation: append portal input/output (script reveal) and charge full-delta fee like nodes
    info!("portal appending to COMMIT");
    let portal_info = get_portal_info(&mut reg_tester.clone()).await?;
    let (portal_outpoint, portal_prevout) = portal_info.next_funding_utxo.clone();
    let base_before_portal_vb = tx_vbytes(&commit_psbt.unsigned_tx);
    let portal_input_index = commit_psbt.unsigned_tx.input.len();
    commit_psbt.unsigned_tx.input.push(TxIn {
        previous_output: portal_outpoint,
        script_sig: bitcoin::script::ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    });
    commit_psbt.inputs.push(Default::default());
    commit_psbt.inputs[portal_input_index].witness_utxo = Some(portal_prevout.clone());
    commit_psbt.inputs[portal_input_index].tap_internal_key = Some(portal_info.internal_key);

    // Portal tapscript output to reveal its x-only pubkey
    let (portal_tap_script, portal_tap_info, portal_script_addr) =
        build_tap_script_and_script_address_helper(
            portal_info.internal_key,
            b"portal-data".to_vec(),
            Network::Regtest,
        )?;
    let portal_reveal_vb = estimate_single_input_single_output_reveal_vbytes(
        &portal_tap_script,
        &portal_tap_info,
        portal_info.address.script_pubkey().len(),
        dust_limit_sat,
    );
    let portal_reveal_fee = portal_reveal_vb.saturating_mul(min_sat_per_vb);
    let portal_script_value = dust_limit_sat + portal_reveal_fee;
    commit_psbt.unsigned_tx.output.push(TxOut {
        value: Amount::from_sat(portal_script_value),
        script_pubkey: portal_script_addr.script_pubkey(),
    });
    commit_psbt.outputs.push(Default::default());

    // Full-delta commit fee for portal
    let mut temp_portal = commit_psbt.unsigned_tx.clone();
    let mut dwp = Witness::new();
    dwp.push(vec![0u8; 65]);
    temp_portal.input[portal_input_index].witness = dwp;
    temp_portal.output.push(TxOut {
        value: Amount::from_sat(0),
        script_pubkey: portal_info.address.script_pubkey(),
    });
    let after_with_change_portal_vb = tx_vbytes(&temp_portal);
    let portal_full_delta_vb = after_with_change_portal_vb.saturating_sub(base_before_portal_vb);
    let portal_fee_full_delta = portal_full_delta_vb.saturating_mul(min_sat_per_vb);

    let mut portal_change_value = portal_prevout
        .value
        .to_sat()
        .saturating_sub(portal_script_value + portal_fee_full_delta);
    if portal_change_value > dust_limit_sat {
        commit_psbt.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(portal_change_value),
            script_pubkey: portal_info.address.script_pubkey(),
        });
        commit_psbt.outputs.push(Default::default());
    } else {
        portal_change_value = 0;
    }

    log_portal!(
        "portal commit_vb_with_dummy_sig={} vB; portal_delta={} vB; total_fee_paid={} sat (commit_fee={} sat, reveal_fee={} sat, buffer={} sat)",
        tx_vbytes(&temp_portal),
        portal_full_delta_vb,
        portal_prevout.value.to_sat() - (portal_script_value + portal_change_value),
        portal_fee_full_delta,
        portal_reveal_fee,
        portal_fee_full_delta - portal_full_delta_vb.saturating_mul(min_sat_per_vb)
    );

    // Prepare prevouts for commit signing
    let all_prevouts_c: Vec<TxOut> = commit_psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().unwrap())
        .collect();
    info!("portal finalizing commit psbt");

    // Phase 3: Portal constructs REVEAL PSBT referencing fixed commit txid
    let commit_txid = commit_psbt.unsigned_tx.compute_txid();
    let mut reveal_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    info!("portal constructing reveal psbt");
    // For each node, add script spend input and a send to node's address as output
    for (i, s) in signups.iter().enumerate() {
        let script_vout = node_script_vouts[i] as u32;
        reveal_tx.input.push(TxIn {
            previous_output: OutPoint {
                txid: commit_txid,
                vout: script_vout,
            },
            script_sig: bitcoin::script::ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
        reveal_tx.output.push(TxOut {
            value: Amount::from_sat(dust_limit_sat),
            script_pubkey: s.address.script_pubkey(),
        });
    }
    let mut reveal_psbt = Psbt::from_unsigned_tx(reveal_tx.clone())?;
    for (i, s) in signups.iter().enumerate() {
        reveal_psbt.inputs[i].witness_utxo =
            Some(commit_psbt.unsigned_tx.output[node_script_vouts[i]].clone());
        reveal_psbt.inputs[i].tap_internal_key = Some(s.internal_key);
    }
    // Add portal reveal input/output
    let portal_script_vout = (commit_psbt.unsigned_tx.output.len() - 1) as u32
        - if portal_change_value > 0 { 1 } else { 0 };
    reveal_psbt.unsigned_tx.input.push(TxIn {
        previous_output: OutPoint {
            txid: commit_txid,
            vout: portal_script_vout,
        },
        script_sig: bitcoin::script::ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    });
    reveal_psbt.unsigned_tx.output.push(TxOut {
        value: Amount::from_sat(dust_limit_sat),
        script_pubkey: portal_info.address.script_pubkey(),
    });
    reveal_psbt.inputs.push(Default::default());
    let nodes_n = signups.len();
    reveal_psbt.inputs[nodes_n].witness_utxo =
        Some(commit_psbt.unsigned_tx.output[portal_script_vout as usize].clone());
    reveal_psbt.inputs[nodes_n].tap_internal_key = Some(portal_info.internal_key);

    // Phase 4: Portal sends both PSBTs to nodes; nodes sign commit input (key-spend, SIGHASH_ALL) and reveal input (script-spend, SIGHASH_ALL)
    // Each node signs asynchronously and returns only its own witnesses; portal merges them
    let commit_base_tx = commit_psbt.unsigned_tx.clone();
    let commit_base_psbt = commit_psbt.clone();
    let reveal_base_psbt = reveal_psbt.clone();
    let all_prevouts_clone = all_prevouts_c.clone();

    let node_sign_futs = signups.iter().enumerate().map(|(i, s)| {
        let secp = Secp256k1::new();
        let keypair = node_secrets[i].keypair;
        let mut commit_tx_local = commit_base_tx.clone();
        let mut commit_psbt_local = commit_base_psbt.clone();
        let mut reveal_psbt_local = reveal_base_psbt.clone();
        let prevouts_commit = all_prevouts_clone.clone();
        info!("portal finalizing commit psbt");
        let node_input_indices_async = node_input_indices.clone();
        let input_index = node_input_indices_async[i];
        async move {
            // Commit: sign only this node's input
            test_utils::sign_key_spend(
                &secp,
                &mut commit_tx_local,
                &prevouts_commit,
                &keypair,
                input_index,
                Some(TapSighashType::Default),
            )?;
            let commit_witness = commit_tx_local.input[input_index].witness.clone();
            log_node!(
                "idx={} produced commit witness (stack_elems={})",
                i,
                commit_witness.len()
            );
            // Attach to local commit psbt
            commit_psbt_local.inputs[input_index].final_script_witness = Some(commit_witness);

            // Reveal: sign only this node's reveal input and log sizes/fees
            let (tap_script, tap_info, _addr) = build_tap_script_and_script_address_helper(
                s.internal_key,
                b"node-data".to_vec(),
                Network::Regtest,
            )?;
            let prevouts_reveal: Vec<TxOut> = reveal_psbt_local
                .inputs
                .iter()
                .map(|inp| inp.witness_utxo.clone().expect("wutxo"))
                .collect();
            let mut reveal_tx_local = reveal_psbt_local.unsigned_tx.clone();
            test_utils::sign_script_spend_with_sighash(
                &secp,
                &tap_info,
                &tap_script,
                &mut reveal_tx_local,
                &prevouts_reveal,
                &keypair,
                i,
                TapSighashType::Default,
            )?;

            log_node_sign_size_and_fee_breakdown(
                &reveal_psbt_local,
                i,
                &mut reveal_tx_local,
                min_sat_per_vb,
            );

            let reveal_witness = reveal_tx_local.input[i].witness.clone();
            // Attach to local reveal psbt
            reveal_psbt_local.inputs[i].final_script_witness = Some(reveal_witness);

            Ok::<(usize, Psbt, Psbt), anyhow::Error>((i, commit_psbt_local, reveal_psbt_local))
        }
    });

    let node_psbts: Vec<(usize, Psbt, Psbt)> = join_all(node_sign_futs)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    // Merge node witnesses back into the original PSBTs
    for (i, c_psbt, r_psbt) in node_psbts {
        let idx = node_input_indices[i];
        commit_psbt.inputs[idx].final_script_witness =
            c_psbt.inputs[idx].final_script_witness.clone();
        reveal_psbt.inputs[i].final_script_witness = r_psbt.inputs[i].final_script_witness.clone();
        log_portal!(
            "merged node {} commit ({} elems), reveal ({} elems)",
            i,
            commit_psbt.inputs[idx]
                .final_script_witness
                .as_ref()
                .map(|w| w.len())
                .unwrap_or(0),
            reveal_psbt.inputs[i]
                .final_script_witness
                .as_ref()
                .map(|w| w.len())
                .unwrap_or(0)
        );
    }

    // Sign portal commit input
    {
        let mut tx_to_sign_portal = commit_psbt.unsigned_tx.clone();
        test_utils::sign_key_spend(
            &secp,
            &mut tx_to_sign_portal,
            &all_prevouts_c,
            &portal_info.keypair,
            portal_input_index,
            Some(TapSighashType::Default),
        )?;
        commit_psbt.inputs[portal_input_index].final_script_witness =
            Some(tx_to_sign_portal.input[portal_input_index].witness.clone());
        log_portal!(
            "portal added commit witness (stack_elems={})",
            tx_to_sign_portal.input[portal_input_index].witness.len()
        );
    }

    // Portal signs reveal input
    {
        let (tap_script, tap_info, _addr) = build_tap_script_and_script_address_helper(
            portal_info.internal_key,
            b"portal-data".to_vec(),
            Network::Regtest,
        )?;
        let prevouts: Vec<TxOut> = reveal_psbt
            .inputs
            .iter()
            .map(|inp| inp.witness_utxo.clone().expect("wutxo"))
            .collect();
        let mut txp = reveal_psbt.unsigned_tx.clone();
        test_utils::sign_script_spend_with_sighash(
            &secp,
            &tap_info,
            &tap_script,
            &mut txp,
            &prevouts,
            &portal_info.keypair,
            nodes_n,
            TapSighashType::Default,
        )?;
        // Log portal reveal
        let mut reveal_before = reveal_psbt.unsigned_tx.clone();
        for j in 0..reveal_before.input.len() {
            if let Some(wit) = &reveal_psbt.inputs[j].final_script_witness {
                reveal_before.input[j].witness = wit.clone();
            }
        }
        let before_vb_r_portal = tx_vbytes(&reveal_before);
        let mut reveal_after = reveal_before.clone();
        reveal_after.input[nodes_n].witness = txp.input[nodes_n].witness.clone();
        let after_vb_r_portal = tx_vbytes(&reveal_after);
        let delta_vb_r_portal = after_vb_r_portal.saturating_sub(before_vb_r_portal);
        let in_val_r_portal = reveal_psbt.inputs[nodes_n]
            .witness_utxo
            .as_ref()
            .expect("wutxo")
            .value
            .to_sat();
        let out_val_r_portal = reveal_psbt.unsigned_tx.output[nodes_n].value.to_sat();
        let fee_paid_r_portal = in_val_r_portal.saturating_sub(out_val_r_portal);
        let needed_fee_portal = delta_vb_r_portal.saturating_mul(min_sat_per_vb);
        log_portal!(
            "portal reveal_vb_now={} vB; reveal_delta={} vB; reveal_fee_paid={} sat; reveal_fee_needed={} sat",
            after_vb_r_portal,
            delta_vb_r_portal,
            fee_paid_r_portal,
            needed_fee_portal
        );
        assert!(
            fee_paid_r_portal >= needed_fee_portal,
            "portal reveal fee insufficient: paid={} < needed={}",
            fee_paid_r_portal,
            needed_fee_portal
        );
        reveal_psbt.inputs[nodes_n].final_script_witness = Some(txp.input[nodes_n].witness.clone());
        log_portal!(
            "portal added reveal witness (stack_elems={})",
            txp.input[nodes_n].witness.len()
        );
    }

    // Phase 5: Verify the x-only pubkeys are revealed in reveal witnesses
    for (i, s) in signups.iter().enumerate() {
        let wit = reveal_psbt.inputs[i]
            .final_script_witness
            .as_ref()
            .expect("node reveal witness");
        assert!(wit.len() >= 2, "witness must contain signature and script");
        let script_bytes = wit.iter().nth(1).expect("script");
        let script = bitcoin::script::ScriptBuf::from_bytes(script_bytes.to_vec());
        let mut it = script.instructions();
        if let Some(Ok(Instruction::PushBytes(bytes))) = it.next() {
            assert_eq!(
                bytes.as_bytes(),
                &s.internal_key.serialize(),
                "node xonly pubkey not revealed correctly"
            );
        } else {
            panic!("node tapscript missing leading pubkey push");
        }
    }

    log_total_size_and_fee_breakdown(&commit_psbt, &reveal_psbt, min_sat_per_vb);

    let commit_tx = commit_psbt.extract_tx()?;
    let reveal_tx = reveal_psbt.extract_tx()?;

    // Phase 6: Broadcast commit then reveal together
    let commit_hex = hex::encode(serialize_tx(&commit_tx));
    let reveal_hex = hex::encode(serialize_tx(&reveal_tx));
    let res = reg_tester
        .mempool_accept_result(&[commit_hex, reveal_hex])
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
