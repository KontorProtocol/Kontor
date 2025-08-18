use anyhow::Result;
use bitcoin::address::Address;
use bitcoin::amount::Amount;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::script::Instruction;
use bitcoin::secp256k1::All;
use bitcoin::transaction::Version;
use bitcoin::{
    Network, OutPoint, Psbt, Sequence, Transaction, TxIn, TxOut, XOnlyPublicKey, absolute::LockTime,
};
use bitcoin::{TapSighashType, consensus::encode::serialize as serialize_tx};
use bitcoin::{Txid, Witness};
use clap::Parser;
use indexer::api::compose::build_tap_script_and_script_address;
use indexer::config::{Config, TestConfig};
use indexer::{bitcoin_client::Client, logging, test_utils};
use std::str::FromStr;
use tracing::info;

#[derive(Clone, Debug)]
struct NodeInfo {
    address: Address,
    internal_key: XOnlyPublicKey,
}

#[derive(Clone, Debug)]
struct NodeSecrets {
    keypair: Keypair,
}

// Portal constructs the commit/reveal, but does not contribute its own input/output in this simplified flow

// NODE SETUP HELPERS
fn get_node_addresses(
    secp: &Secp256k1<All>,
    test_cfg: &TestConfig,
) -> Result<(Vec<NodeInfo>, Vec<NodeSecrets>)> {
    let mut infos = Vec::new();
    let mut secrets = Vec::new();
    for i in 0..3 {
        let (address, child_key, _compressed) =
            test_utils::generate_taproot_address_from_mnemonic(secp, test_cfg, i as u32)?;
        let keypair = Keypair::from_secret_key(secp, &child_key.private_key);
        let (internal_key, _parity) = keypair.x_only_public_key();
        infos.push(NodeInfo {
            address,
            internal_key,
        });
        secrets.push(NodeSecrets { keypair });
    }
    Ok((infos, secrets))
}

fn mock_fetch_utxos_for_addresses(signups: &[NodeInfo]) -> Vec<(OutPoint, TxOut)> {
    // deterministic mapping like the other test
    signups
        .iter()
        .enumerate()
        .map(|(i, s)| {
            let (txid_str, vout_u32, value_sat): (&str, u32, u64) = match i {
                0 => (
                    "dac8f123136bb59926e559e9da97eccc9f46726c3e7daaf2ab3502ef3a47fa46",
                    0,
                    500_000,
                ),
                1 => (
                    "465de2192b246635df14ff81c3b6f37fb864f308ad271d4f91a29dcf476640ba",
                    0,
                    500_000,
                ),
                2 => (
                    "49e327c2945f88908f67586de66af3bfc2567fe35ec7c5f1769f973f9fe8e47e",
                    0,
                    500_000,
                ),
                _ => unreachable!(),
            };
            (
                OutPoint {
                    txid: Txid::from_str(txid_str).unwrap(),
                    vout: vout_u32,
                },
                TxOut {
                    value: Amount::from_sat(value_sat),
                    script_pubkey: s.address.script_pubkey(),
                },
            )
        })
        .collect()
}

// SIZE ESTIMATION HELPERS
fn tx_vbytes(tx: &Transaction) -> u64 {
    let mut no_wit = tx.clone();
    for inp in &mut no_wit.input {
        inp.witness = Witness::new();
    }
    let base_size = serialize_tx(&no_wit).len() as u64;
    let total_size = serialize_tx(tx).len() as u64;
    let witness_size = total_size.saturating_sub(base_size);
    let weight = base_size * 4 + witness_size;
    weight.div_ceil(4)
}

fn estimate_single_input_single_output_reveal_vbytes(
    tap_script: &bitcoin::script::ScriptBuf,
    tap_info: &bitcoin::taproot::TaprootSpendInfo,
    recipient_spk_len: usize,
    envelope_sat: u64,
) -> u64 {
    let mut dummy_reveal = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(
                    "0000000000000000000000000000000000000000000000000000000000000000",
                )
                .unwrap(),
                vout: 0,
            },
            script_sig: bitcoin::script::ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(envelope_sat),
            script_pubkey: bitcoin::script::ScriptBuf::from_bytes(vec![0u8; recipient_spk_len]),
        }],
    };
    let mut w = Witness::new();
    w.push(vec![0u8; 65]);
    w.push(tap_script.clone());
    w.push(
        tap_info
            .control_block(&(tap_script.clone(), bitcoin::taproot::LeafVersion::TapScript))
            .expect("cb")
            .serialize(),
    );
    dummy_reveal.input[0].witness = w;
    tx_vbytes(&dummy_reveal)
}

#[tokio::test]
async fn test_portal_coordinated_commit_reveal_flow() -> Result<()> {
    // Setup
    logging::setup();
    let config = Config::try_parse()?;
    let client = Client::new_from_config(&config)?;

    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();

    // Fee environment
    let mp = client.get_mempool_info().await?;
    let min_btc_per_kvb = mp
        .mempool_min_fee_btc_per_kvb
        .max(mp.min_relay_tx_fee_btc_per_kvb);
    let min_sat_per_vb: u64 = ((min_btc_per_kvb * 100_000_000.0) / 1000.0).ceil() as u64;
    let dust_limit_sat: u64 = 330;
    info!(target: "portal", "min_sat_per_vb={}", min_sat_per_vb);

    // Phase 1: Nodes sign up for agreement with address + x-only pubkey
    let (signups, _) = get_node_addresses(&secp, &test_cfg)?;

    // Phase 2: Portal fetches node utxos and constructs COMMIT PSBT using nodes' known outpoints/prevouts
    let node_utxos: Vec<(OutPoint, TxOut)> = mock_fetch_utxos_for_addresses(&signups);
    info!(target: "portal", "portal fetching node utxos and constructing commit/reveal psbts");

    let mut commit_psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;

    // Append each node's input and script output; calculate node change such that each pays their own commit and reveal deltas
    let mut node_input_indices: Vec<usize> = Vec::with_capacity(signups.len());
    let mut node_script_vouts: Vec<usize> = Vec::with_capacity(signups.len());

    for (idx, s) in signups.iter().enumerate() {
        info!(target: "node", "***************node idx={} appending to COMMIT", idx);
        let (node_outpoint, node_prevout) = node_utxos[idx].clone();
        // Use known outpoint and value; prevout script is the node's address script
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
        let (tap_script, tap_info, script_addr) =
            build_tap_script_and_script_address(s.internal_key, b"node-data".to_vec())?;

        // Estimate reveal fee the node will need to pay later (1-in script + 1-out to self)
        let reveal_vb = estimate_single_input_single_output_reveal_vbytes(
            &tap_script,
            &tap_info,
            s.address.script_pubkey().len(),
            dust_limit_sat,
        );
        let reveal_fee = reveal_vb.saturating_mul(min_sat_per_vb);
        info!(target: "node", "node idx={} estimated_reveal_size={} vB; estimated_reveal_fee={} sat ", idx, reveal_vb, reveal_fee);

        let script_value = dust_limit_sat + reveal_fee;

        commit_psbt.unsigned_tx.output.push(TxOut {
            value: Amount::from_sat(script_value),
            script_pubkey: script_addr.script_pubkey(),
        });
        commit_psbt.outputs.push(Default::default());

        // Estimate commit delta if we also include a node change output
        let base_vb = tx_vbytes(&commit_psbt.unsigned_tx);
        info!(target: "node", "node idx={} base_vb={}", idx, base_vb);
        let mut temp = commit_psbt.unsigned_tx.clone();
        let mut dw = Witness::new();
        dw.push(vec![0u8; 65]);
        temp.input[node_input_index].witness = dw;
        temp.output.push(TxOut {
            value: Amount::from_sat(0),
            script_pubkey: s.address.script_pubkey(),
        });
        let after_with_change_vb = tx_vbytes(&temp);
        info!(target: "node", "node idx={} after_with_change_vb={}", idx, after_with_change_vb);
        let delta_with_change_vb = after_with_change_vb.saturating_sub(base_vb);
        info!(target: "node", "node idx={} delta_with_change_vb={}", idx, delta_with_change_vb);
        let fee_with_change = delta_with_change_vb.saturating_mul(min_sat_per_vb);
        info!(target: "node", "node idx={} fee_with_change={}", idx, fee_with_change);

        let mut node_change_value = node_prevout
            .value
            .to_sat()
            .saturating_sub(script_value + fee_with_change);
        info!(target: "node", "node idx={} node_change_value={}", idx, node_change_value);

        // Include change only if above dust
        if node_change_value > dust_limit_sat {
            commit_psbt.unsigned_tx.output.push(TxOut {
                value: Amount::from_sat(node_change_value),
                script_pubkey: s.address.script_pubkey(),
            });
            commit_psbt.outputs.push(Default::default());
            info!(target: "node", "idx={} including node change={} sat", idx, node_change_value);
        } else {
            info!(target: "node", "idx={} omitting node change ({} sat would be dust)", idx, node_change_value);
            node_change_value = 0;
        }

        node_input_indices.push(node_input_index);
        // script output was appended just before optional change; so it is at len-1 if no change, or len-2 if change was added
        let script_vout = if node_change_value > 0 {
            println!("node_change_value > 0");
            commit_psbt.unsigned_tx.output.len() - 2
        } else {
            println!("node_change_value <= 0");
            commit_psbt.unsigned_tx.output.len() - 1
        };
        node_script_vouts.push(script_vout);

        // Log current estimated size and node's fee breakdown
        let pre_vb_node = base_vb; // size before adding dummy witness/change already captured
        let mut temp2 = commit_psbt.unsigned_tx.clone();
        let mut dw2 = Witness::new();
        dw2.push(vec![0u8; 65]);
        temp2.input[node_input_index].witness = dw2;
        let post_vb_node = tx_vbytes(&temp2);
        let node_delta_vb = post_vb_node.saturating_sub(pre_vb_node);
        let estimated_commit_fee_for_node = node_delta_vb.saturating_mul(min_sat_per_vb);
        let commit_fee_paid_by_node_actual = node_prevout
            .value
            .to_sat()
            .saturating_sub(script_value + node_change_value);
        let total_fee_paid_budgeted = commit_fee_paid_by_node_actual.saturating_add(reveal_fee);
        let fee_buffer =
            commit_fee_paid_by_node_actual.saturating_sub(estimated_commit_fee_for_node);
        info!(target: "node",
            "idx={} commit_vb_with_dummy_sig={} vB; node_delta={} vB; total_fee_paid={} sat (commit_fee={} sat, reveal_fee={} sat, buffer={} sat)",
            idx,
            post_vb_node,
            node_delta_vb,
            total_fee_paid_budgeted,
            commit_fee_paid_by_node_actual,
            reveal_fee,
            fee_buffer
        );
    }

    // Prepare prevouts for commit signing
    let all_prevouts_c: Vec<TxOut> = commit_psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().unwrap())
        .collect();

    // Phase 3: Portal constructs REVEAL PSBT referencing fixed commit txid
    let commit_txid = commit_psbt.unsigned_tx.compute_txid();
    let mut reveal_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };

    // For each node, add script spend input and a simple send to node's address as output
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
            value: Amount::from_sat(330),
            script_pubkey: s.address.script_pubkey(),
        });
    }
    let mut reveal_psbt = Psbt::from_unsigned_tx(reveal_tx.clone())?;
    for (i, s) in signups.iter().enumerate() {
        reveal_psbt.inputs[i].witness_utxo =
            Some(commit_psbt.unsigned_tx.output[node_script_vouts[i]].clone());
        reveal_psbt.inputs[i].tap_internal_key = Some(s.internal_key);
    }
    let _nodes_n = signups.len();
    let (_, node_secrets) = get_node_addresses(&secp, &test_cfg)?;

    // Phase 4: Portal sends both PSBTs to nodes; nodes sign commit input (key-spend, SIGHASH_ALL) and reveal input (script-spend, SIGHASH_ALL)
    // Merge node signatures back into original PSBTs
    for (i, s) in signups.iter().enumerate() {
        // Sign commit input for this node
        let input_index = node_input_indices[i];
        let mut tx_to_sign = commit_psbt.unsigned_tx.clone();
        test_utils::sign_key_spend(
            &secp,
            &mut tx_to_sign,
            &all_prevouts_c,
            &node_secrets[i].keypair,
            input_index,
            Some(TapSighashType::Default),
        )?;
        commit_psbt.inputs[input_index].final_script_witness =
            Some(tx_to_sign.input[input_index].witness.clone());

        // Reveal: build tapscript for node and sign script-spend
        let (tap_script, tap_info, _addr) =
            build_tap_script_and_script_address(s.internal_key, b"node-data".to_vec())?;
        let prevouts: Vec<TxOut> = reveal_psbt
            .inputs
            .iter()
            .map(|inp| inp.witness_utxo.clone().expect("wutxo"))
            .collect();
        let mut tx_to_sign_r = reveal_psbt.unsigned_tx.clone();
        test_utils::sign_script_spend_with_sighash(
            &secp,
            &tap_info,
            &tap_script,
            &mut tx_to_sign_r,
            &prevouts,
            &node_secrets[i].keypair,
            i,
            TapSighashType::Default,
        )?;
        reveal_psbt.inputs[i].final_script_witness = Some(tx_to_sign_r.input[i].witness.clone());
    }

    // No portal input to sign in reveal

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
    // No portal assertion (no portal reveal input)

    // Phase 6: Broadcast commit then reveal together
    let commit_hex = hex::encode(serialize_tx(&commit_psbt.extract_tx()?));
    let reveal_hex = hex::encode(serialize_tx(&reveal_psbt.extract_tx()?));
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
