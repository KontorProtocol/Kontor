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
use futures_util::future::join_all;
use indexer::api::compose::build_tap_script_and_script_address;
use indexer::config::{Config, TestConfig};
use indexer::{bitcoin_client::Client, logging, test_utils};
use std::str::FromStr;
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

#[derive(Clone, Debug)]
struct NodeInfo {
    address: Address,
    internal_key: XOnlyPublicKey,
}

#[derive(Clone, Debug)]
struct NodeSecrets {
    keypair: Keypair,
}

#[derive(Clone, Debug)]
struct PortalInfo {
    address: Address,
    internal_key: XOnlyPublicKey,
    keypair: Keypair,
}

// NODE AND PORTAL SETUP HELPERS
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

fn get_portal_info(secp: &Secp256k1<All>, test_cfg: &TestConfig) -> Result<PortalInfo> {
    let (address, child_key, _compressed) =
        test_utils::generate_taproot_address_from_mnemonic(secp, test_cfg, 4)?;
    let keypair = Keypair::from_secret_key(secp, &child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();
    Ok(PortalInfo {
        address,
        internal_key,
        keypair,
    })
}

fn mock_fetch_utxos_for_addresses(signups: &[NodeInfo]) -> Vec<(OutPoint, TxOut)> {
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

fn mock_fetch_portal_utxo(portal: &PortalInfo) -> (OutPoint, TxOut) {
    let (txid_str, vout_u32, value_sat): (&str, u32, u64) = (
        "09c741dd08af774cb5d1c26bfdc28eaa4ae42306a6a07d7be01de194979ff8df",
        0,
        500_000,
    );
    (
        OutPoint {
            txid: Txid::from_str(txid_str).unwrap(),
            vout: vout_u32,
        },
        TxOut {
            value: Amount::from_sat(value_sat),
            script_pubkey: portal.address.script_pubkey(),
        },
    )
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
    let mut config = Config::try_parse()?;
    // Ensure we are talking to the Testnet4 node (default port 48332)
    config.bitcoin_rpc_url = "https://testnet4.counterparty.io:48332/".to_string();
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
    info!("min_sat_per_vb={}", min_sat_per_vb);

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

    for (idx, s) in signups.iter().enumerate() {
        log_node!("node idx={} appending to COMMIT", idx);
        let (node_outpoint, node_prevout) = node_utxos[idx].clone();
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

        // Log current estimated size and node's fee breakdown (full-delta based)
        let mut temp2 = commit_psbt.unsigned_tx.clone();
        let mut dw2 = Witness::new();
        dw2.push(vec![0u8; 65]);
        temp2.input[node_input_index].witness = dw2;
        let post_vb_node = tx_vbytes(&temp2);
        let node_delta_vb = full_delta_vb;
        let estimated_commit_fee_for_node = fee_full_delta;
        let commit_fee_paid_by_node_actual = node_prevout
            .value
            .to_sat()
            .saturating_sub(script_value + node_change_value);
        let total_fee_paid_budgeted = commit_fee_paid_by_node_actual.saturating_add(reveal_fee);
        let fee_buffer =
            commit_fee_paid_by_node_actual.saturating_sub(estimated_commit_fee_for_node);
        log_node!(
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

    // Portal participation: append portal input/output (script reveal) and charge full-delta fee like nodes
    info!("portal appending to COMMIT");
    let portal_info = get_portal_info(&secp, &test_cfg)?;
    let (portal_outpoint, portal_prevout) = mock_fetch_portal_utxo(&portal_info);
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
        build_tap_script_and_script_address(portal_info.internal_key, b"portal-data".to_vec())?;
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

    let mut temp2_portal = commit_psbt.unsigned_tx.clone();
    let mut dw2p = Witness::new();
    dw2p.push(vec![0u8; 65]);
    temp2_portal.input[portal_input_index].witness = dw2p;
    let post_vb_portal = tx_vbytes(&temp2_portal);
    let estimated_commit_fee_for_portal = portal_fee_full_delta;
    let commit_fee_paid_by_portal_actual = portal_prevout
        .value
        .to_sat()
        .saturating_sub(portal_script_value + portal_change_value);
    let portal_total_fee_budgeted =
        commit_fee_paid_by_portal_actual.saturating_add(portal_reveal_fee);
    let portal_fee_buffer =
        commit_fee_paid_by_portal_actual.saturating_sub(estimated_commit_fee_for_portal);
    log_portal!(
        "portal commit_vb_with_dummy_sig={} vB; portal_delta={} vB; total_fee_paid={} sat (commit_fee={} sat, reveal_fee={} sat, buffer={} sat)",
        post_vb_portal,
        portal_full_delta_vb,
        portal_total_fee_budgeted,
        commit_fee_paid_by_portal_actual,
        portal_reveal_fee,
        portal_fee_buffer
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

    let (_, node_secrets) = get_node_addresses(&secp, &test_cfg)?;

    // Phase 4: Portal sends both PSBTs to nodes; nodes sign commit input (key-spend, SIGHASH_ALL) and reveal input (script-spend, SIGHASH_ALL)
    // Each node signs asynchronously and returns only its own witnesses; portal merges them
    let commit_base_tx = commit_psbt.unsigned_tx.clone();
    let reveal_base_psbt = reveal_psbt.clone();
    let all_prevouts_clone = all_prevouts_c.clone();

    let node_sign_futs = signups.iter().enumerate().map(|(i, s)| {
        let secp = Secp256k1::new();
        let keypair = node_secrets[i].keypair;
        let mut commit_tx_local = commit_base_tx.clone();
        let reveal_psbt_local = reveal_base_psbt.clone();
        let prevouts_commit = all_prevouts_clone.clone();
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

            // Reveal: sign only this node's reveal input and log sizes/fees
            let (tap_script, tap_info, _addr) =
                build_tap_script_and_script_address(s.internal_key, b"node-data".to_vec())?;
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

            // Logging: compute delta for this node
            let mut reveal_before = reveal_psbt_local.unsigned_tx.clone();
            for j in 0..reveal_before.input.len() {
                if let Some(wit) = &reveal_psbt_local.inputs[j].final_script_witness {
                    reveal_before.input[j].witness = wit.clone();
                }
            }
            let before_vb_r = tx_vbytes(&reveal_before);
            let mut reveal_after = reveal_before.clone();
            reveal_after.input[i].witness = reveal_tx_local.input[i].witness.clone();
            let after_vb_r = tx_vbytes(&reveal_after);
            let delta_vb_r = after_vb_r.saturating_sub(before_vb_r);
            let in_val_r = reveal_psbt_local.inputs[i]
                .witness_utxo
                .as_ref()
                .expect("wutxo")
                .value
                .to_sat();
            let out_val_r = reveal_psbt_local.unsigned_tx.output[i].value.to_sat();
            let fee_paid_r_i = in_val_r.saturating_sub(out_val_r);
            let needed_fee_node = delta_vb_r.saturating_mul(min_sat_per_vb);
            log_node!(
                "idx={} reveal_vb_now={} vB; node_reveal_delta={} vB; reveal_fee_paid={} sat; reveal_fee_needed={} sat",
                i,
                after_vb_r,
                delta_vb_r,
                fee_paid_r_i,
                needed_fee_node
            );
            assert!(fee_paid_r_i >= needed_fee_node,
                "node {} reveal fee insufficient: paid={} < needed={}", i, fee_paid_r_i, needed_fee_node);

            let reveal_witness = reveal_tx_local.input[i].witness.clone();
            Ok::<(usize, Witness, Witness), anyhow::Error>((i, commit_witness, reveal_witness))
        }
    });

    let node_witnesses: Vec<(usize, Witness, Witness)> = join_all(node_sign_futs)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    // Merge node witnesses back into the original PSBTs
    for (i, cw, rw) in node_witnesses {
        commit_psbt.inputs[node_input_indices[i]].final_script_witness = Some(cw);
        reveal_psbt.inputs[i].final_script_witness = Some(rw);
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
    }

    // Portal signs reveal input
    {
        let (tap_script, tap_info, _addr) =
            build_tap_script_and_script_address(portal_info.internal_key, b"portal-data".to_vec())?;
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

    // Final fee accounting: compute full signed sizes and required fees, and assert total paid >= total required
    {
        // Commit actual size and required fee
        let mut commit_tx_f = commit_psbt.unsigned_tx.clone();
        for i in 0..commit_psbt.inputs.len() {
            if let Some(w) = &commit_psbt.inputs[i].final_script_witness {
                commit_tx_f.input[i].witness = w.clone();
            }
        }
        let commit_vb_actual = tx_vbytes(&commit_tx_f);
        let commit_req_fee_actual = commit_vb_actual.saturating_mul(min_sat_per_vb);
        let commit_in_total: u64 = commit_psbt
            .inputs
            .iter()
            .map(|inp| inp.witness_utxo.as_ref().unwrap().value.to_sat())
            .sum();
        let commit_out_total: u64 = commit_psbt
            .unsigned_tx
            .output
            .iter()
            .map(|o| o.value.to_sat())
            .sum();
        let commit_paid_total = commit_in_total.saturating_sub(commit_out_total);

        // Reveal actual size and required fee
        let mut reveal_tx_f = reveal_psbt.unsigned_tx.clone();
        for i in 0..reveal_psbt.inputs.len() {
            if let Some(w) = &reveal_psbt.inputs[i].final_script_witness {
                reveal_tx_f.input[i].witness = w.clone();
            }
        }
        let reveal_vb_actual = tx_vbytes(&reveal_tx_f);
        let reveal_req_fee_actual = reveal_vb_actual.saturating_mul(min_sat_per_vb);
        let reveal_in_total: u64 = reveal_psbt
            .inputs
            .iter()
            .map(|inp| inp.witness_utxo.as_ref().unwrap().value.to_sat())
            .sum();
        let reveal_out_total: u64 = reveal_psbt
            .unsigned_tx
            .output
            .iter()
            .map(|o| o.value.to_sat())
            .sum();
        let reveal_paid_total = reveal_in_total.saturating_sub(reveal_out_total);

        let required_total = commit_req_fee_actual.saturating_add(reveal_req_fee_actual);
        let paid_total = commit_paid_total.saturating_add(reveal_paid_total);
        info!(
            "final: commit_size={} vB, commit_required={} sat, commit_paid={} sat; reveal_size={} vB, reveal_required={} sat, reveal_paid={} sat; overall_required={} sat, overall_paid={} sat",
            commit_vb_actual,
            commit_req_fee_actual,
            commit_paid_total,
            reveal_vb_actual,
            reveal_req_fee_actual,
            reveal_paid_total,
            required_total,
            paid_total
        );
        assert!(
            paid_total >= required_total,
            "overall fee insufficient: paid={} < required={}",
            paid_total,
            required_total
        );
    }

    let commit_tx = commit_psbt.extract_tx()?;
    let reveal_tx = reveal_psbt.extract_tx()?;
    println!("commit_tx: {:#?}", commit_tx);
    println!("reveal_tx: {:#?}", reveal_tx);

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
