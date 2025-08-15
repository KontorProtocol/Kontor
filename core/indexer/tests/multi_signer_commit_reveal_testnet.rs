use anyhow::Result;
use bitcoin::address::Address;
use bitcoin::amount::Amount;
use bitcoin::hashes::Hash;
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

#[derive(Clone, Debug)]
struct SignerInput {
    outpoint: OutPoint,
    prevout: TxOut,
    internal_key: XOnlyPublicKey,
    keypair: Keypair,
    recipient: Address,
}

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

#[derive(Clone, Debug)]
struct PortalSetup {
    address: Address,
    internal_key: XOnlyPublicKey,
    keypair: Keypair,
    utxos: Vec<(&'static str, u32, u64)>,
}

fn setup_portal(secp: &Secp256k1<All>, test_cfg: &TestConfig) -> Result<PortalSetup> {
    let (portal_address, portal_child_key, _compressed) =
        test_utils::generate_taproot_address_from_mnemonic(secp, test_cfg, 4)?;
    let portal_keypair = Keypair::from_secret_key(secp, &portal_child_key.private_key);
    let (portal_internal_key, _parity) = portal_keypair.x_only_public_key();

    let portal_utxos: Vec<(&'static str, u32, u64)> = vec![
        (
            "09c741dd08af774cb5d1c26bfdc28eaa4ae42306a6a07d7be01de194979ff8df",
            0,
            500_000,
        ),
        (
            "81171f7871d64a2eeae4953bd42c66d8deb1a64e940849f36ffd098398481473",
            0,
            500_000,
        ),
        (
            "ce8cb3d30c0152b71e7007824c06de2b6c6c7598b78196e8133ccb3ca252efa0",
            0,
            500_000,
        ),
    ];

    Ok(PortalSetup {
        address: portal_address,
        internal_key: portal_internal_key,
        keypair: portal_keypair,
        utxos: portal_utxos,
    })
}

fn get_node_signer_info(secp: &Secp256k1<All>, test_cfg: &TestConfig) -> Result<Vec<SignerInput>> {
    let num_signers = 3;
    let mut signers: Vec<SignerInput> = Vec::with_capacity(num_signers);
    for i in 0..num_signers {
        let (address, child_key, _compressed) =
            test_utils::generate_taproot_address_from_mnemonic(secp, test_cfg, i as u32)?;
        let keypair = Keypair::from_secret_key(secp, &child_key.private_key);
        let (internal_key, _parity) = keypair.x_only_public_key();
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
        let outpoint = OutPoint {
            txid: Txid::from_str(txid_str)?,
            vout: vout_u32,
        };
        let prevout = TxOut {
            value: Amount::from_sat(value_sat),
            script_pubkey: address.script_pubkey(),
        };
        let recipient = address.clone();

        signers.push(SignerInput {
            outpoint,
            prevout,
            internal_key,
            keypair,
            recipient,
        });
    }
    Ok(signers)
}

fn tx_vbytes_with_psbt_witnesses_and_portal_dummy(
    psbt: &Psbt,
    portal_inputs_to_dummy: usize,
) -> u64 {
    let mut tx_with_wit = psbt.unsigned_tx.clone();
    let mut remaining_portal = portal_inputs_to_dummy;
    for (idx, input) in tx_with_wit.input.iter_mut().enumerate() {
        if input.witness.is_empty() {
            if let Some(wit) = psbt.inputs[idx].final_script_witness.clone() {
                input.witness = wit;
            } else if remaining_portal > 0 {
                let mut wit = Witness::new();
                wit.push(vec![0u8; 64]);
                input.witness = wit;
                remaining_portal -= 1;
            }
        }
    }
    tx_vbytes(&tx_with_wit)
}

fn estimate_single_input_single_output_reveal_vbytes(
    tap_script: &bitcoin::script::ScriptBuf,
    tap_info: &bitcoin::taproot::TaprootSpendInfo,
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
            value: Amount::from_sat(330),
            // Use 34-byte placeholder to approximate a P2TR output script len
            script_pubkey: bitcoin::script::ScriptBuf::from_bytes(vec![0u8; 34]),
        }],
    };
    let mut w = Witness::new();
    // 64-byte sig + 1 byte sighash type for estimation
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

// (Old test removed)

#[tokio::test]
async fn test_multi_signer_commit_reveal_portal_flow() -> Result<()> {
    logging::setup();
    let mut config = Config::try_parse()?;
    config.bitcoin_rpc_url = "http://127.0.0.1:48332".to_string();
    let client = Client::new_from_config(&config)?;

    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();

    let signers = get_node_signer_info(&secp, &test_cfg)?;
    let portal = setup_portal(&secp, &test_cfg)?;

    let mp = client.get_mempool_info().await?;
    let min_btc_per_kvb = mp
        .mempool_min_fee_btc_per_kvb
        .max(mp.min_relay_tx_fee_btc_per_kvb);
    let min_sat_per_vb: u64 = ((min_btc_per_kvb * 100_000_000.0) / 1000.0).ceil() as u64;
    let dust_limit_sat: u64 = 330;
    info!(target: "node", "min_sat_per_vb={}", min_sat_per_vb);

    // Base COMMIT with portal funding input and placeholder change
    let (portal_funding_txid_s, portal_funding_vout, portal_funding_value) = portal.utxos[0];
    let portal_prevout = TxOut {
        value: Amount::from_sat(portal_funding_value),
        script_pubkey: portal.address.script_pubkey(),
    };
    let base_commit_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(portal_funding_txid_s)?,
                vout: portal_funding_vout,
            },
            script_sig: bitcoin::script::ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: portal.address.script_pubkey(),
        }],
    };
    let mut base_commit_psbt = Psbt::from_unsigned_tx(base_commit_tx.clone())?;
    base_commit_psbt.inputs[0].witness_utxo = Some(portal_prevout.clone());
    base_commit_psbt.inputs[0].tap_internal_key = Some(portal.internal_key);

    // Log base commit details before distributing to nodes
    info!(
        target: "portal",
        "Base COMMIT created: inputs={}, outputs={}, ~{} vB",
        base_commit_psbt.unsigned_tx.input.len(),
        base_commit_psbt.unsigned_tx.output.len(),
        tx_vbytes(&base_commit_psbt.unsigned_tx)
    );

    // Nodes asynchronously append their commit pieces (script output funding reveal + node change) and sign SINGLE|ACP
    let node_commit_futs = signers.iter().enumerate().map(|(idx, s)| {
        let secp = Secp256k1::new();
        let mut psbt_one = base_commit_psbt.clone();
        let portal_prevout_clone = portal_prevout.clone();
        async move {
            info!(target: "node", "Node idx={} appending to COMMIT", idx);

            // Node tapscript and script address
            let (tap_script, tap_info, script_addr) =
                build_tap_script_and_script_address(s.internal_key, b"node-data".to_vec())?;

            // Estimate reveal fee for 1-in (script spend) + 1-out
            let reveal_vb = estimate_single_input_single_output_reveal_vbytes(&tap_script, &tap_info);
            let reveal_fee = reveal_vb.saturating_mul(min_sat_per_vb);
            info!(
                target: "node",
                "idx={} projected reveal size={} vB; projected reveal fee={} sat (@ {} sat/vB)",
                idx,
                reveal_vb,
                reveal_fee,
                min_sat_per_vb
            );
            let script_value = 330 + reveal_fee;

            // Append node input at the end
            let node_input_index = psbt_one.unsigned_tx.input.len();
            psbt_one.unsigned_tx.input.push(TxIn {
                previous_output: s.outpoint,
                script_sig: bitcoin::script::ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            });
            psbt_one.inputs.push(Default::default());
            psbt_one.inputs[node_input_index].witness_utxo = Some(s.prevout.clone());
            psbt_one.inputs[node_input_index].tap_internal_key = Some(s.internal_key);

            // Ensure output index matches node_input_index for SINGLE binding
            debug_assert_eq!(psbt_one.unsigned_tx.output.len(), node_input_index);
            psbt_one.unsigned_tx.output.push(TxOut {
                value: Amount::from_sat(script_value),
                script_pubkey: script_addr.script_pubkey(),
            });
            psbt_one.outputs.push(Default::default());

            // Estimate commit fee impact of witness + a potential change output
            let base_vb = tx_vbytes(&psbt_one.unsigned_tx);
            let mut temp = psbt_one.unsigned_tx.clone();
            let mut dw = Witness::new();
            // 64-byte sig + 1-byte sighash for estimation
            dw.push(vec![0u8; 65]);
            temp.input[node_input_index].witness = dw;
            temp.output.push(TxOut {
                value: Amount::from_sat(0),
                script_pubkey: s.recipient.script_pubkey(),
            });
            let after_with_change_vb = tx_vbytes(&temp);
            let delta_with_change_vb = after_with_change_vb.saturating_sub(base_vb);
            let fee_with_change = delta_with_change_vb.saturating_mul(min_sat_per_vb);

            let mut node_change_value_included = s
                .prevout
                .value
                .to_sat()
                .saturating_sub(script_value + fee_with_change);

            // Only include change if strictly above dust; otherwise omit and let it contribute to fees
            if node_change_value_included > dust_limit_sat {
                psbt_one.unsigned_tx.output.push(TxOut {
                    value: Amount::from_sat(node_change_value_included),
                    script_pubkey: s.recipient.script_pubkey(),
                });
                psbt_one.outputs.push(Default::default());
                info!(
                    target: "node",
                    "idx={} including node change={} sat",
                    idx,
                    node_change_value_included
                );
            } else {
                info!(
                    target: "node",
                    "idx={} omitting node change ({} sat would be dust)",
                    idx,
                    node_change_value_included
                );
                node_change_value_included = 0;
            }

            // Sign node input with SINGLE|ACP
            let mut tx_to_sign = psbt_one.unsigned_tx.clone();
            let prevouts = vec![portal_prevout_clone.clone(), s.prevout.clone()];
            test_utils::sign_key_spend(
                &secp,
                &mut tx_to_sign,
                &prevouts,
                &s.keypair,
                node_input_index,
                Some(TapSighashType::SinglePlusAnyoneCanPay),
            )?;
            psbt_one.inputs[node_input_index].final_script_witness =
                Some(tx_to_sign.input[node_input_index].witness.clone());

            // Log actual post-signing commit size and fee contribution (commit + reveal budgeting)
            let actual_after_vb = tx_vbytes(&tx_to_sign);
            let actual_delta_vb = actual_after_vb.saturating_sub(base_vb);
            let actual_fee_needed = actual_delta_vb.saturating_mul(min_sat_per_vb);
            // Node's commit fee contribution (pre-aggregation)
            let fee_paid = s
                .prevout
                .value
                .to_sat()
                .saturating_sub(script_value + node_change_value_included);
            info!(
                target: "node",
                "idx={} commit size actual={} vB (delta={} vB); node commit fee={} sat (~needed {}); reveal fee budgeted={} sat",
                idx,
                actual_after_vb,
                actual_delta_vb,
                fee_paid,
                actual_fee_needed,
                reveal_fee
            );

            Ok::<Psbt, anyhow::Error>(psbt_one)
        }
    });

    let mut node_commit_parts: Vec<Psbt> = join_all(node_commit_futs)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    info!(target: "portal", "PORTAL AGGREGATING COMMIT*************");

    // Insert a PORTAL script output so the portal also participates in the reveal (reveals its xonly pubkey)
    // We pre-insert this at index 1 so that nodes' script outputs will occupy indices 1..N and push the portal script output to N+1.
    // This preserves SINGLE|ACP mappings for all node inputs while guaranteeing a stable vout for the portal reveal.
    let (portal_tap_script, portal_tap_info, portal_script_addr) =
        build_tap_script_and_script_address(portal.internal_key, b"portal-data".to_vec())?;
    // Estimate portal reveal fee for 1-in (script spend) + 1-out
    let portal_reveal_vb =
        estimate_single_input_single_output_reveal_vbytes(&portal_tap_script, &portal_tap_info);
    let portal_reveal_fee = portal_reveal_vb.saturating_mul(min_sat_per_vb);
    info!(
        target: "portal",
        "Portal projected reveal size={} vB; projected reveal fee={} sat (@ {} sat/vB)",
        portal_reveal_vb,
        portal_reveal_fee,
        min_sat_per_vb
    );
    let portal_script_value = 330 + portal_reveal_fee;

    // Insert portal script output at index 1 (will be pushed to N+1 after node insertions)
    let mut final_commit_psbt = base_commit_psbt.clone();
    final_commit_psbt.unsigned_tx.output.insert(
        1,
        TxOut {
            value: Amount::from_sat(portal_script_value),
            script_pubkey: portal_script_addr.script_pubkey(),
        },
    );
    final_commit_psbt.outputs.insert(1, Default::default());

    // Aggregate COMMIT ensuring input/output index alignment per node
    for (idx, mut p) in node_commit_parts.drain(..).enumerate() {
        let node_input_idx_in_p = p.unsigned_tx.input.len() - 1;
        // Append node input
        final_commit_psbt
            .unsigned_tx
            .input
            .push(p.unsigned_tx.input.remove(node_input_idx_in_p));
        final_commit_psbt
            .inputs
            .push(p.inputs.remove(node_input_idx_in_p));
        let new_input_idx_final = final_commit_psbt.unsigned_tx.input.len() - 1;

        // Insert node script output at same index as input
        let script_out = p.unsigned_tx.output.remove(node_input_idx_in_p);
        final_commit_psbt
            .unsigned_tx
            .output
            .insert(new_input_idx_final, script_out.clone());
        final_commit_psbt
            .outputs
            .insert(new_input_idx_final, Default::default());

        // Assert and log alignment
        assert_eq!(
            final_commit_psbt.unsigned_tx.output[new_input_idx_final].script_pubkey,
            script_out.script_pubkey,
            "script output not aligned with input index"
        );
        info!(
            target: "portal",
            "Aggregated node idx={} → input_index={}, script_output_index={}",
            idx,
            new_input_idx_final,
            new_input_idx_final
        );

        // Append node change at the end if present (skip if node omitted change to avoid dust)
        if p.unsigned_tx.output.len() > 1 {
            let change_out = p.unsigned_tx.output.pop().expect("node change out");
            final_commit_psbt.unsigned_tx.output.push(change_out);
            final_commit_psbt.outputs.push(Default::default());
        }
    }

    // Finalize portal change and sign portal input
    let total_in_c: u64 = final_commit_psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.as_ref().unwrap().value.to_sat())
        .sum();
    let total_out_c: u64 = final_commit_psbt
        .unsigned_tx
        .output
        .iter()
        .map(|o| o.value.to_sat())
        .sum();
    let mut est_vb_c = tx_vbytes_with_psbt_witnesses_and_portal_dummy(&final_commit_psbt, 1);
    let mut req_c = est_vb_c * min_sat_per_vb;
    info!(
        target: "portal",
        "Commit (pre-sign) estimated size={} vB; estimated required fee={} sat (@ {} sat/vB)",
        est_vb_c,
        req_c,
        min_sat_per_vb
    );
    let mut portal_change_val = total_in_c.saturating_sub(total_out_c + req_c);
    if portal_change_val > dust_limit_sat {
        final_commit_psbt.unsigned_tx.output[0].value = Amount::from_sat(portal_change_val);
    } else {
        // Replace portal change with a zero-value OP_RETURN to keep index 0 without creating dust
        final_commit_psbt.unsigned_tx.output[0] = TxOut {
            value: Amount::from_sat(0),
            script_pubkey: {
                let mut opret = bitcoin::script::ScriptBuf::new();
                opret.push_opcode(bitcoin::opcodes::all::OP_RETURN);
                opret.push_slice(b"kon");
                opret
            },
        };
        portal_change_val = 0;
    }
    est_vb_c = tx_vbytes_with_psbt_witnesses_and_portal_dummy(&final_commit_psbt, 1);
    req_c = est_vb_c * min_sat_per_vb;
    let total_out_c2: u64 = final_commit_psbt
        .unsigned_tx
        .output
        .iter()
        .map(|o| o.value.to_sat())
        .sum();
    let fee_paid_c = total_in_c.saturating_sub(total_out_c2);
    assert!(fee_paid_c >= req_c);
    let all_prevouts_c: Vec<TxOut> = final_commit_psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.clone().unwrap())
        .collect();
    let mut tx_to_sign_c = final_commit_psbt.unsigned_tx.clone();
    test_utils::sign_key_spend(
        &secp,
        &mut tx_to_sign_c,
        &all_prevouts_c,
        &portal.keypair,
        0,
        None,
    )?;
    final_commit_psbt.inputs[0].final_script_witness = Some(tx_to_sign_c.input[0].witness.clone());
    let commit_vb_actual = tx_vbytes_with_psbt_witnesses_and_portal_dummy(&final_commit_psbt, 0);
    let commit_req_fee_actual = commit_vb_actual * min_sat_per_vb;
    let portal_total_input_spent = portal_prevout
        .value
        .to_sat()
        .saturating_sub(portal_change_val);
    let portal_fee_contribution = portal_total_input_spent.saturating_sub(portal_script_value);
    let node_fee_contribution_total = fee_paid_c.saturating_sub(portal_fee_contribution);
    info!(
        target: "portal",
        "Commit actual size={} vB; commit required fee={} sat; portal input spent={} sat (fees {} sat, script {} sat); node fee total={} sat; total commit fee paid={} sat",
        commit_vb_actual,
        commit_req_fee_actual,
        portal_total_input_spent,
        portal_fee_contribution,
        portal_script_value,
        node_fee_contribution_total,
        fee_paid_c
    );

    // Build REVEAL PSBT from frozen commit; no portal inputs
    let commit_tx = final_commit_psbt.unsigned_tx.clone();
    let mut reveal_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    // Outputs layout: [0]=portal change/opreturn, then for each node i: script at vout (i+1)
    let nodes_n = signers.len();
    for (i, s) in signers.iter().enumerate() {
        let script_vout = (i as u32) + 1;
        reveal_tx.input.push(TxIn {
            previous_output: OutPoint {
                txid: commit_tx.compute_txid(),
                vout: script_vout,
            },
            script_sig: bitcoin::script::ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
        reveal_tx.output.push(TxOut {
            value: Amount::from_sat(330),
            script_pubkey: s.recipient.script_pubkey(),
        });
    }
    // Add portal reveal input/output. After node insertions, portal script output is at vout (nodes_n + 1)
    let portal_script_vout = (nodes_n as u32) + 1;
    reveal_tx.input.push(TxIn {
        previous_output: OutPoint {
            txid: commit_tx.compute_txid(),
            vout: portal_script_vout,
        },
        script_sig: bitcoin::script::ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    });
    reveal_tx.output.push(TxOut {
        value: Amount::from_sat(330),
        script_pubkey: portal.address.script_pubkey(),
    });
    let mut reveal_psbt = Psbt::from_unsigned_tx(reveal_tx.clone())?;
    (0..nodes_n).for_each(|i| {
        let vout = i + 1;
        reveal_psbt.inputs[i].witness_utxo = Some(commit_tx.output[vout].clone());
        reveal_psbt.inputs[i].tap_internal_key = Some(signers[i].internal_key);
    });
    // Set portal reveal input metadata
    reveal_psbt.inputs[nodes_n].witness_utxo = Some(commit_tx.output[nodes_n + 1].clone());
    reveal_psbt.inputs[nodes_n].tap_internal_key = Some(portal.internal_key);

    // Nodes sign reveal inputs with SINGLE|ACP (script path)
    let reveal_futs = signers.iter().enumerate().map(|(i, s)| {
        let secp = Secp256k1::new();
        let mut psbt_one = reveal_psbt.clone();
        async move {
            // Base size before this node's witness is attached
            let base_vb_r = tx_vbytes_with_psbt_witnesses_and_portal_dummy(&psbt_one, 0);
            let (tap_script, tap_info, _addr) =
                build_tap_script_and_script_address(s.internal_key, b"node-data".to_vec())?;
            use bitcoin::secp256k1::Message;
            use bitcoin::sighash::{Prevouts, SighashCache};
            use bitcoin::taproot::{LeafVersion, TapLeafHash};
            let tx_to_sign = psbt_one.unsigned_tx.clone();
            let prevouts: Vec<TxOut> = psbt_one
                .inputs
                .iter()
                .map(|inp| inp.witness_utxo.clone().expect("wutxo"))
                .collect();
            let mut sighasher = SighashCache::new(&tx_to_sign);
            let sighash = sighasher
                .taproot_script_spend_signature_hash(
                    i,
                    &Prevouts::All(&prevouts),
                    TapLeafHash::from_script(&tap_script, LeafVersion::TapScript),
                    TapSighashType::SinglePlusAnyoneCanPay,
                )
                .expect("sighash");
            let msg = Message::from_digest(sighash.to_byte_array());
            let sig = secp.sign_schnorr(&msg, &s.keypair);
            let signature = bitcoin::taproot::Signature {
                signature: sig,
                sighash_type: TapSighashType::SinglePlusAnyoneCanPay,
            };
            let mut w = Witness::new();
            w.push(signature.to_vec());
            w.push(tap_script.as_bytes());
            w.push(
                tap_info
                    .control_block(&(tap_script.clone(), LeafVersion::TapScript))
                    .expect("cb")
                    .serialize(),
            );
            psbt_one.inputs[i].final_script_witness = Some(w);

            // Log actual post-signing reveal size and fee contribution
            let actual_after_vb_r = tx_vbytes_with_psbt_witnesses_and_portal_dummy(&psbt_one, 0);
            let delta_vb_r = actual_after_vb_r.saturating_sub(base_vb_r);
            let in_val_r = psbt_one.inputs[i]
                .witness_utxo
                .as_ref()
                .expect("wutxo")
                .value
                .to_sat();
            let out_val_r = psbt_one.unsigned_tx.output[i].value.to_sat();
            let fee_paid_r_i = in_val_r.saturating_sub(out_val_r);
            info!(
                target: "node",
                "idx={} reveal size actual={} vB (delta={} vB); reveal fee paid by input={} sat",
                i,
                actual_after_vb_r,
                delta_vb_r,
                fee_paid_r_i
            );
            Ok::<Psbt, anyhow::Error>(psbt_one)
        }
    });
    let mut reveal_parts: Vec<Psbt> = join_all(reveal_futs)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;
    let mut final_reveal_psbt = reveal_psbt.clone();
    for (i, p) in reveal_parts.drain(..).enumerate() {
        final_reveal_psbt.inputs[i].final_script_witness = p.inputs[i].final_script_witness.clone();
    }
    // Sign portal reveal input synchronously and attach
    {
        let secp = Secp256k1::new();
        // Base size before portal witness
        let base_vb_r_portal =
            tx_vbytes_with_psbt_witnesses_and_portal_dummy(&final_reveal_psbt, 0);
        let (tap_script, tap_info, _addr) =
            build_tap_script_and_script_address(portal.internal_key, b"portal-data".to_vec())?;
        use bitcoin::secp256k1::Message;
        use bitcoin::sighash::{Prevouts, SighashCache};
        use bitcoin::taproot::{LeafVersion, TapLeafHash};
        let tx_to_sign = final_reveal_psbt.unsigned_tx.clone();
        let prevouts: Vec<TxOut> = final_reveal_psbt
            .inputs
            .iter()
            .map(|inp| inp.witness_utxo.clone().expect("wutxo"))
            .collect();
        let mut sighasher = SighashCache::new(&tx_to_sign);
        let sighash = sighasher
            .taproot_script_spend_signature_hash(
                nodes_n,
                &Prevouts::All(&prevouts),
                TapLeafHash::from_script(&tap_script, LeafVersion::TapScript),
                TapSighashType::SinglePlusAnyoneCanPay,
            )
            .expect("sighash");
        let msg = Message::from_digest(sighash.to_byte_array());
        let sig = secp.sign_schnorr(&msg, &portal.keypair);
        let signature = bitcoin::taproot::Signature {
            signature: sig,
            sighash_type: TapSighashType::SinglePlusAnyoneCanPay,
        };
        let mut w = Witness::new();
        w.push(signature.to_vec());
        w.push(tap_script.as_bytes());
        w.push(
            tap_info
                .control_block(&(tap_script.clone(), LeafVersion::TapScript))
                .expect("cb")
                .serialize(),
        );
        final_reveal_psbt.inputs[nodes_n].final_script_witness = Some(w);

        // Log actual post-signing reveal size and fee contribution for portal
        let actual_after_vb_r_portal =
            tx_vbytes_with_psbt_witnesses_and_portal_dummy(&final_reveal_psbt, 0);
        let delta_vb_r_portal = actual_after_vb_r_portal.saturating_sub(base_vb_r_portal);
        let in_val_r_portal = final_reveal_psbt.inputs[nodes_n]
            .witness_utxo
            .as_ref()
            .expect("wutxo")
            .value
            .to_sat();
        let out_val_r_portal = final_reveal_psbt.unsigned_tx.output[nodes_n].value.to_sat();
        let fee_paid_r_portal = in_val_r_portal.saturating_sub(out_val_r_portal);
        info!(
            target: "portal",
            "Portal reveal size actual={} vB (delta={} vB); portal reveal fee paid={} sat",
            actual_after_vb_r_portal,
            delta_vb_r_portal,
            fee_paid_r_portal
        );
    }
    let reveal_vb_actual = tx_vbytes_with_psbt_witnesses_and_portal_dummy(&final_reveal_psbt, 0);
    let reveal_req_fee_actual = reveal_vb_actual * min_sat_per_vb;
    let total_in_r: u64 = final_reveal_psbt
        .inputs
        .iter()
        .map(|i| i.witness_utxo.as_ref().unwrap().value.to_sat())
        .sum();
    let total_out_r: u64 = final_reveal_psbt
        .unsigned_tx
        .output
        .iter()
        .map(|o| o.value.to_sat())
        .sum();
    let fee_paid_r = total_in_r.saturating_sub(total_out_r);
    let required_total = commit_req_fee_actual.saturating_add(reveal_req_fee_actual);
    let fee_paid_total = fee_paid_c.saturating_add(fee_paid_r);
    info!(
        target: "portal",
        "Reveal actual size={} vB; reveal required fee={} sat; reveal fee paid={} sat",
        reveal_vb_actual,
        reveal_req_fee_actual,
        fee_paid_r
    );
    info!(
        target: "portal",
        "Overall: required fee={} sat; fee paid={} sat (portal fee {} sat)",
        required_total,
        fee_paid_total,
        portal_fee_contribution
    );

    // Assert each entity's x-only pubkey is revealed in tapscript of reveal witnesses
    for (i, s) in signers.iter().enumerate() {
        let wit = final_reveal_psbt.inputs[i]
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
    // Portal assertion
    {
        let wit = final_reveal_psbt.inputs[nodes_n]
            .final_script_witness
            .as_ref()
            .expect("portal reveal witness");
        assert!(
            wit.len() >= 2,
            "portal witness must contain signature and script"
        );
        let script_bytes = wit.iter().nth(1).expect("script");
        let script = bitcoin::script::ScriptBuf::from_bytes(script_bytes.to_vec());
        let mut it = script.instructions();
        if let Some(Ok(Instruction::PushBytes(bytes))) = it.next() {
            assert_eq!(
                bytes.as_bytes(),
                &portal.internal_key.serialize(),
                "portal xonly pubkey not revealed correctly"
            );
        } else {
            panic!("portal tapscript missing leading pubkey push");
        }
    }

    // Broadcast both at the end
    let commit_hex = hex::encode(serialize_tx(&final_commit_psbt.extract_tx()?));
    let reveal_hex = hex::encode(serialize_tx(&final_reveal_psbt.extract_tx()?));
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
