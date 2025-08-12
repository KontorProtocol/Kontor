use anyhow::Result;
use bitcoin::address::Address;
use bitcoin::amount::Amount;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::secp256k1::All;
use bitcoin::transaction::Version;
use bitcoin::{
    Network, OutPoint, Psbt, Sequence, Transaction, TxIn, TxOut, XOnlyPublicKey, absolute::LockTime,
};
use bitcoin::{TapSighashType, consensus::encode::serialize as serialize_tx};
use bitcoin::{Txid, Witness};
use clap::Parser;
use futures_util::future::join_all;
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

#[derive(Clone)]
struct NodePart {
    psbt: Psbt,
    delta_vb: u64,
    node_fee: u64,
    prevout_value: u64,
    return_value: u64,
}

fn tx_vbytes(tx: &Transaction) -> u64 {
    // Compute virtual size = (base_size*4 + witness_size + 3)/4
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

fn estimate_vbytes_unsigned(base_len_bytes: usize, input_count: usize) -> u64 {
    // Estimate witness overhead per Taproot key-path input (~100 bytes upper bound)
    let witness_estimate = (input_count as u64) * 100u64;
    let weight = (base_len_bytes as u64) * 4 + witness_estimate;
    weight.div_ceil(4)
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
            _ => (
                "b672084964187d9655a008c2af90c7d79b19fddcd66390bcf2926c0ea8e4135a",
                0,
                500_000,
            ),
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

#[tokio::test]
async fn test_multi_signer_psbt_fee_topup_testnet() -> Result<()> {
    // setup
    logging::setup();
    let mut config = Config::try_parse()?;
    config.bitcoin_rpc_url = "http://127.0.0.1:48332".to_string();
    let client = Client::new_from_config(&config)?;

    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();

    // Set up storage node utxos
    let signers = get_node_signer_info(&secp, &test_cfg)?;

    // Portal base with one input and placeholder change output
    let (portal_address, portal_child_key, _compressed) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &test_cfg, 4)?;
    let portal_keypair = Keypair::from_secret_key(&secp, &portal_child_key.private_key);
    let (portal_internal_key, _parity) = portal_keypair.x_only_public_key();

    // Portal funding set (top-up pool)
    let portal_utxos: Vec<(&str, u32, u64)> = vec![
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

    // set up portal utxos
    let first = portal_utxos[0];
    let portal_outpoint = OutPoint {
        txid: Txid::from_str(first.0)?,
        vout: first.1,
    };
    let portal_prevout = TxOut {
        value: Amount::from_sat(first.2),
        script_pubkey: portal_address.script_pubkey(),
    };

    // portal base transaction to be sent to all nodes
    let base_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: portal_outpoint,
            script_sig: bitcoin::script::ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        // placeholder change; will be recomputed after aggregation
        output: vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: portal_address.script_pubkey(),
        }],
    };

    let mut base_psbt = Psbt::from_unsigned_tx(base_tx.clone())?;
    base_psbt.inputs[0].witness_utxo = Some(portal_prevout.clone());
    base_psbt.inputs[0].tap_internal_key = Some(portal_internal_key);
    let base_len_bytes = serialize_tx(&base_psbt.unsigned_tx).len();
    let base_est_vb = estimate_vbytes_unsigned(base_len_bytes, base_psbt.unsigned_tx.input.len());
    info!(target: "portal", "PortalBase PSBT: inputs={}, outputs={}, ~{} vB",
        base_psbt.unsigned_tx.input.len(), base_psbt.unsigned_tx.output.len(), base_est_vb);

    // Fetch min relay fee (sat/vB) before nodes contribute fees
    let mp = client.get_mempool_info().await?;
    let net = client.get_network_info().await?;
    let min_btc_per_kvb = mp.mempool_min_fee_btc_per_kvb.max(net.relayfee);
    let min_sat_per_vb: u64 = ((min_btc_per_kvb * 100_000_000.0) / 1000.0).ceil() as u64;
    info!(target: "portal", "min_sat/vB={} for transaction of base size ~{} vB", min_sat_per_vb, base_est_vb);

    let dust_limit_sat: u64 = 330; // approx P2TR dust

    // Storage nodes: each appends input/output and signs with SINGLE|ACP, contributes fee ~ size_added * rate
    let futures = signers.iter().enumerate().map(|(idx, s)| {
        let secp = Secp256k1::new();
        let mut psbt_one = base_psbt.clone();
        let portal_prevout_clone = portal_prevout.clone();
        async move {
            info!(target: "node", " Node idx={} adding input: {}:{}, value={} sat",
                idx, s.outpoint.txid, s.outpoint.vout, s.prevout.value.to_sat());

            // Estimate node's size contribution in vbytes: before vs after adding input+output
            let base_len_b = serialize_tx(&psbt_one.unsigned_tx).len();
            let base_est_vb = estimate_vbytes_unsigned(base_len_b, psbt_one.unsigned_tx.input.len());
            info!(target: "node", "Node idx={} base size before adding input/output ~{} vB",
                idx, base_est_vb);
            let mut temp_unsigned = psbt_one.unsigned_tx.clone();
            temp_unsigned.input.push(TxIn {
                previous_output: s.outpoint,
                script_sig: bitcoin::script::ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            });
            temp_unsigned.output.push(TxOut {
                value: Amount::from_sat(0), // placeholder; value doesn't affect size much
                script_pubkey: s.recipient.script_pubkey(),
            });
            let after_len_b = serialize_tx(&temp_unsigned).len();
            let after_est_vb = estimate_vbytes_unsigned(after_len_b, temp_unsigned.input.len());
            let delta_vb = after_est_vb.saturating_sub(base_est_vb);
            let node_fee = delta_vb.saturating_mul(min_sat_per_vb);
            info!(target: "node", "Node idx={} size after adding input/output ~{} vB",
                idx, after_est_vb);
            info!(target: "node", "Node idx={} size added by node delta_vB={} fee_contrib={} sat",
                idx, delta_vb, node_fee);

            // Now actually append input+output to psbt_one with node's fee contribution
            psbt_one.unsigned_tx = temp_unsigned; // reuse temp we already built
            psbt_one.inputs.push(Default::default());
            let new_input_index = psbt_one.unsigned_tx.input.len() - 1;
            psbt_one.inputs[new_input_index].witness_utxo = Some(s.prevout.clone());
            psbt_one.inputs[new_input_index].tap_internal_key = Some(s.internal_key);

            // Compute return value; ensure not below dust
            let mut node_return_value = s.prevout.value.to_sat().saturating_sub(node_fee);
            if node_return_value < dust_limit_sat {
                node_return_value = dust_limit_sat;
            }
            psbt_one.unsigned_tx.output.last_mut().unwrap().value = Amount::from_sat(node_return_value);
            psbt_one.outputs.push(Default::default());

            let mut tx_to_sign = psbt_one.unsigned_tx.clone();
            let prevouts = vec![portal_prevout_clone, s.prevout.clone()];
            let psbt_len = serialize_tx(&psbt_one.unsigned_tx).len();
            let psbt_est_vb = estimate_vbytes_unsigned(psbt_len, psbt_one.unsigned_tx.input.len());
            info!(target: "node", "Node idx={} sighash=SINGLE|ACP, ~{} vB (delta={} vB), fee_contrib={} sat, output_to={}, change value={} sat",
                idx, psbt_est_vb, delta_vb, node_fee, s.recipient, node_return_value);
            test_utils::sign_key_spend(
                &secp,
                &mut tx_to_sign,
                &prevouts,
                &s.keypair,
                new_input_index,
                Some(TapSighashType::SinglePlusAnyoneCanPay),
            )?;
            psbt_one.inputs[new_input_index].final_script_witness =
                Some(tx_to_sign.input[new_input_index].witness.clone());

            Ok::<NodePart, anyhow::Error>(NodePart {
                psbt: psbt_one,
                delta_vb,
                node_fee,
                prevout_value: s.prevout.value.to_sat(),
                return_value: node_return_value,
            })
        }
    });

    let mut parts: Vec<NodePart> = join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    // Assert each node contributed the correct fee based on size delta and rate
    for (idx, p) in parts.iter().enumerate() {
        let max_affordable_fee = p.prevout_value.saturating_sub(dust_limit_sat);
        let expected_fee = p.node_fee.min(max_affordable_fee);
        let actual_fee = p.prevout_value.saturating_sub(p.return_value);
        assert_eq!(
            actual_fee, expected_fee,
            "node {} fee mismatch: expected {}, actual {} (delta_vb={}, sats/vB={})",
            idx, expected_fee, actual_fee, p.delta_vb, min_sat_per_vb
        );
    }

    // Aggregate starting from base
    let mut final_psbt = base_psbt.clone();
    for mut p in parts.drain(..) {
        let last_input_idx = p.psbt.unsigned_tx.input.len() - 1;
        let last_output_idx = p.psbt.unsigned_tx.output.len() - 1;
        final_psbt
            .unsigned_tx
            .input
            .push(p.psbt.unsigned_tx.input.remove(last_input_idx));
        final_psbt.inputs.push(p.psbt.inputs.remove(last_input_idx));
        final_psbt
            .unsigned_tx
            .output
            .push(p.psbt.unsigned_tx.output.remove(last_output_idx));
        final_psbt
            .outputs
            .push(p.psbt.outputs.remove(last_output_idx));
    }

    // Compute top-up need: ensure non-negative change for portal, else add more portal inputs
    // Compute overall budget and fee target; then portal tops up if needed
    let dust_limit_sat: u64 = 330; // approximate P2TR dust
    let mut sum_inputs: u64 = portal_prevout.value.to_sat();
    let mut sum_outputs: u64 = 0;
    for s in &signers {
        sum_inputs += s.prevout.value.to_sat();
    }
    // node outputs are all outputs except index 0 (portal change placeholder)
    for (i, o) in final_psbt.unsigned_tx.output.iter().enumerate() {
        if i == 0 {
            continue;
        }
        sum_outputs += o.value.to_sat();
    }
    // Reuse the pre-fetched min_sat_per_vb computed above
    info!(target: "portal", "FeeTopUp: using pre-fetched min_sat/vB={}", min_sat_per_vb);

    // Rough vsize estimate: base bytes + 100B per input for taproot witness (upper bound)
    let mut base_len = serialize_tx(&final_psbt.unsigned_tx).len();
    let mut est_vbytes = estimate_vbytes_unsigned(base_len, final_psbt.unsigned_tx.input.len());
    let mut required_fee = est_vbytes * min_sat_per_vb;
    // Available budget for fee and change
    let mut available_budget = sum_inputs.saturating_sub(sum_outputs);

    // If required_change is insufficient for a valid change output, add more portal inputs
    let mut portal_inputs_used = 1usize;
    // Ensure fee is covered by available inputs; only add portal inputs if budget < required_fee
    while available_budget < required_fee && portal_inputs_used < portal_utxos.len() {
        let (txid_s, vout_u32, value_sat) = portal_utxos[portal_inputs_used];
        let more_prevout = TxOut {
            value: Amount::from_sat(value_sat),
            script_pubkey: portal_address.script_pubkey(),
        };
        final_psbt.unsigned_tx.input.push(TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(txid_s)?,
                vout: vout_u32,
            },
            script_sig: bitcoin::script::ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        });
        final_psbt.inputs.push(Default::default());
        let idx = final_psbt.inputs.len() - 1;
        final_psbt.inputs[idx].witness_utxo = Some(more_prevout.clone());
        final_psbt.inputs[idx].tap_internal_key = Some(portal_internal_key);
        sum_inputs += value_sat;

        // Recompute estimated fee with added input
        base_len = serialize_tx(&final_psbt.unsigned_tx).len();
        est_vbytes = estimate_vbytes_unsigned(base_len, final_psbt.unsigned_tx.input.len());
        required_fee = est_vbytes * min_sat_per_vb;
        available_budget = sum_inputs.saturating_sub(sum_outputs);
        portal_inputs_used += 1;
        info!(target: "portal", "FeeTopUp: Added portal input {}:{} ({} sat); new budget={} sat, est_fee={} sat",
            txid_s, vout_u32, value_sat, available_budget, required_fee);
    }

    // Compute change after fee is covered
    if available_budget <= required_fee {
        // No change; treat remainder (if any) as fee
        final_psbt.unsigned_tx.output.remove(0);
        final_psbt.outputs.remove(0);
        info!(target: "portal", "FeeTopUp: No change (budget {} <= fee {}), dropping change output", available_budget, required_fee);
    } else {
        let change = available_budget - required_fee;
        if change >= dust_limit_sat {
            final_psbt.unsigned_tx.output[0].value = Amount::from_sat(change);
            info!(target: "portal", "FeeTopUp: Portal change set to {} sat", change);
        } else {
            final_psbt.unsigned_tx.output.remove(0);
            final_psbt.outputs.remove(0);
            info!(target: "portal", "FeeTopUp: Change {} < dust {}, dropped (added to fee)", change, dust_limit_sat);
        }
    }

    // Sign all portal inputs (first N used) with DEFAULT
    for i in 0..portal_inputs_used {
        let mut tx_to_sign = final_psbt.unsigned_tx.clone();
        // Build prevouts in order for all inputs
        let mut all_prevouts: Vec<TxOut> = Vec::with_capacity(final_psbt.unsigned_tx.input.len());
        // For simplicity, reconstruct from known pieces
        // First portal input
        if i == 0 {
            all_prevouts.push(portal_prevout.clone());
            for s in &signers {
                all_prevouts.push(s.prevout.clone());
            }
            // Additional portal inputs appended after nodes
            (1..portal_inputs_used).for_each(|j| {
                let (_txid_s, _vout_u32, value_sat) = portal_utxos[j];
                all_prevouts.push(TxOut {
                    value: Amount::from_sat(value_sat),
                    script_pubkey: portal_address.script_pubkey(),
                });
            });
        } else {
            // Still build the same full prevouts vector; index i will point to the ith portal input
            all_prevouts.push(portal_prevout.clone());
            for s in &signers {
                all_prevouts.push(s.prevout.clone());
            }
            (1..portal_inputs_used).for_each(|j| {
                let (_txid_s, _vout_u32, value_sat) = portal_utxos[j];
                all_prevouts.push(TxOut {
                    value: Amount::from_sat(value_sat),
                    script_pubkey: portal_address.script_pubkey(),
                });
            });
        }
        test_utils::sign_key_spend(
            &secp,
            &mut tx_to_sign,
            &all_prevouts,
            &portal_keypair,
            i,
            None,
        )?;
        final_psbt.inputs[i].final_script_witness = Some(tx_to_sign.input[i].witness.clone());
    }

    let final_tx = final_psbt.extract_tx()?;
    let final_vbytes = tx_vbytes(&final_tx);
    let mut total_in = 0u64;
    (0..portal_inputs_used).for_each(|inp| {
        total_in += portal_utxos[inp].2;
    });
    for s in &signers {
        total_in += s.prevout.value.to_sat();
    }
    let mut total_out = 0u64;
    for o in &final_tx.output {
        total_out += o.value.to_sat();
    }
    let fee_sat = total_in.saturating_sub(total_out);
    info!(target: "portal", "FeeTopUp: Final tx ~{} vB, inputs={}, outputs={}, fee={} sat",
        final_vbytes, final_tx.input.len(), final_tx.output.len(), fee_sat);
    println!("FINAL TX {:#?}", final_tx);
    let hex = hex::encode(serialize_tx(&final_tx));
    let res = client.test_mempool_accept(&[hex]).await?;
    assert!(!res.is_empty());
    assert!(
        res[0].allowed,
        "Final aggregated transaction was rejected: {:?}",
        res[0].reject_reason
    );

    Ok(())
}
