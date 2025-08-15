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
use tracing::{info, warn};
#[derive(Clone, Debug)]
struct SignerInput {
    outpoint: OutPoint,
    prevout: TxOut,
    internal_key: XOnlyPublicKey,
    keypair: Keypair,
    recipient: Address,
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

#[derive(Clone, Debug)]
struct PortalSetup {
    address: Address,
    internal_key: XOnlyPublicKey,
    keypair: Keypair,
    first_prevout: TxOut,
    base_psbt: Psbt,
    utxos: Vec<(&'static str, u32, u64)>,
}

fn setup_portal(secp: &Secp256k1<All>, test_cfg: &TestConfig) -> Result<PortalSetup> {
    // Generate portal address (derivation index 4)
    let (portal_address, portal_child_key, _compressed) =
        test_utils::generate_taproot_address_from_mnemonic(secp, test_cfg, 4)?;
    let portal_keypair = Keypair::from_secret_key(secp, &portal_child_key.private_key);
    let (portal_internal_key, _parity) = portal_keypair.x_only_public_key();

    // Portal funding set (top-up pool)
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

    // Use the first portal UTXO for initial base PSBT input
    let first = portal_utxos[0];
    let portal_outpoint = OutPoint {
        txid: Txid::from_str(first.0)?,
        vout: first.1,
    };
    let portal_prevout = TxOut {
        value: Amount::from_sat(first.2),
        script_pubkey: portal_address.script_pubkey(),
    };

    // Base transaction with placeholder change output
    let base_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: portal_outpoint,
            script_sig: bitcoin::script::ScriptBuf::new(),
            sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: portal_address.script_pubkey(),
        }],
    };

    let mut base_psbt = Psbt::from_unsigned_tx(base_tx)?;
    base_psbt.inputs[0].witness_utxo = Some(portal_prevout.clone());
    base_psbt.inputs[0].tap_internal_key = Some(portal_internal_key);

    Ok(PortalSetup {
        address: portal_address,
        internal_key: portal_internal_key,
        keypair: portal_keypair,
        first_prevout: portal_prevout,
        base_psbt,
        utxos: portal_utxos,
    })
}

fn tx_vbytes_with_psbt_witnesses_and_portal_dummy(
    psbt: &Psbt,
    portal_internal_key: XOnlyPublicKey,
    portal_inputs_to_dummy: usize,
) -> u64 {
    // Build a tx view: use actual witnesses for signed inputs; add dummy for portal inputs still unsigned
    let mut tx_with_wit = psbt.unsigned_tx.clone();
    let mut remaining_portal = portal_inputs_to_dummy;
    for (idx, input) in tx_with_wit.input.iter_mut().enumerate() {
        if input.witness.is_empty() {
            if let Some(wit) = psbt.inputs[idx].final_script_witness.clone() {
                input.witness = wit;
            } else if psbt.inputs[idx].tap_internal_key == Some(portal_internal_key)
                && remaining_portal > 0
            {
                let mut wit = Witness::new();
                // DEFAULT sighash for portal inputs → 64B Schnorr signature
                wit.push(vec![0u8; 64]);
                input.witness = wit;
                remaining_portal -= 1;
            }
        }
    }
    tx_vbytes(&tx_with_wit)
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
#[ignore]
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

    // Portal setup
    let portal = setup_portal(&secp, &test_cfg)?;
    let portal_address = portal.address.clone();
    let portal_internal_key = portal.internal_key;
    let portal_prevout = portal.first_prevout.clone();
    let portal_utxos = portal.utxos.clone();
    let base_psbt = portal.base_psbt.clone();
    let base_actual_vb = tx_vbytes(&base_psbt.unsigned_tx);
    info!(target: "portal", "Portal created PSBT to send to nodes: inputs={}, outputs={}, ~{} vB",
        base_psbt.unsigned_tx.input.len(), base_psbt.unsigned_tx.output.len(), base_actual_vb);

    // Fetch min relay fee (sat/vB) before nodes contribute fees
    let mp = client.get_mempool_info().await?;
    let min_btc_per_kvb = mp
        .mempool_min_fee_btc_per_kvb
        .max(mp.min_relay_tx_fee_btc_per_kvb);
    let min_sat_per_vb: u64 = ((min_btc_per_kvb * 100_000_000.0) / 1000.0).ceil() as u64;
    info!(target: "portal", "min_sat_per_vb={}", min_sat_per_vb);

    let dust_limit_sat: u64 = 330; // approx P2TR dust

    // Storage nodes: each appends input/output and signs with SINGLE|ACP, contributes fee ~ size_added * rate
    let futures = signers.iter().enumerate().map(|(idx, s)| {
        let secp = Secp256k1::new();
        let mut psbt_one = base_psbt.clone();
        let portal_prevout_clone = portal_prevout.clone();
        async move {
            info!(target: "node", "Node idx={} starting**********************", idx);
            // create dummy inputs/outputs in order to calculate size for fee
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

            // Estimate node's size contribution in vbytes: include dummy signature for accuracy
            let base_vb = tx_vbytes(&psbt_one.unsigned_tx);

            // dummy Schnorr sig ~65 bytes in witness to approximate signed vbytes
            let last_idx = temp_unsigned.input.len() - 1;
            let mut dummy_wit = Witness::new();
            dummy_wit.push(vec![0u8; 65]);
            temp_unsigned.input[last_idx].witness = dummy_wit;

            // calculate size + fee after adding dummy input/output and dummy sig
            let after_vb = tx_vbytes(&temp_unsigned);
            let delta_vb = after_vb.saturating_sub(base_vb);
            let node_fee = delta_vb.saturating_mul(min_sat_per_vb);
            info!(target: "node", "size_with_dummy_sig={}vB (size_delta_dummy={}vB); node_fee={} sats (@ {} sats/vB)", after_vb, delta_vb, node_fee, min_sat_per_vb);

            // Now actually append input+output to psbt_one with node's fee contribution
            psbt_one.unsigned_tx = temp_unsigned; // reuse temp we already built
            psbt_one.inputs.push(Default::default());
            let new_input_index = psbt_one.unsigned_tx.input.len() - 1;

            // Clear the dummy witness before real signing
            psbt_one.unsigned_tx.input[new_input_index].witness = Witness::new();
            psbt_one.inputs[new_input_index].witness_utxo = Some(s.prevout.clone());
            psbt_one.inputs[new_input_index].tap_internal_key = Some(s.internal_key);

            // Compute return value; ensure not below dust; this is effectively "change" going back to the node
            // Output value = input - fee
            let mut node_return_value = s.prevout.value.to_sat().saturating_sub(node_fee);
            if node_return_value < dust_limit_sat {
                node_return_value = dust_limit_sat;
            }
            psbt_one.unsigned_tx.output.last_mut().unwrap().value = Amount::from_sat(node_return_value);
            psbt_one.outputs.push(Default::default());

            let mut tx_to_sign = psbt_one.unsigned_tx.clone();
            let prevouts = vec![portal_prevout_clone, s.prevout.clone()];

            // sign the tx
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

            // Re-check with ACTUAL signed size
            let actual_after_vb = tx_vbytes(&tx_to_sign);
            let actual_delta_vb = actual_after_vb.saturating_sub(base_vb);
            let actual_fee_needed = actual_delta_vb.saturating_mul(min_sat_per_vb);
            let fee_paid = s.prevout.value.to_sat().saturating_sub(node_return_value);
            info!(target: "node", "size_final={}vB (size_delta_final={}vB); node_fee: {} sats >= {} sats)", actual_after_vb, actual_delta_vb,fee_paid, actual_fee_needed);

            if s.prevout.value.to_sat() >= actual_fee_needed.saturating_add(dust_limit_sat) {
                assert_eq!(fee_paid, actual_fee_needed, "Node idx={} expected actual fee {} sat based on {} vB @ {} sat/vB, got {} sat", idx, actual_fee_needed, actual_delta_vb, min_sat_per_vb, fee_paid);
            } else {
                warn!(target: "node", "Node idx={} couldn't fully cover fee without violating dust; change clamped to dust", idx);
                // don't fail bc portal will cover remaining fee
                assert!(fee_paid <= actual_fee_needed, "Node idx={} overpaid actual fee ({} > {})", idx, fee_paid, actual_fee_needed);
                assert_eq!(node_return_value, dust_limit_sat, "Node idx={} change not clamped to dust as expected (actual)", idx);
            }

            Ok::<Psbt, anyhow::Error>(psbt_one)
        }
    });

    let mut parts: Vec<Psbt> = join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    // Aggregate starting from base
    info!(target: "portal", " **********************PORTAL AGGREGATING PSBT********************************");

    let mut final_psbt = base_psbt.clone();
    for mut p in parts.drain(..) {
        let last_input_idx = p.unsigned_tx.input.len() - 1;
        let last_output_idx = p.unsigned_tx.output.len() - 1;
        final_psbt
            .unsigned_tx
            .input
            .push(p.unsigned_tx.input.remove(last_input_idx));
        final_psbt.inputs.push(p.inputs.remove(last_input_idx));
        final_psbt
            .unsigned_tx
            .output
            .push(p.unsigned_tx.output.remove(last_output_idx));
        final_psbt.outputs.push(p.outputs.remove(last_output_idx));
    }

    // Compute top-up need: ensure non-negative change for portal, else add more portal inputs
    // Compute overall budget and fee target; then portal tops up if needed
    let dust_limit_sat: u64 = 330; // approximate P2TR dust
    let mut sum_inputs: u64 = portal_prevout.value.to_sat();
    let mut sum_outputs: u64 = 0;
    for s in &signers {
        sum_inputs += s.prevout.value.to_sat();
    }
    // Node outputs are all outputs except index 0 (portal change placeholder)
    for (i, o) in final_psbt.unsigned_tx.output.iter().enumerate() {
        if i == 0 {
            continue;
        }
        sum_outputs += o.value.to_sat();
    }

    // Fees already contributed by nodes
    let node_fee_sum = sum_inputs
        .saturating_sub(portal_prevout.value.to_sat())
        .saturating_sub(sum_outputs);

    // Track portal inputs used, their total value, and indices in the tx
    let mut portal_inputs_sum: u64 = portal_prevout.value.to_sat();
    let mut portal_input_indices: Vec<usize> = vec![0usize];

    // Compute vbytes approximating post-signing by using node witnesses (present) and dummying portal
    let mut est_vbytes = tx_vbytes_with_psbt_witnesses_and_portal_dummy(
        &final_psbt,
        portal_internal_key,
        portal_input_indices.len(),
    );
    let mut required_fee = est_vbytes * min_sat_per_vb;
    let mut remaining_fee = required_fee.saturating_sub(node_fee_sum);
    info!(target: "portal", "Aggregated PSBT: psbt_size_with_dummy_portal_sig={}vB, required_fee={}, node_fee_sum={}, remaining_fee for portal to cover={}", est_vbytes, required_fee, node_fee_sum, remaining_fee);

    // Ensure portal covers remaining fee; add more portal inputs if necessary
    while portal_inputs_sum < remaining_fee && portal_input_indices.len() < portal_utxos.len() {
        let next_portal_utxo_idx = portal_input_indices.len();
        let (txid_s, vout_u32, value_sat) = portal_utxos[next_portal_utxo_idx];
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

        portal_inputs_sum = portal_inputs_sum.saturating_add(value_sat);
        portal_input_indices.push(idx);

        // Recompute size and remaining fee with current portal inputs
        est_vbytes = tx_vbytes_with_psbt_witnesses_and_portal_dummy(
            &final_psbt,
            portal_internal_key,
            portal_input_indices.len(),
        );
        required_fee = est_vbytes * min_sat_per_vb;
        remaining_fee = required_fee.saturating_sub(node_fee_sum);
        info!(target: "portal", "Input added to portal portal_inputs_sum={}, est_vbytes={}, required_fee={}, remaining_fee={}",
            portal_inputs_sum, est_vbytes, required_fee, remaining_fee);
    }

    // Compute portal change after fee is covered
    let portal_change = portal_inputs_sum.saturating_sub(remaining_fee);
    if portal_change < dust_limit_sat {
        final_psbt.unsigned_tx.output.remove(0);
        final_psbt.outputs.remove(0);
        info!(target: "portal", "Change {} < dust {}, dropped (added to fee), total_fee_paid={}", portal_change, dust_limit_sat, node_fee_sum + (portal_inputs_sum - portal_change));
    } else {
        final_psbt.unsigned_tx.output[0].value = Amount::from_sat(portal_change);
        info!(target: "portal", "portal_change={}; required_fee={}; total_fee_paid={}", portal_change, required_fee, node_fee_sum + (portal_inputs_sum - portal_change));
    }

    // Sign only the portal inputs with portal key: build prevouts once
    let all_prevouts: Vec<TxOut> = final_psbt
        .inputs
        .iter()
        .map(|inp| {
            inp.witness_utxo
                .clone()
                .expect("missing witness_utxo for input")
        })
        .collect();

    let mut tx_to_sign = final_psbt.unsigned_tx.clone();
    for &idx in &portal_input_indices {
        test_utils::sign_key_spend(
            &secp,
            &mut tx_to_sign,
            &all_prevouts,
            &portal.keypair,
            idx,
            None,
        )?;
    }
    // Copy back only portal input witnesses
    for &idx in &portal_input_indices {
        final_psbt.inputs[idx].final_script_witness = Some(tx_to_sign.input[idx].witness.clone());
    }

    // Compute total input value directly from PSBT inputs' witness_utxo
    let total_in: u64 = final_psbt
        .inputs
        .iter()
        .map(|inp| {
            inp.witness_utxo
                .as_ref()
                .expect("missing witness_utxo for input")
                .value
                .to_sat()
        })
        .sum();

    let final_tx = final_psbt.extract_tx()?;
    let final_vbytes = tx_vbytes(&final_tx);
    let mut total_out = 0u64;
    for o in &final_tx.output {
        total_out += o.value.to_sat();
    }
    let fee_sat = total_in.saturating_sub(total_out);
    let final_required_fee = final_vbytes.saturating_mul(min_sat_per_vb);
    info!(target: "portal", "assert fee paid covers required fee");
    info!(target: "portal", "Final size={}vB; min_sat_per_vb={}; required_fee={} sat; fee_paid={} sat", final_vbytes, min_sat_per_vb, final_required_fee, fee_sat);
    assert!(
        fee_sat >= final_required_fee,
        "Final fee {} sat is less than required {} sat at {} sat/vB for {} vB",
        fee_sat,
        final_required_fee,
        min_sat_per_vb,
        final_vbytes
    );

    println!("final_tx: {:#?}", final_tx);

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
