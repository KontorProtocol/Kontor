use anyhow::Result;
use bitcoin::address::Address;
use bitcoin::amount::Amount;
use bitcoin::consensus::encode::serialize as serialize_tx;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::script::Instruction;
use bitcoin::secp256k1::All;
use bitcoin::transaction::Version;
use bitcoin::{OutPoint, Sequence, Transaction, TxIn, TxOut, XOnlyPublicKey, absolute::LockTime};
use bitcoin::{Psbt, TapSighashType, Txid, Witness};
use futures_util::future::join_all;
use tracing::info;

use std::path::Path;
use std::str::FromStr;

use crate::test_utils;
use bitcoin::Network;
use bitcoin::address::KnownHrp;
use bitcoin::opcodes::{
    OP_0, OP_FALSE,
    all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::taproot::{TaprootBuilder, TaprootSpendInfo};

#[derive(Clone, Debug)]
pub struct NodeInfo {
    pub address: Address,
    pub internal_key: XOnlyPublicKey,
}

#[derive(Clone, Debug)]
pub struct NodeSecrets {
    pub keypair: Keypair,
}

#[derive(Clone, Debug)]
pub struct PortalInfo {
    pub address: Address,
    pub internal_key: XOnlyPublicKey,
    pub keypair: Keypair,
}

// NODE AND PORTAL SETUP HELPERS
pub fn get_node_addresses(
    secp: &Secp256k1<All>,
    network: Network,
    taproot_key_path: &Path,
) -> Result<(Vec<NodeInfo>, Vec<NodeSecrets>)> {
    let mut infos = Vec::new();
    let mut secrets = Vec::new();
    for i in 0..3 {
        let (address, child_key, _compressed) = test_utils::generate_taproot_address_from_mnemonic(
            secp,
            network,
            taproot_key_path,
            i as u32,
        )?;
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

pub fn get_portal_info(
    secp: &Secp256k1<All>,
    network: Network,
    taproot_key_path: &Path,
) -> Result<PortalInfo> {
    let (address, child_key, _compressed) =
        test_utils::generate_taproot_address_from_mnemonic(secp, network, taproot_key_path, 4)?;
    let keypair = Keypair::from_secret_key(secp, &child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();
    Ok(PortalInfo {
        address,
        internal_key,
        keypair,
    })
}

pub fn mock_fetch_utxos_for_addresses(signups: &[NodeInfo]) -> Vec<(OutPoint, TxOut)> {
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

pub fn mock_fetch_portal_utxo(portal: &PortalInfo) -> (OutPoint, TxOut) {
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
pub fn tx_vbytes(tx: &Transaction) -> u64 {
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

pub fn estimate_single_input_single_output_reveal_vbytes(
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

/// Network-aware builder for tapscript and its P2TR address.
pub fn build_tap_script_and_script_address_helper(
    x_only_public_key: XOnlyPublicKey,
    data: Vec<u8>,
    network: Network,
) -> Result<(bitcoin::script::ScriptBuf, TaprootSpendInfo, Address)> {
    let secp = Secp256k1::new();

    // tapscript: <xonly_pubkey> OP_CHECKSIG OP_FALSE OP_IF "kon" OP_0 <data_chunks...> OP_ENDIF
    let mut builder = Builder::new()
        .push_slice(x_only_public_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0);

    const MAX_SCRIPT_ELEMENT_SIZE: usize = 520;
    if data.is_empty() {
        return Err(anyhow::anyhow!("script data cannot be empty"));
    }
    for chunk in data.chunks(MAX_SCRIPT_ELEMENT_SIZE) {
        builder = builder.push_slice(PushBytesBuf::try_from(chunk.to_vec())?);
    }
    let tap_script = builder.push_opcode(OP_ENDIF).into_script();

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .map_err(|e| anyhow::anyhow!("Failed to add leaf: {}", e))?
        .finalize(&secp, x_only_public_key)
        .map_err(|e| anyhow::anyhow!("Failed to finalize Taproot tree: {:?}", e))?;

    let output_key = taproot_spend_info.output_key();
    // Map networks to correct HRP strings for address presentation
    let hrp = match network {
        Network::Bitcoin => KnownHrp::Mainnet,
        Network::Regtest => KnownHrp::Regtest,
        _ => KnownHrp::Testnets,
    };
    let script_spendable_address = Address::p2tr_tweaked(output_key, hrp);
    Ok((tap_script, taproot_spend_info, script_spendable_address))
}

pub fn log_node_sign_size_and_fee_breakdown(
    reveal_psbt_local: &Psbt,
    i: usize,
    reveal_tx_local: &mut Transaction,
    min_sat_per_vb: u64,
) {
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
    // Compute fair share of base (non-witness) bytes across inputs
    let mut base_no_witness = reveal_psbt_local.unsigned_tx.clone();
    for inp in &mut base_no_witness.input {
        inp.witness = Witness::new();
    }
    let base_vb = tx_vbytes(&base_no_witness);
    let num_inputs = reveal_psbt_local.unsigned_tx.input.len() as u64;
    let base_share_vb = if num_inputs > 0 {
        base_vb / num_inputs
    } else {
        0
    };
    let fair_needed_fee_node =
        (base_share_vb.saturating_add(delta_vb_r)).saturating_mul(min_sat_per_vb);
    let witness_only_needed = delta_vb_r.saturating_mul(min_sat_per_vb);
    info!(
        "idx={} reveal_vb_now={} vB; node_reveal_delta={} vB; base_share={} vB; reveal_fee_paid={} sat; witness_only_needed={} sat; fair_needed={} sat",
        i,
        after_vb_r,
        delta_vb_r,
        base_share_vb,
        fee_paid_r_i,
        witness_only_needed,
        fair_needed_fee_node
    );
    assert!(
        fee_paid_r_i >= fair_needed_fee_node,
        "node {} reveal fee insufficient: paid={} < fair_needed={}",
        i,
        fee_paid_r_i,
        fair_needed_fee_node
    );

    let reveal_witness = reveal_tx_local.input[i].witness.clone();
    info!(
        "idx={} produced reveal witness (stack_elems={})",
        i,
        reveal_witness.len()
    );
}

pub fn log_total_size_and_fee_breakdown(
    commit_psbt: &Psbt,
    reveal_psbt: &Psbt,
    min_sat_per_vb: u64,
)
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

pub fn add_single_node_input_and_output_to_commit_psbt(
    commit_psbt: &mut Psbt,
    node_utxos: &[(OutPoint, TxOut)],
    idx: usize,
    min_sat_per_vb: u64,
    node_info: &NodeInfo,
    dust_limit_sat: u64,
) -> Result<(u64, usize, usize)> {
    info!("node idx={} appending to COMMIT", idx);
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
    commit_psbt.inputs[node_input_index].tap_internal_key = Some(node_info.internal_key);

    // Append script output for node at the end
    let (tap_script, tap_info, script_addr) = build_tap_script_and_script_address_helper(
        node_info.internal_key,
        b"node-data".to_vec(),
        Network::Testnet4,
    )?;

    // Estimate reveal fee the node will need to pay later (1-in script + 1-out to self)
    let reveal_vb = estimate_single_input_single_output_reveal_vbytes(
        &tap_script,
        &tap_info,
        node_info.address.script_pubkey().len(),
        dust_limit_sat,
    );
    let reveal_fee = reveal_vb.saturating_mul(min_sat_per_vb);
    let node_reveal_fee = reveal_fee;
    info!(
        "node idx={} estimated_reveal_size={} vB; estimated_reveal_fee={} sat ",
        idx, reveal_vb, reveal_fee
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
        script_pubkey: node_info.address.script_pubkey(),
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
            script_pubkey: node_info.address.script_pubkey(),
        });
        commit_psbt.outputs.push(Default::default());
    } else {
        node_change_value = 0;
    }

    let node_input_index: usize = node_input_index;
    // script output was appended just before optional change; so it is at len-1 if no change, or len-2 if change was added
    let script_vout = if node_change_value > 0 {
        commit_psbt.unsigned_tx.output.len() - 2
    } else {
        commit_psbt.unsigned_tx.output.len() - 1
    };
    let node_script_vout = script_vout;

    info!(
        "idx={} commit_vb_with_dummy_sig={} vB; node_delta={} vB; total_fee_paid={} sat (commit_fee={} sat, reveal_fee={} sat, buffer={} sat)",
        idx,
        tx_vbytes(&temp),
        full_delta_vb,
        node_prevout.value.to_sat() - (script_value + node_change_value),
        fee_full_delta,
        reveal_fee,
        fee_full_delta - full_delta_vb.saturating_mul(min_sat_per_vb)
    );

    Ok((node_reveal_fee, node_input_index, node_script_vout))
}

pub fn add_portal_input_and_output_to_commit_psbt(
    commit_psbt: &mut Psbt,
    min_sat_per_vb: u64,
    dust_limit_sat: u64,
    secp: &Secp256k1<All>,
    network: Network,
    taproot_key_path: &Path,
) -> Result<(PortalInfo, u64, usize)> {
    // Portal participation: append portal input/output (script reveal) and charge full-delta fee like nodes
    info!("portal appending to COMMIT");
    let portal_info = get_portal_info(secp, network, taproot_key_path)?;
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
        build_tap_script_and_script_address_helper(
            portal_info.internal_key,
            b"portal-data".to_vec(),
            Network::Testnet4,
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

    info!(
        "portal commit_vb_with_dummy_sig={} vB; portal_delta={} vB; total_fee_paid={} sat (commit_fee={} sat, reveal_fee={} sat, buffer={} sat)",
        tx_vbytes(&temp_portal),
        portal_full_delta_vb,
        portal_prevout.value.to_sat() - (portal_script_value + portal_change_value),
        portal_fee_full_delta,
        portal_reveal_fee,
        portal_fee_full_delta - portal_full_delta_vb.saturating_mul(min_sat_per_vb)
    );

    Ok((portal_info, portal_change_value, portal_input_index))
}

pub fn add_node_input_and_output_to_reveal_psbt(
    reveal_psbt: &mut Psbt,
    commit_txid: Txid,
    node_script_vouts: &[usize],
    idx: usize,
    dust_limit_sat: u64,
    node_info: &NodeInfo,
    commit_psbt: &Psbt,
) {
    let script_vout = node_script_vouts[idx] as u32;
    reveal_psbt.unsigned_tx.input.push(TxIn {
        previous_output: OutPoint {
            txid: commit_txid,
            vout: script_vout,
        },
        script_sig: bitcoin::script::ScriptBuf::new(),
        sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
        witness: Witness::new(),
    });
    reveal_psbt.unsigned_tx.output.push(TxOut {
        value: Amount::from_sat(dust_limit_sat),
        script_pubkey: node_info.address.script_pubkey(),
    });
    reveal_psbt.inputs.push(Default::default());
    reveal_psbt.inputs[idx].witness_utxo =
        Some(commit_psbt.unsigned_tx.output[node_script_vouts[idx]].clone());
    reveal_psbt.inputs[idx].tap_internal_key = Some(node_info.internal_key);
}

pub fn add_portal_input_and_output_to_reveal_psbt(
    reveal_psbt: &mut Psbt,
    portal_change_value: u64,
    dust_limit_sat: u64,
    portal_info: &PortalInfo,
    commit_psbt: &Psbt,
    nodes_length: usize,
) {
    let commit_txid = commit_psbt.unsigned_tx.compute_txid();
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
    reveal_psbt.inputs[nodes_length].witness_utxo =
        Some(commit_psbt.unsigned_tx.output[portal_script_vout as usize].clone());
    reveal_psbt.inputs[nodes_length].tap_internal_key = Some(portal_info.internal_key);
}

pub fn node_sign_commit_and_reveal(
    node_info: &NodeInfo,
    index: usize,
    psbts: (Psbt, Psbt),
    prevouts_commits: &[TxOut],
    node_input_indices: &[usize],
    min_sat_per_vb: u64,
    node_secrets: &[NodeSecrets],
) -> impl std::future::Future<Output = Result<(usize, Psbt, Psbt), anyhow::Error>> + Send {
    let secp = Secp256k1::new();
    let keypair = node_secrets[index].keypair;
    let mut commit_tx_local = psbts.0.unsigned_tx.clone();
    let mut commit_psbt_local = psbts.0;
    let mut reveal_psbt_local = psbts.1;
    let input_index = node_input_indices[index];
    async move {
        // Commit: sign only this node's input
        test_utils::sign_key_spend(
            &secp,
            &mut commit_tx_local,
            prevouts_commits,
            &keypair,
            input_index,
            Some(TapSighashType::Default),
        )?;
        let commit_witness = commit_tx_local.input[input_index].witness.clone();
        info!(
            "idx={} produced commit witness (stack_elems={})",
            index,
            commit_witness.len()
        );
        // Attach to local commit psbt
        commit_psbt_local.inputs[input_index].final_script_witness = Some(commit_witness);

        // Reveal: sign only this node's reveal input and log sizes/fees
        let (tap_script, tap_info, _addr) = build_tap_script_and_script_address_helper(
            node_info.internal_key,
            b"node-data".to_vec(),
            Network::Testnet4,
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
            index,
            TapSighashType::Default,
        )?;

        log_node_sign_size_and_fee_breakdown(
            &reveal_psbt_local,
            index,
            &mut reveal_tx_local,
            min_sat_per_vb,
        );

        let reveal_witness = reveal_tx_local.input[index].witness.clone();
        // Attach to local reveal psbt
        reveal_psbt_local.inputs[index].final_script_witness = Some(reveal_witness);

        Ok::<(usize, Psbt, Psbt), anyhow::Error>((index, commit_psbt_local, reveal_psbt_local))
    }
}

pub async fn merge_node_signatures<I, F>(
    node_sign_futs: I,
    node_input_indices: &[usize],
    commit_psbt: &mut Psbt,
    reveal_psbt: &mut Psbt,
) -> Result<()>
where
    I: IntoIterator<Item = F>,
    F: std::future::Future<Output = Result<(usize, Psbt, Psbt), anyhow::Error>> + Send,
{
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
        info!(
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
    Ok(())
}

pub fn portal_signs_commit_and_reveal(
    commit_psbt: &mut Psbt,
    reveal_psbt: &mut Psbt,
    portal_info: &PortalInfo,
    all_prevouts_c: &[TxOut],
    portal_input_index: usize,
    min_sat_per_vb: u64,
    nodes_length: usize,
) -> Result<()> {
    let secp = Secp256k1::new();

    // Sign portal commit input
    let mut tx_to_sign_portal = commit_psbt.unsigned_tx.clone();
    test_utils::sign_key_spend(
        &secp,
        &mut tx_to_sign_portal,
        all_prevouts_c,
        &portal_info.keypair,
        portal_input_index,
        Some(TapSighashType::Default),
    )?;
    commit_psbt.inputs[portal_input_index].final_script_witness =
        Some(tx_to_sign_portal.input[portal_input_index].witness.clone());
    info!(
        "portal added commit witness (stack_elems={})",
        tx_to_sign_portal.input[portal_input_index].witness.len()
    );

    // Portal signs reveal input
    let (tap_script, tap_info, _addr) = build_tap_script_and_script_address_helper(
        portal_info.internal_key,
        b"portal-data".to_vec(),
        Network::Testnet4,
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
        nodes_length,
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
    reveal_after.input[nodes_length].witness = txp.input[nodes_length].witness.clone();
    let after_vb_r_portal = tx_vbytes(&reveal_after);
    let delta_vb_r_portal = after_vb_r_portal.saturating_sub(before_vb_r_portal);
    let in_val_r_portal = reveal_psbt.inputs[nodes_length]
        .witness_utxo
        .as_ref()
        .expect("wutxo")
        .value
        .to_sat();
    let out_val_r_portal = reveal_psbt.unsigned_tx.output[nodes_length].value.to_sat();
    let fee_paid_r_portal = in_val_r_portal.saturating_sub(out_val_r_portal);
    let needed_fee_portal = delta_vb_r_portal.saturating_mul(min_sat_per_vb);
    info!(
        "portal reveal_vb_now={} vB; reveal_delta={} vB; reveal_fee_paid={} sat; reveal_fee_needed={} sat",
        after_vb_r_portal, delta_vb_r_portal, fee_paid_r_portal, needed_fee_portal
    );
    assert!(
        fee_paid_r_portal >= needed_fee_portal,
        "portal reveal fee insufficient: paid={} < needed={}",
        fee_paid_r_portal,
        needed_fee_portal
    );
    reveal_psbt.inputs[nodes_length].final_script_witness =
        Some(txp.input[nodes_length].witness.clone());
    info!(
        "portal added reveal witness (stack_elems={})",
        txp.input[nodes_length].witness.len()
    );
    Ok(())
}

pub fn verify_x_only_pubkeys(
    signups: &[NodeInfo],
    reveal_psbt: &Psbt,
    commit_psbt: &Psbt,
    min_sat_per_vb: u64,
) {
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

    log_total_size_and_fee_breakdown(commit_psbt, reveal_psbt, min_sat_per_vb);
}
