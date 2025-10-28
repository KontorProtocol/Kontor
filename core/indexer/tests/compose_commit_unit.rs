use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::{Address, FeeRate, KnownHrp, transaction::TxOut};
use bitcoin::{Amount, OutPoint, Txid};
use indexer::api::compose::{CommitInputs, ComposeInputs, InstructionInputs, compose_commit};
use std::str::FromStr;

fn fixed_keypair() -> (Secp256k1<bitcoin::secp256k1::All>, Keypair) {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[2u8; 32]).expect("secret key");
    let kp = Keypair::from_secret_key(&secp, &sk);
    (secp, kp)
}

#[test]
fn test_compose_commit_unique_vout_mapping_even_with_identical_chunks() {
    let (_secp, kp) = fixed_keypair();
    let (xonly, _parity) = kp.x_only_public_key();
    let addr = Address::p2tr_tweaked(
        bitcoin::taproot::TaprootBuilder::new()
            .finalize(&Secp256k1::new(), xonly)
            .unwrap()
            .output_key(),
        KnownHrp::Mainnet,
    );
    // Two participants with identical script data to force identical tapscripts
    let data = b"same".to_vec();
    let utxo0 = (
        OutPoint {
            txid: Txid::from_str(
                "0303030303030303030303030303030303030303030303030303030303030303",
            )
            .unwrap(),
            vout: 0,
        },
        TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: addr.script_pubkey(),
        },
    );
    let utxo1 = (
        OutPoint {
            txid: Txid::from_str(
                "0404040404040404040404040404040404040404040404040404040404040404",
            )
            .unwrap(),
            vout: 0,
        },
        TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: addr.script_pubkey(),
        },
    );

    let chunks = indexer::api::compose::split_even_chunks(&data, 2).unwrap();
    let inputs = ComposeInputs::builder()
        .instructions(vec![
            InstructionInputs {
                address: addr.clone(),
                x_only_public_key: xonly,
                funding_utxos: vec![utxo0.clone()],
                script_data: chunks[0].clone(),
            },
            InstructionInputs {
                address: addr.clone(),
                x_only_public_key: xonly,
                funding_utxos: vec![utxo1.clone()],
                script_data: chunks[1].clone(),
            },
        ])
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .envelope(546)
        .build();
    let commit = compose_commit(CommitInputs::from(inputs)).expect("commit");
    // Ensure outpoints in reveal_inputs are unique
    let vouts: std::collections::HashSet<u32> = commit
        .reveal_inputs
        .participants
        .iter()
        .map(|p| p.commit_outpoint.vout)
        .collect();
    assert_eq!(
        vouts.len(),
        2,
        "each participant should map to a unique vout"
    );
}

#[test]
fn test_compose_commit_psbt_inputs_have_metadata() {
    let (_secp, kp) = fixed_keypair();
    let (xonly, _parity) = kp.x_only_public_key();
    let addr = Address::p2tr_tweaked(
        bitcoin::taproot::TaprootBuilder::new()
            .finalize(&Secp256k1::new(), xonly)
            .unwrap()
            .output_key(),
        KnownHrp::Mainnet,
    );
    let utxo = (
        OutPoint {
            txid: Txid::from_str(
                "0505050505050505050505050505050505050505050505050505050505050505",
            )
            .unwrap(),
            vout: 0,
        },
        TxOut {
            value: Amount::from_sat(10_000),
            script_pubkey: addr.script_pubkey(),
        },
    );
    let inputs = ComposeInputs::builder()
        .instructions(vec![InstructionInputs {
            address: addr.clone(),
            x_only_public_key: xonly,
            funding_utxos: vec![utxo],
            script_data: b"x".to_vec(),
        }])
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .envelope(546)
        .build();
    let commit = compose_commit(CommitInputs::from(inputs)).expect("commit");
    let psbt_hex = commit.commit_psbt_hex;
    eprintln!(
        "commit_psbt_hex_prefix={}...",
        &psbt_hex.get(0..16).unwrap_or("")
    );
    let psbt_bytes = hex::decode(&psbt_hex).expect("hex decode");
    let psbt: bitcoin::psbt::Psbt =
        bitcoin::psbt::Psbt::deserialize(&psbt_bytes).expect("psbt decode");
    assert!(!psbt.inputs.is_empty());
    for inp in psbt.inputs.iter() {
        assert!(inp.witness_utxo.is_some());
        assert!(inp.tap_internal_key.is_some());
    }
}
