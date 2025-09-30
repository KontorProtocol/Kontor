use bitcoin::FeeRate;
use bitcoin::{Amount, OutPoint, TxOut, Txid};
use indexer::api::compose::{
    CommitInputs, ComposeAddressInputs, ComposeInputs, build_tap_script_and_script_address,
    compose_commit, compose_reveal,
};
use std::str::FromStr;

#[test]
fn test_compose_reveal_psbt_inputs_have_tap_fields() {
    let xonly = bitcoin::secp256k1::XOnlyPublicKey::from_slice(&[2u8; 32]).unwrap();
    let (_tap, _info, addr) =
        build_tap_script_and_script_address(xonly, b"d".to_vec()).expect("build");
    let utxo = (
        OutPoint {
            txid: Txid::from_str(
                "1111111111111111111111111111111111111111111111111111111111111111",
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
        .addresses(vec![ComposeAddressInputs {
            address: addr.clone(),
            x_only_public_key: xonly,
            funding_utxos: vec![utxo],
            script_data: b"d".to_vec(),
        }])
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .envelope(546)
        .build();
    let commit = compose_commit(CommitInputs::from(inputs)).expect("commit");
    let reveal = compose_reveal(commit.reveal_inputs).expect("reveal");
    let psbt = reveal.psbt;
    for inp in psbt.inputs.iter() {
        assert!(inp.witness_utxo.is_some());
        assert!(inp.tap_internal_key.is_some());
        assert!(inp.tap_merkle_root.is_some());
    }
}

#[test]
fn test_compose_reveal_chained_output_and_change_thresholds() {
    let secp = bitcoin::secp256k1::Secp256k1::new();
    let sk = bitcoin::secp256k1::SecretKey::from_slice(&[3u8; 32]).unwrap();
    let kp = bitcoin::secp256k1::Keypair::from_secret_key(&secp, &sk);
    let (xonly, _) = kp.x_only_public_key();
    let (_tap, _info, addr) = build_tap_script_and_script_address(xonly, b"abc".to_vec()).unwrap();
    let utxo = (
        OutPoint {
            txid: Txid::from_str(
                "2222222222222222222222222222222222222222222222222222222222222222",
            )
            .unwrap(),
            vout: 0,
        },
        TxOut {
            value: Amount::from_sat(20_000),
            script_pubkey: addr.script_pubkey(),
        },
    );
    let inputs = ComposeInputs::builder()
        .addresses(vec![ComposeAddressInputs {
            address: addr.clone(),
            x_only_public_key: xonly,
            funding_utxos: vec![utxo],
            script_data: b"abc".to_vec(),
        }])
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .envelope(600)
        .chained_script_data(b"xyz".to_vec())
        .build();
    let commit = compose_commit(CommitInputs::from(inputs)).expect("commit");
    let reveal = compose_reveal(commit.reveal_inputs).expect("reveal");
    // First output is optional OP_RETURN; chained outputs follow
    let outputs = &reveal.transaction.output;
    // Check at least one chained output at exactly envelope value
    assert!(outputs.iter().any(|o| o.value.to_sat() == 600));
}
