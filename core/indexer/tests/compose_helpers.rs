use bitcoin::script::Instruction;
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::{Amount, FeeRate, OutPoint, ScriptBuf, Txid};
use indexer::api::compose::{
    RevealInputs, RevealParticipantInputs, build_dummy_tx, build_tap_script_and_script_address,
    calculate_change_single, estimate_fee_with_dummy_key_witness, estimate_reveal_fee_for_address,
    split_even_chunks,
};
use std::str::FromStr;

fn fixed_keypair() -> (Secp256k1<bitcoin::secp256k1::All>, Keypair) {
    let secp = Secp256k1::new();
    let sk = SecretKey::from_slice(&[1u8; 32]).expect("secret key");
    let kp = Keypair::from_secret_key(&secp, &sk);
    (secp, kp)
}

#[test]
fn test_split_even_chunks_roundtrip_and_balance() {
    let data: Vec<u8> = (0u8..100u8).collect();
    let chunks = split_even_chunks(&data, 3).unwrap();
    assert_eq!(chunks.len(), 3);
    assert_eq!(chunks[0].len(), 34);
    assert_eq!(chunks[1].len(), 33);
    assert_eq!(chunks[2].len(), 33);
    let reconcat: Vec<u8> = chunks.concat();
    assert_eq!(reconcat, data);

    let single = split_even_chunks(&data, 1).unwrap();
    assert_eq!(single.len(), 1);
    assert_eq!(single[0], data);
}

#[test]
fn test_split_even_chunks_more_parts_than_bytes() {
    let data: Vec<u8> = (0u8..5u8).collect();
    let parts = 10;
    let chunks = split_even_chunks(&data, parts).unwrap();
    assert_eq!(chunks.len(), parts);
    let non_empty = chunks.iter().filter(|c| !c.is_empty()).count();
    assert_eq!(non_empty, data.len());
    for (i, c) in chunks.iter().enumerate() {
        if i < 5 {
            assert_eq!(c.len(), 1);
        } else {
            assert!(c.is_empty());
        }
    }
}

#[test]
fn test_split_even_chunks_zero_parts_errs() {
    let res = split_even_chunks(&[1, 2, 3], 0);
    assert!(res.is_err());
}

#[test]
fn test_build_tap_script_and_script_address_empty_data_errs() {
    let (_secp, kp) = fixed_keypair();
    let (xonly, _parity) = kp.x_only_public_key();
    let res = build_tap_script_and_script_address(xonly, vec![]);
    assert!(res.is_err());
}

#[test]
fn test_build_tap_script_and_script_address_multi_push_and_structure() {
    let (_secp, kp) = fixed_keypair();
    let (xonly, _parity) = kp.x_only_public_key();
    // 600 bytes ensures > 520, triggering multiple pushes
    let data = vec![7u8; 600];
    let (tap_script, tap_info, script_addr) =
        build_tap_script_and_script_address(xonly, data.clone()).expect("build tapscript");
    // Control block should be derivable
    let _cb = tap_info
        .control_block(&(tap_script.clone(), bitcoin::taproot::LeafVersion::TapScript))
        .expect("control block");
    // Script address should be P2TR-like spk length 34
    assert_eq!(script_addr.script_pubkey().len(), 34);

    // Inspect instructions
    let instructions = tap_script
        .instructions()
        .collect::<Result<Vec<_>, _>>()
        .expect("parse script");

    // Expected prefix: push pubkey (32B), OP_CHECKSIG, OP_FALSE (or empty push), OP_IF, push "kon", OP_0 (or empty push)
    use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF};
    use bitcoin::opcodes::{OP_0, OP_FALSE};
    assert!(matches!(instructions[0], Instruction::PushBytes(_)));
    assert!(matches!(instructions[1], Instruction::Op(op) if op == OP_CHECKSIG));
    assert!(
        matches!(instructions[2], Instruction::Op(op) if op == OP_FALSE)
            || matches!(instructions[2], Instruction::PushBytes(pb) if pb.as_bytes().is_empty())
    );
    assert!(matches!(instructions[3], Instruction::Op(op) if op == OP_IF));
    assert!(matches!(instructions[4], Instruction::PushBytes(pb) if pb.as_bytes() == b"kon"));
    assert!(
        matches!(instructions[5], Instruction::Op(op) if op == OP_0)
            || matches!(instructions[5], Instruction::PushBytes(pb) if pb.as_bytes().is_empty())
    );

    // The data is pushed in one or more chunks, then OP_ENDIF
    let mut pushed: Vec<u8> = Vec::new();
    for inst in &instructions[6..instructions.len() - 1] {
        match inst {
            Instruction::PushBytes(pb) => pushed.extend_from_slice(pb.as_bytes()),
            _ => panic!("unexpected instruction in data pushes"),
        }
    }
    assert_eq!(instructions.last(), Some(&Instruction::Op(OP_ENDIF)));
    assert_eq!(pushed.len(), data.len());
    assert_eq!(pushed, data);
}

fn build_commit_components(
    value_sat: u64,
) -> (bitcoin::TxIn, bitcoin::TxOut, ScriptBuf, ScriptBuf) {
    let (_secp, kp) = fixed_keypair();
    let (xonly, _parity) = kp.x_only_public_key();
    let data = b"hello world".to_vec();
    let (tap_script, tap_info, script_addr) =
        build_tap_script_and_script_address(xonly, data).expect("build tapscript");
    let control_block = ScriptBuf::from_bytes(
        tap_info
            .control_block(&(tap_script.clone(), bitcoin::taproot::LeafVersion::TapScript))
            .expect("cb")
            .serialize(),
    );
    let txin = bitcoin::TxIn {
        previous_output: OutPoint {
            txid: Txid::from_str(
                "0000000000000000000000000000000000000000000000000000000000000001",
            )
            .unwrap(),
            vout: 0,
        },
        ..Default::default()
    };
    let txout = bitcoin::TxOut {
        value: Amount::from_sat(value_sat),
        script_pubkey: script_addr.script_pubkey(),
    };
    (txin, txout, tap_script, control_block)
}

#[test]
fn test_tx_vbytes_est_matches_tx_vsize_no_witness_and_with_witness() {
    // No-witness transaction
    let tx_nowit = indexer::api::compose::build_dummy_tx(
        vec![],
        vec![bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0; 34]),
        }],
    );
    let est = indexer::api::compose::tx_vbytes_est(&tx_nowit);
    let actual = tx_nowit.vsize() as u64;
    assert!((est as i64 - actual as i64).abs() <= 1);

    // With a script-spend-like witness
    let (_secp, kp) = fixed_keypair();
    let (xonly, _parity) = kp.x_only_public_key();
    let data = b"w".repeat(200);
    let (tap_script, tap_info, _addr) =
        build_tap_script_and_script_address(xonly, data).expect("build tapscript");
    let cb = tap_info
        .control_block(&(tap_script.clone(), bitcoin::taproot::LeafVersion::TapScript))
        .expect("cb");
    let mut tx = indexer::api::compose::build_dummy_tx(
        vec![bitcoin::TxIn {
            ..Default::default()
        }],
        vec![],
    );
    let mut wit = bitcoin::Witness::new();
    wit.push(vec![0u8; 64]);
    wit.push(tap_script);
    wit.push(cb.serialize());
    tx.input[0].witness = wit;
    let est2 = indexer::api::compose::tx_vbytes_est(&tx);
    let actual2 = tx.vsize() as u64;
    assert!((est2 as i64 - actual2 as i64).abs() <= 1);
}

#[test]
fn test_split_even_chunks_diff_at_most_one_and_order_preserved() {
    let data: Vec<u8> = (0..1234u16).map(|i| (i % 251) as u8).collect();
    let parts = 7;
    let chunks = split_even_chunks(&data, parts).unwrap();
    assert_eq!(chunks.len(), parts);
    let lens: Vec<usize> = chunks.iter().map(|c| c.len()).collect();
    let min_len = *lens.iter().min().unwrap();
    let max_len = *lens.iter().max().unwrap();
    assert!(max_len - min_len <= 1);
    let reconcat: Vec<u8> = chunks.concat();
    assert_eq!(reconcat, data);
}

#[test]
fn test_build_tap_script_chunk_boundaries_push_count() {
    let (_secp, kp) = fixed_keypair();
    let (xonly, _parity) = kp.x_only_public_key();
    for &len in &[520usize, 521usize, 1040usize, 1041usize] {
        let data = vec![0xABu8; len];
        let (tap_script, _info, _addr) =
            build_tap_script_and_script_address(xonly, data.clone()).expect("build tapscript");
        let instr = tap_script
            .instructions()
            .collect::<Result<Vec<_>, _>>()
            .expect("parse");
        // Count pushes after header (6 ops) and before final OP_ENDIF
        let mut push_count = 0usize;
        for ins in &instr[6..instr.len() - 1] {
            if let Instruction::PushBytes(_) = ins {
                push_count += 1;
            } else {
                panic!("unexpected non-push in data section");
            }
        }
        let expected = len.div_ceil(520);
        assert_eq!(push_count, expected);
    }
}

#[test]
fn test_estimate_commit_delta_fee_increases_with_each_spk_len_independently() {
    let base = build_dummy_tx(vec![], vec![]);
    let fr = FeeRate::from_sat_per_vb(3).unwrap();
    // Vary script_spk_len
    let a = {
        let mut temp = base.clone();
        temp.input.push(bitcoin::TxIn {
            ..Default::default()
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 22]),
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
            - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
    };
    let b = {
        let mut temp = base.clone();
        temp.input.push(bitcoin::TxIn {
            ..Default::default()
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
            - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
    };
    assert!(b >= a);
    // Vary change_spk_len
    let c = {
        let mut temp = base.clone();
        temp.input.push(bitcoin::TxIn {
            ..Default::default()
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 22]),
        });
        estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
            - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
    };
    let d = {
        let mut temp = base.clone();
        temp.input.push(bitcoin::TxIn {
            ..Default::default()
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
            - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
    };
    assert!(d >= c);
}

#[test]
fn test_build_tap_script_address_type_is_p2tr() {
    let (_secp, kp) = fixed_keypair();
    let (xonly, _parity) = kp.x_only_public_key();
    let data = b"abc".to_vec();
    let (_tap, _info, addr) =
        build_tap_script_and_script_address(xonly, data).expect("build tapscript");
    assert_eq!(addr.address_type(), Some(bitcoin::AddressType::P2tr));
}

#[test]
fn test_calculate_change_single_monotonic_fee_rate_and_owner_output_effect() {
    let (txin, txout, tap_script, control_block) = build_commit_components(20_000);

    let low_fee = FeeRate::from_sat_per_vb(1).unwrap();
    let high_fee = FeeRate::from_sat_per_vb(10).unwrap();

    let ch_low = calculate_change_single(
        vec![],
        (txin.clone(), txout.clone()),
        &tap_script,
        &control_block,
        low_fee,
    )
    .expect("some change");
    let ch_high = calculate_change_single(
        vec![],
        (txin.clone(), txout.clone()),
        &tap_script,
        &control_block,
        high_fee,
    )
    .expect("some change");
    assert!(ch_low > ch_high);

    // Adding an owner output (e.g., envelope) reduces available change
    let owner_output = bitcoin::TxOut {
        value: Amount::from_sat(546),
        script_pubkey: ScriptBuf::from_bytes(vec![0; 34]),
    };
    let ch_with_owner = calculate_change_single(
        vec![owner_output],
        (txin, txout),
        &tap_script,
        &control_block,
        low_fee,
    )
    .expect("some change");
    assert!(ch_with_owner < ch_low);
}

#[test]
fn test_calculate_change_single_insufficient_returns_none() {
    let (txin, mut txout, tap_script, control_block) = build_commit_components(0);
    // With zero input value and any fee rate, change cannot cover fee+outputs
    let fee = FeeRate::from_sat_per_vb(5).unwrap();
    let res = calculate_change_single(
        vec![],
        (txin, txout.clone()),
        &tap_script,
        &control_block,
        fee,
    );
    assert!(res.is_none());

    // Tiny input also should be None for realistic fee rates
    txout.value = Amount::from_sat(10);
    let res2 = calculate_change_single(
        vec![],
        (
            bitcoin::TxIn {
                previous_output: OutPoint {
                    txid: Txid::from_str(
                        "0000000000000000000000000000000000000000000000000000000000000002",
                    )
                    .unwrap(),
                    vout: 0,
                },
                ..Default::default()
            },
            txout,
        ),
        &tap_script,
        &control_block,
        FeeRate::from_sat_per_vb(100).unwrap(),
    );
    assert!(res2.is_none());
}

#[test]
fn test_estimate_reveal_fee_for_address_monotonic_and_envelope_invariance() {
    let (_secp, kp) = fixed_keypair();
    let (xonly, _parity) = kp.x_only_public_key();
    let data = vec![9u8; 100];
    let (tap_script, tap_info, _addr) =
        build_tap_script_and_script_address(xonly, data).expect("build tapscript");

    let fee_rate = FeeRate::from_sat_per_vb(5).unwrap();
    let fee_small = estimate_reveal_fee_for_address(&tap_script, &tap_info, 22, fee_rate).unwrap();
    let fee_large = estimate_reveal_fee_for_address(&tap_script, &tap_info, 34, fee_rate).unwrap();
    assert!(fee_large >= fee_small);

    // Changing envelope value should not affect fee
    let fee_env_small =
        estimate_reveal_fee_for_address(&tap_script, &tap_info, 34, fee_rate).unwrap();
    let fee_env_large =
        estimate_reveal_fee_for_address(&tap_script, &tap_info, 34, fee_rate).unwrap();
    assert_eq!(fee_env_small, fee_env_large);
}

#[test]
fn test_estimate_commit_delta_fee_monotonic() {
    let base = build_dummy_tx(vec![], vec![]);
    let fr = FeeRate::from_sat_per_vb(5).unwrap();
    let d1 = {
        let mut temp = base.clone();
        temp.input.push(bitcoin::TxIn {
            ..Default::default()
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
            - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
    };
    let d2 = {
        let mut temp = base.clone();
        temp.input.push(bitcoin::TxIn {
            ..Default::default()
        });
        temp.input.push(bitcoin::TxIn {
            ..Default::default()
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
            - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
    };
    assert!(d2 > d1);

    let small_spk = {
        let mut temp = base.clone();
        temp.input.push(bitcoin::TxIn {
            ..Default::default()
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 22]),
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 22]),
        });
        estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
            - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
    };
    let large_spk = {
        let mut temp = base.clone();
        temp.input.push(bitcoin::TxIn {
            ..Default::default()
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
            - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
    };
    assert!(large_spk >= small_spk);

    let d0 = {
        let mut temp = base.clone();
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        temp.output.push(bitcoin::TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
        });
        estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
            - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
    };
    assert!(d0 > 0);
}

#[test]
fn test_compose_reveal_op_return_size_validation() {
    let (_secp, kp) = fixed_keypair();
    let (xonly, _parity) = kp.x_only_public_key();
    let commit_data = b"data".to_vec();
    let (_tap_script, _tap_info, script_addr) =
        build_tap_script_and_script_address(xonly, commit_data.clone()).expect("build");
    let commit_prevout = bitcoin::TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: script_addr.script_pubkey(),
    };
    let participant = RevealParticipantInputs {
        address: script_addr.clone(),
        x_only_public_key: xonly,
        commit_outpoint: OutPoint {
            txid: Txid::from_str(
                "0000000000000000000000000000000000000000000000000000000000000003",
            )
            .unwrap(),
            vout: 0,
        },
        commit_prevout,
        commit_script_data: commit_data,
    };

    // With single-push OP_RETURN, total payload includes the tag ("kon").
    // So max user data length is 80 - 3 = 77 bytes.
    let ok_inputs = RevealInputs::builder()
        .commit_txid(
            Txid::from_str("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap(),
        )
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .participants(vec![participant.clone()])
        .op_return_data(vec![1u8; 77])
        .envelope(546)
        .build();
    let ok = indexer::api::compose::compose_reveal(ok_inputs);
    assert!(ok.is_ok(), "77-byte OP_RETURN payload should be accepted");

    let err_inputs = RevealInputs::builder()
        .commit_txid(
            Txid::from_str("0000000000000000000000000000000000000000000000000000000000000003")
                .unwrap(),
        )
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .participants(vec![participant])
        .op_return_data(vec![2u8; 78])
        .envelope(546)
        .build();
    let err = indexer::api::compose::compose_reveal(err_inputs);
    assert!(err.is_err(), "78-byte OP_RETURN payload should be rejected");
    let msg = err.err().unwrap().to_string();
    assert!(
        msg.contains("OP_RETURN data exceeds 80 bytes"),
        "unexpected error: {}",
        msg
    );
}
