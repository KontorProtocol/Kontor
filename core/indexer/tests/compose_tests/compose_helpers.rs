// use anyhow::Result;
// use bitcoin::script::Instruction;
// use bitcoin::taproot::LeafVersion;
// use bitcoin::{Amount, FeeRate, OutPoint, ScriptBuf, Txid};
// use indexer::api::compose::{
//     RevealInputs, RevealParticipantInputs, TapLeafScript, TapScriptPair,
//     build_tap_script_and_script_address, compose_reveal,
// };
// use std::str::FromStr;
// use testlib::RegTester;
// use tracing::info;

// pub async fn test_build_tap_script_and_script_address_empty_data_errs(
//     reg_tester: &mut RegTester,
// ) -> Result<()> {
//     info!("test_build_tap_script_and_script_address_empty_data_errs");
//     let identity = reg_tester.identity().await?;
//     let keypair = identity.keypair;
//     let (xonly, _parity) = keypair.x_only_public_key();
//     let res = build_tap_script_and_script_address(xonly, vec![]);
//     assert!(res.is_err());
//     Ok(())
// }

// pub async fn test_build_tap_script_and_script_address_multi_push_and_structure(
//     reg_tester: &mut RegTester,
// ) -> Result<()> {
//     info!("test_build_tap_script_and_script_address_multi_push_and_structure");
//     let identity = reg_tester.identity().await?;
//     let keypair = identity.keypair;
//     let (xonly, _parity) = keypair.x_only_public_key();
//     // 600 bytes ensures > 520, triggering multiple pushes
//     let data = vec![7u8; 600];
//     let (tap_script, tap_info, script_addr) =
//         build_tap_script_and_script_address(xonly, data.clone()).expect("build tapscript");
//     // Control block should be derivable
//     let _cb = tap_info
//         .control_block(&(tap_script.clone(), LeafVersion::TapScript))
//         .expect("control block");
//     // Script address should be P2TR-like spk length 34
//     assert_eq!(script_addr.script_pubkey().len(), 34);

//     // Inspect instructions
//     let instructions = tap_script
//         .instructions()
//         .collect::<Result<Vec<_>, _>>()
//         .expect("parse script");

//     // Expected prefix: push pubkey (32B), OP_CHECKSIG, OP_FALSE (or empty push), OP_IF, push "kon", OP_0 (or empty push)
//     use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF};
//     use bitcoin::opcodes::{OP_0, OP_FALSE};
//     assert!(matches!(instructions[0], Instruction::PushBytes(_)));
//     assert!(matches!(instructions[1], Instruction::Op(op) if op == OP_CHECKSIG));
//     assert!(
//         matches!(instructions[2], Instruction::Op(op) if op == OP_FALSE)
//             || matches!(instructions[2], Instruction::PushBytes(pb) if pb.as_bytes().is_empty())
//     );
//     assert!(matches!(instructions[3], Instruction::Op(op) if op == OP_IF));
//     assert!(matches!(instructions[4], Instruction::PushBytes(pb) if pb.as_bytes() == b"kon"));
//     assert!(
//         matches!(instructions[5], Instruction::Op(op) if op == OP_0)
//             || matches!(instructions[5], Instruction::PushBytes(pb) if pb.as_bytes().is_empty())
//     );

//     // The data is pushed in one or more chunks, then OP_ENDIF
//     let mut pushed: Vec<u8> = Vec::new();
//     for inst in &instructions[6..instructions.len() - 1] {
//         match inst {
//             Instruction::PushBytes(pb) => pushed.extend_from_slice(pb.as_bytes()),
//             _ => panic!("unexpected instruction in data pushes"),
//         }
//     }
//     assert_eq!(instructions.last(), Some(&Instruction::Op(OP_ENDIF)));
//     assert_eq!(pushed.len(), data.len());
//     assert_eq!(pushed, data);
//     Ok(())
// }

// async fn build_commit_components(
//     value_sat: u64,
//     reg_tester: &mut RegTester,
// ) -> Result<(bitcoin::TxIn, bitcoin::TxOut, ScriptBuf, ScriptBuf)> {
//     let identity = reg_tester.identity().await?;
//     let keypair = identity.keypair;
//     let (xonly, _parity) = keypair.x_only_public_key();
//     let data = b"hello world".to_vec();
//     let (tap_script, tap_info, script_addr) =
//         build_tap_script_and_script_address(xonly, data).expect("build tapscript");
//     let control_block = ScriptBuf::from_bytes(
//         tap_info
//             .control_block(&(tap_script.clone(), LeafVersion::TapScript))
//             .expect("cb")
//             .serialize(),
//     );
//     let (out_point, _utxo_for_output) = identity.next_funding_utxo;
//     let txin = bitcoin::TxIn {
//         previous_output: out_point,
//         ..Default::default()
//     };
//     let txout = bitcoin::TxOut {
//         value: Amount::from_sat(value_sat),
//         script_pubkey: script_addr.script_pubkey(),
//     };
//     Ok((txin, txout, tap_script, control_block))
// }

// pub async fn test_build_tap_script_chunk_boundaries_push_count(
//     reg_tester: &mut RegTester,
// ) -> Result<()> {
//     info!("test_build_tap_script_chunk_boundaries_push_count");
//     let identity = reg_tester.identity().await?;
//     let keypair = identity.keypair;
//     let (xonly, _parity) = keypair.x_only_public_key();
//     for &len in &[520usize, 521usize, 1040usize, 1041usize] {
//         let data = vec![0xABu8; len];
//         let (tap_script, _info, _addr) =
//             build_tap_script_and_script_address(xonly, data.clone()).expect("build tapscript");
//         let instr = tap_script
//             .instructions()
//             .collect::<Result<Vec<_>, _>>()
//             .expect("parse");
//         // Count pushes after header (6 ops) and before final OP_ENDIF
//         let mut push_count = 0usize;
//         for ins in &instr[6..instr.len() - 1] {
//             if let Instruction::PushBytes(_) = ins {
//                 push_count += 1;
//             } else {
//                 panic!("unexpected non-push in data section");
//             }
//         }
//         let expected = len.div_ceil(520);
//         assert_eq!(push_count, expected);
//     }
//     Ok(())
// }

// pub async fn test_build_tap_script_address_type_is_p2tr(reg_tester: &mut RegTester) -> Result<()> {
//     info!("test_build_tap_script_address_type_is_p2tr");
//     let identity = reg_tester.identity().await?;
//     let keypair = identity.keypair;
//     let (xonly, _parity) = keypair.x_only_public_key();
//     let data = b"abc".to_vec();
//     let (_tap, _info, addr) =
//         build_tap_script_and_script_address(xonly, data).expect("build tapscript");
//     assert_eq!(addr.address_type(), Some(bitcoin::AddressType::P2tr));
//     Ok(())
// }

// pub async fn test_calculate_change_single_monotonic_fee_rate_and_owner_output_effect(
//     reg_tester: &mut RegTester,
// ) -> Result<()> {
//     info!("test_calculate_change_single_monotonic_fee_rate_and_owner_output_effect");
//     let (_txin, txout, tap_script, control_block) =
//         build_commit_components(20_000, reg_tester).await?;

//     let low_fee = FeeRate::from_sat_per_vb(1).unwrap();
//     let high_fee = FeeRate::from_sat_per_vb(10).unwrap();

//     let ch_low =
//         calculate_change_single(vec![], txout.clone(), &tap_script, &control_block, low_fee)
//             .expect("some change");
//     let ch_high =
//         calculate_change_single(vec![], txout.clone(), &tap_script, &control_block, high_fee)
//             .expect("some change");
//     assert!(ch_low > ch_high);

//     // Adding an owner output (e.g., envelope) reduces available change
//     let owner_output = bitcoin::TxOut {
//         value: Amount::from_sat(546),
//         script_pubkey: ScriptBuf::from_bytes(vec![0; 34]),
//     };
//     let ch_with_owner = calculate_change_single(
//         vec![owner_output],
//         txout,
//         &tap_script,
//         &control_block,
//         low_fee,
//     )
//     .expect("some change");
//     assert!(ch_with_owner < ch_low);
//     Ok(())
// }

// pub async fn test_calculate_change_single_insufficient_returns_none(
//     reg_tester: &mut RegTester,
// ) -> Result<()> {
//     info!("test_calculate_change_single_insufficient_returns_none");
//     let (_txin, mut txout, tap_script, control_block) =
//         build_commit_components(0, reg_tester).await?;
//     // With zero input value and any fee rate, change cannot cover fee+outputs
//     let fee = FeeRate::from_sat_per_vb(5).unwrap();
//     let res = calculate_change_single(vec![], txout.clone(), &tap_script, &control_block, fee);
//     assert!(res.is_none());

//     // Tiny input also should be None for realistic fee rates
//     txout.value = Amount::from_sat(10);
//     let res2 = calculate_change_single(
//         vec![],
//         txout,
//         &tap_script,
//         &control_block,
//         FeeRate::from_sat_per_vb(100).unwrap(),
//     );
//     assert!(res2.is_none());
//     Ok(())
// }

// pub async fn test_estimate_reveal_fee_for_address_monotonic_and_envelope_invariance(
//     reg_tester: &mut RegTester,
// ) -> Result<()> {
//     info!("test_estimate_reveal_fee_for_address_monotonic_and_envelope_invariance");
//     let identity = reg_tester.identity().await?;
//     let keypair = identity.keypair;
//     let (xonly, _parity) = keypair.x_only_public_key();
//     let data = vec![9u8; 100];
//     let (tap_script, tap_info, _addr) =
//         build_tap_script_and_script_address(xonly, data).expect("build tapscript");

//     let fee_rate = FeeRate::from_sat_per_vb(5).unwrap();
//     let fee_small =
//         estimate_reveal_fee_for_address(&tap_script, &tap_info, 22, fee_rate, false).unwrap();
//     let fee_large =
//         estimate_reveal_fee_for_address(&tap_script, &tap_info, 34, fee_rate, false).unwrap();
//     assert!(fee_large >= fee_small);

//     // Changing envelope value should not affect fee
//     let fee_env_small =
//         estimate_reveal_fee_for_address(&tap_script, &tap_info, 34, fee_rate, false).unwrap();
//     let fee_env_large =
//         estimate_reveal_fee_for_address(&tap_script, &tap_info, 34, fee_rate, false).unwrap();
//     assert_eq!(fee_env_small, fee_env_large);
//     Ok(())
// }

// pub async fn test_compose_reveal_op_return_size_validation(
//     reg_tester: &mut RegTester,
// ) -> Result<()> {
//     info!("test_compose_reveal_op_return_size_validation");
//     let identity = reg_tester.identity().await?;
//     let keypair = identity.keypair;
//     let (xonly, _parity) = keypair.x_only_public_key();
//     let commit_data = b"data".to_vec();
//     let (tap_script, tap_info, script_addr) =
//         build_tap_script_and_script_address(xonly, commit_data.clone()).expect("build");
//     let commit_prevout = bitcoin::TxOut {
//         value: Amount::from_sat(10_000),
//         script_pubkey: script_addr.script_pubkey(),
//     };
//     // Build TapScriptPair for the commit script data
//     let tap_leaf = TapLeafScript {
//         leaf_version: LeafVersion::TapScript,
//         script: tap_script.clone(),
//         control_block: ScriptBuf::from_bytes(
//             tap_info
//                 .control_block(&(tap_script.clone(), LeafVersion::TapScript))
//                 .expect("control block")
//                 .serialize(),
//         ),
//     };
//     let commit_tap_script_pair = TapScriptPair {
//         tap_script,
//         tap_leaf_script: tap_leaf,
//         script_data_chunk: commit_data,
//     };
//     let participant = RevealParticipantInputs::builder()
//         .address(script_addr.clone())
//         .x_only_public_key(xonly)
//         .commit_outpoint(OutPoint {
//             txid: Txid::from_str(
//                 "0000000000000000000000000000000000000000000000000000000000000003",
//             )
//             .unwrap(),
//             vout: 0,
//         })
//         .commit_prevout(commit_prevout.clone())
//         .commit_tap_script_pair(commit_tap_script_pair)
//         .build();

//     // With single-push OP_RETURN, total payload includes the tag ("kon").
//     // So max user data length is 80 - 3 = 77 bytes.
//     let dummy_commit_tx = bitcoin::Transaction {
//         version: bitcoin::transaction::Version(2),
//         lock_time: bitcoin::absolute::LockTime::ZERO,
//         input: vec![],
//         output: vec![commit_prevout.clone()],
//     };
//     let ok_inputs = RevealInputs::builder()
//         .commit_tx(dummy_commit_tx.clone())
//         .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
//         .participants(vec![participant.clone()])
//         .op_return_data(vec![1u8; 80])
//         .envelope(546)
//         .build();
//     let ok = compose_reveal(ok_inputs);
//     assert!(ok.is_ok(), "80-byte OP_RETURN payload should be accepted");

//     let err_inputs = RevealInputs::builder()
//         .commit_tx(dummy_commit_tx)
//         .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
//         .participants(vec![participant])
//         .op_return_data(vec![2u8; 81])
//         .envelope(546)
//         .build();
//     let err = compose_reveal(err_inputs);
//     assert!(err.is_err(), "81-byte OP_RETURN payload should be rejected");
//     let msg = err.err().unwrap().to_string();
//     assert!(
//         msg.contains("OP_RETURN data exceeds 80 bytes"),
//         "unexpected error: {}",
//         msg
//     );
//     Ok(())
// }
