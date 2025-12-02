// use anyhow::Result;
// use bitcoin::{Amount, FeeRate, ScriptBuf, Transaction, absolute::LockTime, transaction::Version};
// use indexer::api::compose::estimate_fee_with_dummy_key_witness;

// fn empty_tx() -> Transaction {
//     Transaction {
//         version: Version(2),
//         lock_time: LockTime::ZERO,
//         input: vec![],
//         output: vec![],
//     }
// }

// #[tokio::test]

// async fn test_estimate_commit_delta_fee_monotonic() -> Result<()> {
//     let base = empty_tx();
//     let fr = FeeRate::from_sat_per_vb(5).unwrap();
//     let d1 = {
//         let mut temp = base.clone();
//         temp.input.push(bitcoin::TxIn {
//             ..Default::default()
//         });
//         temp.output.push(bitcoin::TxOut {
//             value: Amount::from_sat(0),
//             script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
//         });
//         temp.output.push(bitcoin::TxOut {
//             value: Amount::from_sat(0),
//             script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
//         });
//         estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
//             - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
//     };
//     let d2 = {
//         let mut temp = base.clone();
//         temp.input.push(bitcoin::TxIn {
//             ..Default::default()
//         });
//         temp.input.push(bitcoin::TxIn {
//             ..Default::default()
//         });
//         temp.output.push(bitcoin::TxOut {
//             value: Amount::from_sat(0),
//             script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
//         });
//         temp.output.push(bitcoin::TxOut {
//             value: Amount::from_sat(0),
//             script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
//         });
//         estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
//             - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
//     };
//     assert!(d2 > d1);

//     let small_spk = {
//         let mut temp = base.clone();
//         temp.input.push(bitcoin::TxIn {
//             ..Default::default()
//         });
//         temp.output.push(bitcoin::TxOut {
//             value: Amount::from_sat(0),
//             script_pubkey: ScriptBuf::from_bytes(vec![0u8; 22]),
//         });
//         temp.output.push(bitcoin::TxOut {
//             value: Amount::from_sat(0),
//             script_pubkey: ScriptBuf::from_bytes(vec![0u8; 22]),
//         });
//         estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
//             - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
//     };
//     let large_spk = {
//         let mut temp = base.clone();
//         temp.input.push(bitcoin::TxIn {
//             ..Default::default()
//         });
//         temp.output.push(bitcoin::TxOut {
//             value: Amount::from_sat(0),
//             script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
//         });
//         temp.output.push(bitcoin::TxOut {
//             value: Amount::from_sat(0),
//             script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
//         });
//         estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
//             - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
//     };
//     assert!(large_spk >= small_spk);

//     let d0 = {
//         let mut temp = base.clone();
//         temp.output.push(bitcoin::TxOut {
//             value: Amount::from_sat(0),
//             script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
//         });
//         temp.output.push(bitcoin::TxOut {
//             value: Amount::from_sat(0),
//             script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
//         });
//         estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
//             - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
//     };
//     assert!(d0 > 0);
//     Ok(())
// }

// #[tokio::test]
// async fn test_estimate_commit_delta_fee_increases_with_each_spk_len_independently() -> Result<()> {
//     let base = empty_tx();
//     let fr = FeeRate::from_sat_per_vb(3).unwrap();
//     // Vary script_spk_len
//     let a = {
//         let mut temp = base.clone();
//         temp.input.push(bitcoin::TxIn {
//             ..Default::default()
//         });
//         temp.output.push(bitcoin::TxOut {
//             value: Amount::from_sat(0),
//             script_pubkey: ScriptBuf::from_bytes(vec![0u8; 22]),
//         });
//         temp.output.push(bitcoin::TxOut {
//             value: Amount::from_sat(0),
//             script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
//         });
//         estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
//             - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
//     };
//     let b = {
//         let mut temp = base.clone();
//         temp.input.push(bitcoin::TxIn {
//             ..Default::default()
//         });
//         temp.output.push(bitcoin::TxOut {
//             value: Amount::from_sat(0),
//             script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
//         });
//         temp.output.push(bitcoin::TxOut {
//             value: Amount::from_sat(0),
//             script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
//         });
//         estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
//             - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
//     };
//     assert!(b >= a);
//     // Vary change_spk_len
//     let c = {
//         let mut temp = base.clone();
//         temp.input.push(bitcoin::TxIn {
//             ..Default::default()
//         });
//         temp.output.push(bitcoin::TxOut {
//             value: Amount::from_sat(0),
//             script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
//         });
//         temp.output.push(bitcoin::TxOut {
//             value: Amount::from_sat(0),
//             script_pubkey: ScriptBuf::from_bytes(vec![0u8; 22]),
//         });
//         estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
//             - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
//     };
//     let d = {
//         let mut temp = base.clone();
//         temp.input.push(bitcoin::TxIn {
//             ..Default::default()
//         });
//         temp.output.push(bitcoin::TxOut {
//             value: Amount::from_sat(0),
//             script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
//         });
//         temp.output.push(bitcoin::TxOut {
//             value: Amount::from_sat(0),
//             script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
//         });
//         estimate_fee_with_dummy_key_witness(&temp, fr).unwrap_or(0)
//             - estimate_fee_with_dummy_key_witness(&base, fr).unwrap_or(0)
//     };
//     assert!(d >= c);
//     Ok(())
// }
