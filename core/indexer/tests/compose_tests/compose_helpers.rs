use anyhow::Result;
use bitcoin::absolute::LockTime;
use bitcoin::script::Instruction;
use bitcoin::taproot::LeafVersion;
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{Amount, FeeRate, OutPoint, ScriptBuf, Txid};
use indexer::api::compose::{
    RevealInputs, RevealParticipantInputs, TapLeafScript, build_tap_script_and_script_address,
    calculate_op_return_fee_per_participant, calculate_reveal_fee_delta, compose_reveal,
    estimate_key_spend_fee, estimate_participant_commit_fees, select_utxos_for_commit,
};
use std::str::FromStr;
use testlib::RegTester;
use tracing::info;

// // ============================================================================
// // estimate_reveal_fees_delta tests
// // ============================================================================

// /// Helper to create a RevealFeeEstimateInput with a dummy tap script of given size.
// fn make_reveal_fee_input(script_size: usize, has_chained: bool) -> RevealFeeEstimateInput {
//     // Create a dummy script of the specified size
//     let tap_script = ScriptBuf::from_bytes(vec![0u8; script_size]);
//     // Control block is typically 33 bytes (1 byte leaf version + 32 bytes internal key)
//     let control_block_bytes = vec![0u8; 33];
//     RevealFeeEstimateInput {
//         tap_script,
//         control_block_bytes,
//         has_chained,
//     }
// }

// /// Helper to create a RevealFeeEstimateInput with realistic tap script from actual data.
// fn make_realistic_reveal_fee_input(
//     xonly: bitcoin::secp256k1::XOnlyPublicKey,
//     data: Vec<u8>,
//     has_chained: bool,
// ) -> RevealFeeEstimateInput {
//     let (tap_script, _, _, control_block) =
//         build_tap_script_and_script_address(xonly, data).expect("build tapscript");
//     RevealFeeEstimateInput {
//         tap_script,
//         control_block_bytes: control_block.serialize(),
//         has_chained,
//     }
// }

// pub fn test_estimate_reveal_fees_delta_empty_participants_returns_empty() {
//     let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
//     let result = estimate_reveal_fees_delta(&[], fee_rate, false, 330).unwrap();
//     assert!(
//         result.is_empty(),
//         "Empty participants should return empty fees"
//     );
// }

// pub fn test_estimate_reveal_fees_delta_single_participant_returns_single_fee() {
//     let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
//     let input = make_reveal_fee_input(100, false);
//     let result = estimate_reveal_fees_delta(&[input], fee_rate, false, 330).unwrap();

//     assert_eq!(
//         result.len(),
//         1,
//         "Single participant should return single fee"
//     );
//     assert!(result[0] > 0, "Fee should be non-zero");
// }

// pub fn test_estimate_reveal_fees_delta_fee_rate_scaling() {
//     // Double fee rate should approximately double the fees
//     let input = make_reveal_fee_input(100, false);

//     let fee_rate_1 = FeeRate::from_sat_per_vb(5).unwrap();
//     let fee_rate_2 = FeeRate::from_sat_per_vb(10).unwrap();

//     let fees_1 =
//         estimate_reveal_fees_delta(std::slice::from_ref(&input), fee_rate_1, false, 330).unwrap();
//     let fees_2 = estimate_reveal_fees_delta(&[input], fee_rate_2, false, 330).unwrap();

//     // Fee at 10 sat/vb should be exactly 2x fee at 5 sat/vb
//     assert_eq!(
//         fees_2[0],
//         fees_1[0] * 2,
//         "Doubling fee rate should double the fee"
//     );
// }

// pub fn test_estimate_reveal_fees_delta_larger_script_higher_fee() {
//     let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

//     let small_script = make_reveal_fee_input(50, false);
//     let large_script = make_reveal_fee_input(500, false);

//     let small_fees = estimate_reveal_fees_delta(&[small_script], fee_rate, false, 330).unwrap();
//     let large_fees = estimate_reveal_fees_delta(&[large_script], fee_rate, false, 330).unwrap();

//     assert!(
//         large_fees[0] > small_fees[0],
//         "Larger script should cost more: {} vs {}",
//         large_fees[0],
//         small_fees[0]
//     );
// }

// pub fn test_estimate_reveal_fees_delta_chained_adds_output_fee() {
//     let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

//     let without_chained = make_reveal_fee_input(100, false);
//     let with_chained = make_reveal_fee_input(100, true);

//     let fees_without =
//         estimate_reveal_fees_delta(&[without_chained], fee_rate, false, 330).unwrap();
//     let fees_with = estimate_reveal_fees_delta(&[with_chained], fee_rate, false, 330).unwrap();

//     assert!(
//         fees_with[0] > fees_without[0],
//         "Chained output should increase fee: {} vs {}",
//         fees_with[0],
//         fees_without[0]
//     );

//     // A P2TR output is 34 bytes, at 10 sat/vb that's 340 sats difference
//     let difference = fees_with[0] - fees_without[0];
//     assert!(
//         difference >= 340,
//         "Chained output should add at least 34 vbytes worth: diff={}",
//         difference
//     );
// }

// pub fn test_estimate_reveal_fees_delta_op_return_is_base_overhead() {
//     // NOTE: The OP_RETURN is added to the dummy tx BEFORE measuring any participant's delta.
//     // This means it's part of the base transaction overhead and NOT charged to any specific
//     // participant in the per-participant fees. This is important to understand when using
//     // this function - the OP_RETURN cost needs to be accounted for separately if needed.
//     let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
//     let input = make_reveal_fee_input(100, false);

//     let fees_without_op_return =
//         estimate_reveal_fees_delta(std::slice::from_ref(&input), fee_rate, false, 330).unwrap();
//     let fees_with_op_return = estimate_reveal_fees_delta(&[input], fee_rate, true, 330).unwrap();

//     // Per-participant fees should be the same - OP_RETURN is base overhead
//     assert_eq!(
//         fees_with_op_return[0], fees_without_op_return[0],
//         "OP_RETURN is base overhead, not charged to participant: {} vs {}",
//         fees_with_op_return[0], fees_without_op_return[0]
//     );
// }

// pub fn test_estimate_reveal_fees_delta_op_return_not_in_participant_fees() {
//     // The OP_RETURN overhead is NOT included in any participant's fee.
//     // It's added before vsize_before is measured for the first participant.
//     let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
//     let input1 = make_reveal_fee_input(100, false);
//     let input2 = make_reveal_fee_input(100, false);

//     // Without OP_RETURN
//     let fees_no_op =
//         estimate_reveal_fees_delta(&[input1.clone(), input2.clone()], fee_rate, false, 330)
//             .unwrap();

//     // With OP_RETURN
//     let fees_with_op = estimate_reveal_fees_delta(&[input1, input2], fee_rate, true, 330).unwrap();

//     // Both participants' fees should be the same regardless of OP_RETURN
//     // because OP_RETURN is measured as part of "base" before any participant delta
//     assert_eq!(
//         fees_with_op[0], fees_no_op[0],
//         "First participant fee should be same: {} vs {}",
//         fees_with_op[0], fees_no_op[0]
//     );
//     assert_eq!(
//         fees_with_op[1], fees_no_op[1],
//         "Second participant fee should be same: {} vs {}",
//         fees_with_op[1], fees_no_op[1]
//     );
// }

// pub fn test_estimate_reveal_fees_delta_multiple_participants_independent_deltas() {
//     let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

//     // Different sized scripts
//     let small = make_reveal_fee_input(50, false);
//     let medium = make_reveal_fee_input(200, false);
//     let large = make_reveal_fee_input(500, false);

//     let fees = estimate_reveal_fees_delta(&[small, medium, large], fee_rate, false, 330).unwrap();

//     assert_eq!(fees.len(), 3);

//     // Each participant pays for their own contribution
//     // Since scripts are different sizes, fees should be different
//     // Note: fees[0] includes base tx overhead, so it's higher than if we measured just the script
//     assert!(fees[0] > 0);
//     assert!(fees[1] > 0);
//     assert!(fees[2] > 0);

//     // Larger scripts should result in higher fees (but first includes base overhead)
//     // Compare 2nd and 3rd which don't have base overhead
//     assert!(
//         fees[2] > fees[1],
//         "Larger script participant should pay more: {} vs {}",
//         fees[2],
//         fees[1]
//     );
// }

// pub fn test_estimate_reveal_fees_delta_deterministic() {
//     let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
//     let inputs = vec![
//         make_reveal_fee_input(100, false),
//         make_reveal_fee_input(200, true),
//         make_reveal_fee_input(150, false),
//     ];

//     let fees1 = estimate_reveal_fees_delta(&inputs, fee_rate, true, 330).unwrap();
//     let fees2 = estimate_reveal_fees_delta(&inputs, fee_rate, true, 330).unwrap();

//     assert_eq!(fees1, fees2, "Same inputs should produce same outputs");
// }

// pub fn test_estimate_reveal_fees_delta_envelope_value_does_not_affect_fee() {
//     // The envelope value is used for output values in the dummy tx, but shouldn't affect vsize
//     let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
//     let input = make_reveal_fee_input(100, false);

//     let fees_small_envelope =
//         estimate_reveal_fees_delta(std::slice::from_ref(&input), fee_rate, false, 330).unwrap();
//     let fees_large_envelope =
//         estimate_reveal_fees_delta(&[input], fee_rate, false, 100_000).unwrap();

//     assert_eq!(
//         fees_small_envelope[0], fees_large_envelope[0],
//         "Envelope value should not affect fee calculation"
//     );
// }

// pub fn test_estimate_reveal_fees_delta_minimum_fee_rate() {
//     // Test with minimum practical fee rate (1 sat/vb)
//     let fee_rate = FeeRate::from_sat_per_vb(1).unwrap();
//     let input = make_reveal_fee_input(100, false);

//     let fees = estimate_reveal_fees_delta(&[input], fee_rate, false, 330).unwrap();

//     assert!(fees[0] > 0, "Even at 1 sat/vb, fee should be non-zero");
// }

// pub fn test_estimate_reveal_fees_delta_high_fee_rate() {
//     // Test with high fee rate (100 sat/vb)
//     let fee_rate = FeeRate::from_sat_per_vb(100).unwrap();
//     let input = make_reveal_fee_input(100, false);

//     let fees = estimate_reveal_fees_delta(&[input], fee_rate, false, 330).unwrap();

//     // At 100 sat/vb, even a small input should cost thousands of sats
//     assert!(
//         fees[0] > 1000,
//         "High fee rate should result in high fees: {}",
//         fees[0]
//     );
// }

// pub fn test_estimate_reveal_fees_delta_mixed_chained_participants() {
//     let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

//     let no_chain = make_reveal_fee_input(100, false);
//     let with_chain = make_reveal_fee_input(100, true);

//     let fees = estimate_reveal_fees_delta(
//         &[no_chain.clone(), with_chain.clone()],
//         fee_rate,
//         false,
//         330,
//     )
//     .unwrap();

//     // The chained participant should pay more
//     assert!(
//         fees[1] > fees[0],
//         "Chained participant should pay more: {} vs {}",
//         fees[1],
//         fees[0]
//     );

//     // Reversing order should swap which participant pays more
//     let fees_reversed =
//         estimate_reveal_fees_delta(&[with_chain, no_chain], fee_rate, false, 330).unwrap();

//     assert!(
//         fees_reversed[0] > fees_reversed[1],
//         "First (chained) should pay more than second: {} vs {}",
//         fees_reversed[0],
//         fees_reversed[1]
//     );
// }

// pub fn test_estimate_reveal_fees_delta_very_large_script() {
//     // Test with a large script (close to max)
//     let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
//     let large_input = make_reveal_fee_input(10_000, false); // 10KB script

//     let fees = estimate_reveal_fees_delta(&[large_input], fee_rate, false, 330).unwrap();

//     // 10KB script should cost significant fees
//     // Witness data is discounted (1/4 weight), so ~2500 vbytes for 10KB
//     // At 10 sat/vb, that's ~25,000 sats minimum
//     assert!(
//         fees[0] > 20_000,
//         "Large script should have high fee: {}",
//         fees[0]
//     );
// }

// pub fn test_estimate_reveal_fees_delta_many_participants() {
//     let fee_rate = FeeRate::from_sat_per_vb(5).unwrap();

//     // 10 participants with varying script sizes
//     let inputs: Vec<RevealFeeEstimateInput> = (0..10)
//         .map(|i| make_reveal_fee_input(50 + i * 50, i % 2 == 0))
//         .collect();

//     let fees = estimate_reveal_fees_delta(&inputs, fee_rate, false, 330).unwrap();

//     assert_eq!(fees.len(), 10, "Should have fee for each participant");

//     // All fees should be non-zero
//     for (i, fee) in fees.iter().enumerate() {
//         assert!(*fee > 0, "Participant {} fee should be non-zero", i);
//     }

//     // Total fees should be reasonable (sum of individual contributions)
//     let total: u64 = fees.iter().sum();
//     assert!(
//         total > fees[0],
//         "Total fees should be more than first participant alone"
//     );
// }

// pub fn test_estimate_reveal_fees_delta_control_block_size_matters() {
//     let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

//     // Same tap script but different control block sizes
//     let tap_script = ScriptBuf::from_bytes(vec![0u8; 100]);

//     let small_cb = RevealFeeEstimateInput {
//         tap_script: tap_script.clone(),
//         control_block_bytes: vec![0u8; 33], // Minimal control block
//         has_chained: false,
//     };

//     let large_cb = RevealFeeEstimateInput {
//         tap_script,
//         control_block_bytes: vec![0u8; 65], // Larger control block (deeper tree)
//         has_chained: false,
//     };

//     let fees_small = estimate_reveal_fees_delta(&[small_cb], fee_rate, false, 330).unwrap();
//     let fees_large = estimate_reveal_fees_delta(&[large_cb], fee_rate, false, 330).unwrap();

//     assert!(
//         fees_large[0] > fees_small[0],
//         "Larger control block should cost more: {} vs {}",
//         fees_large[0],
//         fees_small[0]
//     );
// }

// /// Test with realistic tap scripts built from actual data
// pub async fn test_estimate_reveal_fees_delta_with_realistic_scripts(
//     reg_tester: &mut RegTester,
// ) -> Result<()> {
//     info!("test_estimate_reveal_fees_delta_with_realistic_scripts");
//     let identity = reg_tester.identity().await?;
//     let keypair = identity.keypair;
//     let (xonly, _parity) = keypair.x_only_public_key();

//     let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

//     // Create realistic inputs with actual tap scripts
//     let small_data = b"small".to_vec();
//     let large_data = vec![0xABu8; 1000]; // 1KB data

//     let small_input = make_realistic_reveal_fee_input(xonly, small_data, false);
//     let large_input = make_realistic_reveal_fee_input(xonly, large_data, true);

//     let fees = estimate_reveal_fees_delta(&[small_input, large_input], fee_rate, false, 330)?;

//     assert_eq!(fees.len(), 2);
//     assert!(fees[0] > 0);
//     assert!(fees[1] > 0);

//     // Large input with chained should cost significantly more
//     assert!(
//         fees[1] > fees[0],
//         "Large chained input should cost more: {} vs {}",
//         fees[1],
//         fees[0]
//     );

//     Ok(())
// }

// ============================================================================
// estimate_key_spend_fee tests
// ============================================================================

/// Helper to create a basic transaction with given number of inputs and outputs.
fn make_tx_with_inputs_outputs(num_inputs: usize, num_outputs: usize) -> Transaction {
    let inputs: Vec<TxIn> = (0..num_inputs)
        .map(|i| TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(
                    "0000000000000000000000000000000000000000000000000000000000000001",
                )
                .unwrap(),
                vout: i as u32,
            },
            ..Default::default()
        })
        .collect();

    let outputs: Vec<TxOut> = (0..num_outputs)
        .map(|_| TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]), // P2TR output size
        })
        .collect();

    Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

pub fn test_estimate_key_spend_fee_empty_tx() {
    // Transaction with no inputs - should still return a fee for base tx structure
    let tx = make_tx_with_inputs_outputs(0, 1);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let fee = estimate_key_spend_fee(&tx, fee_rate);

    assert!(fee.is_some(), "Should return fee even for empty input tx");
    // Base tx overhead is ~10-11 vbytes (version + locktime + input/output counts)
    // Plus 1 output at 34 bytes = ~44-45 vbytes total
    // At 10 sat/vb = ~440-450 sats
    let fee_val = fee.unwrap();
    assert!(
        fee_val > 0 && fee_val < 1000,
        "Fee for empty input tx should be reasonable: {}",
        fee_val
    );
}

pub fn test_estimate_key_spend_fee_single_input() {
    let tx = make_tx_with_inputs_outputs(1, 1);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let fee = estimate_key_spend_fee(&tx, fee_rate);

    assert!(fee.is_some(), "Should return fee");
    let fee_val = fee.unwrap();
    // 1 input with 64-byte signature witness adds significant weight
    // Input: ~41 bytes non-witness + 64 bytes witness (discounted)
    // Total ~57 vbytes per input + base + output
    assert!(
        fee_val > 500,
        "Single input tx fee should be > 500 sats at 10 sat/vb: {}",
        fee_val
    );
}

pub fn test_estimate_key_spend_fee_multiple_inputs_scales_linearly() {
    let tx_1 = make_tx_with_inputs_outputs(1, 1);
    let tx_2 = make_tx_with_inputs_outputs(2, 1);
    let tx_3 = make_tx_with_inputs_outputs(3, 1);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let fee_1 = estimate_key_spend_fee(&tx_1, fee_rate).unwrap();
    let fee_2 = estimate_key_spend_fee(&tx_2, fee_rate).unwrap();
    let fee_3 = estimate_key_spend_fee(&tx_3, fee_rate).unwrap();

    // Each additional input should add roughly the same amount
    let delta_1_to_2 = fee_2 - fee_1;
    let delta_2_to_3 = fee_3 - fee_2;

    // Deltas should be similar (within 10% of each other)
    let diff = delta_1_to_2.abs_diff(delta_2_to_3);
    assert!(
        diff <= delta_1_to_2 / 10 + 1,
        "Input fee deltas should be consistent: {} vs {}",
        delta_1_to_2,
        delta_2_to_3
    );
}

pub fn test_estimate_key_spend_fee_fee_rate_scaling() {
    let tx = make_tx_with_inputs_outputs(1, 1);

    let fee_rate_5 = FeeRate::from_sat_per_vb(5).unwrap();
    let fee_rate_10 = FeeRate::from_sat_per_vb(10).unwrap();

    let fee_5 = estimate_key_spend_fee(&tx, fee_rate_5).unwrap();
    let fee_10 = estimate_key_spend_fee(&tx, fee_rate_10).unwrap();

    // Double fee rate should exactly double the fee
    assert_eq!(
        fee_10,
        fee_5 * 2,
        "Double fee rate should double the fee: {} vs {}",
        fee_10,
        fee_5 * 2
    );
}

pub fn test_estimate_key_spend_fee_more_outputs_higher_fee() {
    let tx_1_out = make_tx_with_inputs_outputs(1, 1);
    let tx_3_out = make_tx_with_inputs_outputs(1, 3);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let fee_1 = estimate_key_spend_fee(&tx_1_out, fee_rate).unwrap();
    let fee_3 = estimate_key_spend_fee(&tx_3_out, fee_rate).unwrap();

    assert!(
        fee_3 > fee_1,
        "More outputs should cost more: {} vs {}",
        fee_3,
        fee_1
    );

    // Each output is ~43 bytes (8 value + 1 varint + 34 script_pubkey) = 430 sats at 10 sat/vb
    // 2 additional outputs = ~860 sats difference
    let diff = fee_3 - fee_1;
    assert!(
        (800..=950).contains(&diff),
        "2 additional outputs should add ~860 sats: got {}",
        diff
    );
}

pub fn test_estimate_key_spend_fee_deterministic() {
    let tx = make_tx_with_inputs_outputs(2, 2);
    let fee_rate = FeeRate::from_sat_per_vb(7).unwrap();

    let fee_1 = estimate_key_spend_fee(&tx, fee_rate);
    let fee_2 = estimate_key_spend_fee(&tx, fee_rate);

    assert_eq!(fee_1, fee_2, "Same inputs should produce same outputs");
}

pub fn test_estimate_key_spend_fee_overwrites_existing_witness() {
    // Create tx with pre-existing witness data (should be overwritten)
    let mut tx = make_tx_with_inputs_outputs(1, 1);

    // Add some arbitrary witness data
    let mut existing_witness = bitcoin::Witness::new();
    existing_witness.push(vec![0xAB; 100]); // 100 bytes of junk
    existing_witness.push(vec![0xCD; 200]); // 200 more bytes
    tx.input[0].witness = existing_witness;

    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    // Create a fresh tx without witness
    let fresh_tx = make_tx_with_inputs_outputs(1, 1);

    let fee_with_existing = estimate_key_spend_fee(&tx, fee_rate).unwrap();
    let fee_fresh = estimate_key_spend_fee(&fresh_tx, fee_rate).unwrap();

    // Both should produce the same fee because existing witness is overwritten
    assert_eq!(
        fee_with_existing, fee_fresh,
        "Existing witness should be overwritten: {} vs {}",
        fee_with_existing, fee_fresh
    );
}

pub fn test_estimate_key_spend_fee_does_not_modify_original_tx() {
    let tx = make_tx_with_inputs_outputs(2, 1);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    // Clone to compare later
    let tx_before = tx.clone();

    let _fee = estimate_key_spend_fee(&tx, fee_rate);

    // Original tx should be unchanged
    assert_eq!(
        tx.input.len(),
        tx_before.input.len(),
        "Original tx inputs should be unchanged"
    );
    for (i, (inp, inp_before)) in tx.input.iter().zip(tx_before.input.iter()).enumerate() {
        assert_eq!(
            inp.witness.len(),
            inp_before.witness.len(),
            "Input {} witness should be unchanged",
            i
        );
    }
}

pub fn test_estimate_key_spend_fee_minimum_fee_rate() {
    let tx = make_tx_with_inputs_outputs(1, 1);
    let fee_rate = FeeRate::from_sat_per_vb(1).unwrap();

    let fee = estimate_key_spend_fee(&tx, fee_rate).unwrap();

    assert!(fee > 0, "Even at 1 sat/vb, fee should be non-zero: {}", fee);
}

pub fn test_estimate_key_spend_fee_high_fee_rate() {
    let tx = make_tx_with_inputs_outputs(1, 1);
    let fee_rate = FeeRate::from_sat_per_vb(500).unwrap();

    let fee = estimate_key_spend_fee(&tx, fee_rate).unwrap();

    // At 500 sat/vb, even a small tx should cost tens of thousands of sats
    assert!(
        fee > 30_000,
        "High fee rate should result in high fee: {}",
        fee
    );
}

pub fn test_estimate_key_spend_fee_many_inputs() {
    // Test with many inputs (like a consolidation tx)
    let tx = make_tx_with_inputs_outputs(20, 1);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let fee = estimate_key_spend_fee(&tx, fee_rate).unwrap();

    // 20 inputs at ~57 vbytes each = ~1140 vbytes of inputs
    // Plus base + output = ~1200 vbytes
    // At 10 sat/vb = ~12,000 sats
    assert!(
        fee > 10_000 && fee < 15_000,
        "20 input tx fee should be ~12000 sats: {}",
        fee
    );
}

pub fn test_estimate_key_spend_fee_signature_size_is_64_bytes() {
    // Verify the function uses 64-byte signatures (no sighash byte appended)
    // by comparing against known vsize calculations
    let tx = make_tx_with_inputs_outputs(1, 0);
    let fee_rate = FeeRate::from_sat_per_vb(1).unwrap();

    let fee = estimate_key_spend_fee(&tx, fee_rate).unwrap();

    // With 1 input, no outputs:
    // Base: 4 (version) + 4 (locktime) + 1 (input count) + 1 (output count) = 10 bytes
    // Input non-witness: 32 (txid) + 4 (vout) + 1 (script len) + 4 (sequence) = 41 bytes
    // Witness: 1 (item count) + 1 (sig len) + 64 (sig) = 66 bytes
    // Weight = (10 + 41) * 4 + 66 = 204 + 66 = 270
    // vsize = ceil(270 / 4) = 68 vbytes
    // Fee at 1 sat/vb = 68 sats
    assert!(
        (65..=75).contains(&fee),
        "Single input no output vsize should be ~68: fee={}",
        fee
    );
}

pub async fn test_estimate_key_spend_fee_with_real_commit_tx(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_estimate_key_spend_fee_with_real_commit_tx");

    let identity = reg_tester.identity().await?;
    let (outpoint, prevout) = identity.next_funding_utxo;

    // Build a realistic commit-like transaction
    let tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: outpoint,
            ..Default::default()
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: identity.address.script_pubkey(),
            },
            TxOut {
                value: prevout.value - Amount::from_sat(1500), // Rest as change
                script_pubkey: identity.address.script_pubkey(),
            },
        ],
    };

    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let fee = estimate_key_spend_fee(&tx, fee_rate);

    assert!(fee.is_some(), "Should estimate fee for realistic tx");
    let fee_val = fee.unwrap();

    // 1 input, 2 outputs transaction
    // ~57 vbytes for input + ~10 base + ~68 for outputs = ~135 vbytes
    // At 10 sat/vb = ~1350 sats
    assert!(
        fee_val > 1000 && fee_val < 2000,
        "Realistic tx fee should be ~1350 sats: {}",
        fee_val
    );

    Ok(())
}

pub async fn test_build_tap_script_and_script_address_empty_data_errs(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_build_tap_script_and_script_address_empty_data_errs");
    let identity = reg_tester.identity().await?;
    let keypair = identity.keypair;
    let (xonly, _parity) = keypair.x_only_public_key();
    let res = build_tap_script_and_script_address(xonly, vec![]);
    assert!(res.is_err());
    Ok(())
}

pub async fn test_build_tap_script_and_script_address_multi_push_and_structure(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_build_tap_script_and_script_address_multi_push_and_structure");
    let identity = reg_tester.identity().await?;
    let keypair = identity.keypair;
    let (xonly, _parity) = keypair.x_only_public_key();
    // 600 bytes ensures > 520, triggering multiple pushes
    let data = vec![7u8; 600];
    let (tap_script, script_addr, control_block) =
        build_tap_script_and_script_address(xonly, data.clone()).expect("build tapscript");
    // Control block should have been returned and be valid
    assert!(
        !control_block.serialize().is_empty(),
        "Control block should be non-empty"
    );
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
    Ok(())
}

pub async fn test_build_tap_script_chunk_boundaries_push_count(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_build_tap_script_chunk_boundaries_push_count");
    let identity = reg_tester.identity().await?;
    let keypair = identity.keypair;
    let (xonly, _parity) = keypair.x_only_public_key();
    for &len in &[520usize, 521usize, 1040usize, 1041usize] {
        let data = vec![0xABu8; len];
        let (tap_script, _addr, _control_block) =
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
    Ok(())
}

pub async fn test_build_tap_script_address_type_is_p2tr(reg_tester: &mut RegTester) -> Result<()> {
    info!("test_build_tap_script_address_type_is_p2tr");
    let identity = reg_tester.identity().await?;
    let keypair = identity.keypair;
    let (xonly, _parity) = keypair.x_only_public_key();
    let data = b"abc".to_vec();
    let (_tap, addr, _control_block) =
        build_tap_script_and_script_address(xonly, data).expect("build tapscript");
    assert_eq!(addr.address_type(), Some(bitcoin::AddressType::P2tr));
    Ok(())
}

pub async fn test_compose_reveal_op_return_size_validation(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_compose_reveal_op_return_size_validation");
    let identity = reg_tester.identity().await?;
    let keypair = identity.keypair;
    let (xonly, _parity) = keypair.x_only_public_key();
    let commit_data = b"data".to_vec();
    let (tap_script, script_addr, control_block) =
        build_tap_script_and_script_address(xonly, commit_data.clone()).expect("build");
    let commit_prevout = bitcoin::TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: script_addr.script_pubkey(),
    };

    let participant = RevealParticipantInputs::builder()
        .address(script_addr.clone())
        .x_only_public_key(xonly)
        .commit_outpoint(OutPoint {
            txid: Txid::from_str(
                "0000000000000000000000000000000000000000000000000000000000000003",
            )
            .unwrap(),
            vout: 0,
        })
        .commit_prevout(commit_prevout.clone())
        .commit_tap_leaf_script(TapLeafScript {
            leaf_version: LeafVersion::TapScript,
            script: tap_script,
            control_block: ScriptBuf::from_bytes(control_block.serialize()),
        })
        .build();

    // With single-push OP_RETURN, total payload includes the tag ("kon").
    // So max user data length is 80 - 3 = 77 bytes.
    let dummy_commit_tx = bitcoin::Transaction {
        version: bitcoin::transaction::Version(2),
        lock_time: bitcoin::absolute::LockTime::ZERO,
        input: vec![],
        output: vec![commit_prevout.clone()],
    };
    let ok_inputs = RevealInputs::builder()
        .commit_tx(dummy_commit_tx.clone())
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .participants(vec![participant.clone()])
        .op_return_data(vec![1u8; 80])
        .envelope(546)
        .build();
    let ok = compose_reveal(ok_inputs);
    assert!(ok.is_ok(), "80-byte OP_RETURN payload should be accepted");

    let err_inputs = RevealInputs::builder()
        .commit_tx(dummy_commit_tx)
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .participants(vec![participant])
        .op_return_data(vec![2u8; 81])
        .envelope(546)
        .build();
    let err = compose_reveal(err_inputs);
    assert!(err.is_err(), "81-byte OP_RETURN payload should be rejected");
    let msg = err.err().unwrap().to_string();
    assert!(
        msg.contains("OP_RETURN data exceeds 80 bytes"),
        "unexpected error: {}",
        msg
    );
    Ok(())
}

// ============================================================================
// estimate_participant_commit_fees tests
// ============================================================================

/// Helper to create a base transaction with given inputs/outputs.
fn make_base_tx(num_inputs: usize, num_outputs: usize) -> Transaction {
    let inputs: Vec<TxIn> = (0..num_inputs)
        .map(|i| TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(
                    "0000000000000000000000000000000000000000000000000000000000000001",
                )
                .unwrap(),
                vout: i as u32,
            },
            ..Default::default()
        })
        .collect();

    let outputs: Vec<TxOut> = (0..num_outputs)
        .map(|_| TxOut {
            value: Amount::from_sat(1000),
            script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]), // P2TR output size
        })
        .collect();

    Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: inputs,
        output: outputs,
    }
}

/// Helper to create UTXOs for testing.
fn make_utxos(count: usize) -> Vec<(OutPoint, TxOut)> {
    (0..count)
        .map(|i| {
            (
                OutPoint {
                    txid: Txid::from_str(
                        "0000000000000000000000000000000000000000000000000000000000000002",
                    )
                    .unwrap(),
                    vout: i as u32,
                },
                TxOut {
                    value: Amount::from_sat(10_000),
                    script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
                },
            )
        })
        .collect()
}

pub fn test_estimate_participant_commit_fees_empty_utxos() {
    // Empty UTXOs should still work - adds only outputs, no inputs
    let base_tx = make_base_tx(0, 0);
    let utxos: Vec<(OutPoint, TxOut)> = vec![];
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let result = estimate_participant_commit_fees(&base_tx, &utxos, fee_rate);

    assert!(result.is_ok(), "Should succeed with empty UTXOs");
    let (fee_with_change, fee_no_change) = result.unwrap();

    // With no inputs, only outputs are added:
    // - Script output: 43 vbytes (8 value + 1 varint + 34 script)
    // - Change output: 43 vbytes
    // fee_with_change should be ~860 sats, fee_no_change should be ~430 sats
    assert!(
        fee_with_change > fee_no_change,
        "Fee with change should be higher: {} vs {}",
        fee_with_change,
        fee_no_change
    );
}

pub fn test_estimate_participant_commit_fees_single_utxo() {
    let base_tx = make_base_tx(0, 0);
    let utxos = make_utxos(1);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let (fee_with_change, fee_no_change) =
        estimate_participant_commit_fees(&base_tx, &utxos, fee_rate).unwrap();

    // Single input + 2 outputs (with change) vs single input + 1 output
    // Input: ~57 vbytes (41 non-witness + 64 witness at 1/4 weight)
    // Script output: 43 vbytes
    // Change output: 43 vbytes
    assert!(
        fee_with_change > 0 && fee_no_change > 0,
        "Fees should be non-zero"
    );
    assert!(
        fee_with_change > fee_no_change,
        "Fee with change should be higher: {} vs {}",
        fee_with_change,
        fee_no_change
    );

    // Difference should be one output worth (~43 vbytes * 10 = 430 sats)
    let diff = fee_with_change - fee_no_change;
    assert!(
        (400..=500).contains(&diff),
        "Change output should add ~430 sats: got {}",
        diff
    );
}

pub fn test_estimate_participant_commit_fees_multiple_utxos() {
    let base_tx = make_base_tx(0, 0);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let utxos_1 = make_utxos(1);
    let utxos_3 = make_utxos(3);

    let (fee_1_with, fee_1_no) =
        estimate_participant_commit_fees(&base_tx, &utxos_1, fee_rate).unwrap();
    let (fee_3_with, fee_3_no) =
        estimate_participant_commit_fees(&base_tx, &utxos_3, fee_rate).unwrap();

    // More UTXOs = more inputs = higher fees
    assert!(
        fee_3_with > fee_1_with,
        "3 UTXOs should cost more than 1: {} vs {}",
        fee_3_with,
        fee_1_with
    );
    assert!(
        fee_3_no > fee_1_no,
        "3 UTXOs (no change) should cost more than 1: {} vs {}",
        fee_3_no,
        fee_1_no
    );

    // Each additional input adds ~57 vbytes = 570 sats at 10 sat/vb
    // 2 additional inputs = ~1140 sats
    let diff_with = fee_3_with - fee_1_with;
    let diff_no = fee_3_no - fee_1_no;
    assert!(
        (1000..=1300).contains(&diff_with),
        "2 additional inputs should add ~1140 sats (with change): got {}",
        diff_with
    );
    assert!(
        (1000..=1300).contains(&diff_no),
        "2 additional inputs should add ~1140 sats (no change): got {}",
        diff_no
    );
}

pub fn test_estimate_participant_commit_fees_fee_rate_scaling() {
    let base_tx = make_base_tx(0, 0);
    let utxos = make_utxos(1);

    let fee_rate_5 = FeeRate::from_sat_per_vb(5).unwrap();
    let fee_rate_10 = FeeRate::from_sat_per_vb(10).unwrap();

    let (fee_5_with, fee_5_no) =
        estimate_participant_commit_fees(&base_tx, &utxos, fee_rate_5).unwrap();
    let (fee_10_with, fee_10_no) =
        estimate_participant_commit_fees(&base_tx, &utxos, fee_rate_10).unwrap();

    // Double fee rate = exactly double fees
    assert_eq!(
        fee_10_with,
        fee_5_with * 2,
        "Double fee rate should double fee (with change): {} vs {}",
        fee_10_with,
        fee_5_with * 2
    );
    assert_eq!(
        fee_10_no,
        fee_5_no * 2,
        "Double fee rate should double fee (no change): {} vs {}",
        fee_10_no,
        fee_5_no * 2
    );
}

pub fn test_estimate_participant_commit_fees_with_existing_base_tx() {
    // Base tx already has inputs/outputs - delta should only include new stuff
    let base_tx = make_base_tx(2, 2);
    let utxos = make_utxos(1);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let (fee_with, fee_no) = estimate_participant_commit_fees(&base_tx, &utxos, fee_rate).unwrap();

    // Should only charge for delta (1 input + script output + optional change)
    // Not for the existing 2 inputs + 2 outputs in base_tx
    // Delta: 1 input (~57) + script output (43) + change output (43) = ~143 vbytes = 1430 sats
    assert!(
        (1300..=1600).contains(&fee_with),
        "Delta with change should be ~1430 sats: got {}",
        fee_with
    );
    // Delta: 1 input (~57) + script output (43) = ~100 vbytes = 1000 sats
    assert!(
        (900..=1100).contains(&fee_no),
        "Delta without change should be ~1000 sats: got {}",
        fee_no
    );
}

pub fn test_estimate_participant_commit_fees_deterministic() {
    let base_tx = make_base_tx(1, 1);
    let utxos = make_utxos(2);
    let fee_rate = FeeRate::from_sat_per_vb(7).unwrap();

    let result1 = estimate_participant_commit_fees(&base_tx, &utxos, fee_rate).unwrap();
    let result2 = estimate_participant_commit_fees(&base_tx, &utxos, fee_rate).unwrap();

    assert_eq!(result1, result2, "Same inputs should produce same outputs");
}

pub fn test_estimate_participant_commit_fees_does_not_modify_base_tx() {
    let base_tx = make_base_tx(1, 1);
    let base_tx_clone = base_tx.clone();
    let utxos = make_utxos(2);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let _ = estimate_participant_commit_fees(&base_tx, &utxos, fee_rate);

    // Original base_tx should be unchanged
    assert_eq!(
        base_tx.input.len(),
        base_tx_clone.input.len(),
        "Base tx inputs should be unchanged"
    );
    assert_eq!(
        base_tx.output.len(),
        base_tx_clone.output.len(),
        "Base tx outputs should be unchanged"
    );
}

pub fn test_estimate_participant_commit_fees_minimum_fee_rate() {
    let base_tx = make_base_tx(0, 0);
    let utxos = make_utxos(1);
    let fee_rate = FeeRate::from_sat_per_vb(1).unwrap();

    let (fee_with, fee_no) = estimate_participant_commit_fees(&base_tx, &utxos, fee_rate).unwrap();

    assert!(
        fee_with > 0,
        "Fee should be non-zero even at 1 sat/vb: {}",
        fee_with
    );
    assert!(
        fee_no > 0,
        "Fee (no change) should be non-zero even at 1 sat/vb: {}",
        fee_no
    );
}

pub fn test_estimate_participant_commit_fees_high_fee_rate() {
    let base_tx = make_base_tx(0, 0);
    let utxos = make_utxos(1);
    let fee_rate = FeeRate::from_sat_per_vb(500).unwrap();

    let (fee_with, fee_no) = estimate_participant_commit_fees(&base_tx, &utxos, fee_rate).unwrap();

    // At 500 sat/vb:
    // ~143 vbytes (with change) = 71,500 sats
    // ~100 vbytes (no change) = 50,000 sats
    assert!(
        fee_with > 50_000,
        "High fee rate should result in high fee: {}",
        fee_with
    );
    assert!(
        fee_no > 40_000,
        "High fee rate (no change) should result in high fee: {}",
        fee_no
    );
}

pub fn test_estimate_participant_commit_fees_many_utxos() {
    let base_tx = make_base_tx(0, 0);
    let utxos = make_utxos(10);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let (fee_with, fee_no) = estimate_participant_commit_fees(&base_tx, &utxos, fee_rate).unwrap();

    // 10 inputs at ~57 vbytes each = 570 vbytes
    // + script output (43) + change output (43) = 656 vbytes = 6560 sats
    assert!(
        (6000..=7500).contains(&fee_with),
        "10 inputs + 2 outputs should be ~6500 sats: got {}",
        fee_with
    );
    // Without change: 570 + 43 = 613 vbytes = 6130 sats
    assert!(
        (5500..=7000).contains(&fee_no),
        "10 inputs + 1 output should be ~6100 sats: got {}",
        fee_no
    );
}

pub fn test_estimate_participant_commit_fees_change_output_difference() {
    // Verify the exact difference between with/without change
    let base_tx = make_base_tx(0, 0);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    for num_utxos in [1, 2, 5, 10] {
        let utxos = make_utxos(num_utxos);
        let (fee_with, fee_no) =
            estimate_participant_commit_fees(&base_tx, &utxos, fee_rate).unwrap();

        // Difference should always be exactly one P2TR output (43 vbytes = 430 sats)
        let diff = fee_with - fee_no;
        assert!(
            (400..=480).contains(&diff),
            "With {} UTXOs, change output diff should be ~430 sats: got {}",
            num_utxos,
            diff
        );
    }
}

pub fn test_estimate_participant_commit_fees_input_vsize_delta() {
    // Verify each input adds approximately 57-58 vbytes
    let base_tx = make_base_tx(0, 0);
    let fee_rate = FeeRate::from_sat_per_vb(1).unwrap(); // 1 sat/vb for easy math

    let utxos_1 = make_utxos(1);
    let utxos_2 = make_utxos(2);
    let utxos_3 = make_utxos(3);

    let (_, fee_1) = estimate_participant_commit_fees(&base_tx, &utxos_1, fee_rate).unwrap();
    let (_, fee_2) = estimate_participant_commit_fees(&base_tx, &utxos_2, fee_rate).unwrap();
    let (_, fee_3) = estimate_participant_commit_fees(&base_tx, &utxos_3, fee_rate).unwrap();

    // At 1 sat/vb, fee = vsize
    let delta_1_to_2 = fee_2 - fee_1;
    let delta_2_to_3 = fee_3 - fee_2;

    // Each input should add ~57-58 vbytes
    assert!(
        (55..=62).contains(&delta_1_to_2),
        "Input vsize delta should be ~57: got {}",
        delta_1_to_2
    );
    assert!(
        (55..=62).contains(&delta_2_to_3),
        "Input vsize delta should be ~57: got {}",
        delta_2_to_3
    );
}

pub fn test_estimate_participant_commit_fees_output_vsize() {
    // Verify outputs are 43 vbytes each (P2TR)
    let base_tx = make_base_tx(0, 0);
    let utxos = make_utxos(1);
    let fee_rate = FeeRate::from_sat_per_vb(1).unwrap(); // 1 sat/vb for easy math

    let (fee_with, fee_no) = estimate_participant_commit_fees(&base_tx, &utxos, fee_rate).unwrap();

    // Difference is exactly the change output
    let change_output_vsize = fee_with - fee_no;
    assert!(
        (40..=48).contains(&change_output_vsize),
        "P2TR output should be ~43 vbytes: got {}",
        change_output_vsize
    );
}

pub async fn test_estimate_participant_commit_fees_with_real_utxos(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_estimate_participant_commit_fees_with_real_utxos");

    let identity = reg_tester.identity().await?;
    let (outpoint, prevout) = identity.next_funding_utxo;

    let base_tx = make_base_tx(0, 0);
    let utxos = vec![(outpoint, prevout)];
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let result = estimate_participant_commit_fees(&base_tx, &utxos, fee_rate);
    assert!(result.is_ok(), "Should work with real UTXOs");

    let (fee_with, fee_no) = result.unwrap();
    assert!(fee_with > 0);
    assert!(fee_no > 0);
    assert!(fee_with > fee_no);

    Ok(())
}

// ============================================================================
// select_utxos_for_commit tests
// ============================================================================

/// Helper to create UTXOs with specific values for selection testing.
fn make_utxos_with_values(values: &[u64]) -> Vec<(OutPoint, TxOut)> {
    values
        .iter()
        .enumerate()
        .map(|(i, &value)| {
            (
                OutPoint {
                    txid: Txid::from_str(
                        "0000000000000000000000000000000000000000000000000000000000000099",
                    )
                    .unwrap(),
                    vout: i as u32,
                },
                TxOut {
                    value: Amount::from_sat(value),
                    script_pubkey: ScriptBuf::from_bytes(vec![0u8; 34]),
                },
            )
        })
        .collect()
}

pub fn test_select_utxos_for_commit_empty_utxos_errors() {
    let base_tx = make_base_tx(0, 0);
    let utxos: Vec<(OutPoint, TxOut)> = vec![];
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let result = select_utxos_for_commit(&base_tx, utxos, 1000, fee_rate, 330);

    assert!(result.is_err(), "Empty UTXOs should error");
    let err_msg = result.err().unwrap().to_string();
    assert!(
        err_msg.contains("no UTXOs provided"),
        "Error should mention no UTXOs: {}",
        err_msg
    );
}

pub fn test_select_utxos_for_commit_single_utxo_sufficient() {
    let base_tx = make_base_tx(0, 0);
    // Single large UTXO that can cover script output + fee + change
    let utxos = make_utxos_with_values(&[100_000]);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let script_output = 1000;
    let envelope = 330;

    let result = select_utxos_for_commit(&base_tx, utxos, script_output, fee_rate, envelope);

    assert!(result.is_ok(), "Should succeed with sufficient UTXO");
    let (selected, fee) = result.unwrap();
    assert_eq!(selected.len(), 1, "Should select the single UTXO");
    assert!(fee > 0, "Fee should be non-zero");

    // Verify we can afford everything
    let total_value: u64 = selected.iter().map(|(_, txo)| txo.value.to_sat()).sum();
    assert!(
        total_value >= script_output + fee + envelope,
        "Should have enough for script output + fee + change"
    );
}

pub fn test_select_utxos_for_commit_single_utxo_insufficient() {
    let base_tx = make_base_tx(0, 0);
    // Single small UTXO that cannot cover script output
    let utxos = make_utxos_with_values(&[500]);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let script_output = 10_000;
    let envelope = 330;

    let result = select_utxos_for_commit(&base_tx, utxos, script_output, fee_rate, envelope);

    assert!(result.is_err(), "Should fail with insufficient UTXO");
    let err_msg = result.err().unwrap().to_string();
    assert!(
        err_msg.contains("Insufficient funds"),
        "Error should mention insufficient funds: {}",
        err_msg
    );
}

pub fn test_select_utxos_for_commit_multiple_utxos_selects_minimum() {
    let base_tx = make_base_tx(0, 0);
    // Multiple UTXOs - should select minimum needed
    let utxos = make_utxos_with_values(&[1000, 2000, 3000, 50_000]);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let script_output = 1000;
    let envelope = 330;

    let result =
        select_utxos_for_commit(&base_tx, utxos.clone(), script_output, fee_rate, envelope);

    assert!(result.is_ok(), "Should succeed");
    let (selected, fee) = result.unwrap();

    // Should not need all UTXOs
    assert!(
        selected.len() < utxos.len(),
        "Should not select all UTXOs: selected {} of {}",
        selected.len(),
        utxos.len()
    );

    // Verify we have enough
    let total: u64 = selected.iter().map(|(_, txo)| txo.value.to_sat()).sum();
    assert!(
        total >= script_output + fee,
        "Total {} should cover script {} + fee {}",
        total,
        script_output,
        fee
    );
}

pub fn test_select_utxos_for_commit_selects_in_order() {
    let base_tx = make_base_tx(0, 0);
    // UTXOs in specific order - selection should be in order provided
    let utxos = make_utxos_with_values(&[5000, 6000, 7000]);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let script_output = 1000;
    let envelope = 330;

    let result =
        select_utxos_for_commit(&base_tx, utxos.clone(), script_output, fee_rate, envelope);

    assert!(result.is_ok(), "Should succeed");
    let (selected, _) = result.unwrap();

    // First UTXO (5000 sats) should be enough for script (1000) + fee (~1400) + envelope (330)
    // Total needed: ~2730, so 5000 should be sufficient
    if selected.len() == 1 {
        assert_eq!(
            selected[0].0.vout, 0,
            "Should select first UTXO if sufficient"
        );
    }
}

pub fn test_select_utxos_for_commit_change_above_dust() {
    let base_tx = make_base_tx(0, 0);
    // UTXO value chosen so change will be well above dust
    let utxos = make_utxos_with_values(&[100_000]);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let script_output = 1000;
    let envelope = 330;

    let result = select_utxos_for_commit(&base_tx, utxos, script_output, fee_rate, envelope);

    assert!(result.is_ok());
    let (selected, fee) = result.unwrap();
    let total: u64 = selected.iter().map(|(_, txo)| txo.value.to_sat()).sum();
    let change = total - script_output - fee;

    // Change should be well above dust threshold
    assert!(
        change >= envelope,
        "Change {} should be >= envelope {}",
        change,
        envelope
    );

    // Fee should include change output since change >= envelope
    // At 10 sat/vb, 1 input + 2 outputs (script + change) = ~143 vbytes = ~1430 sats
    assert!(
        (1200..=1700).contains(&fee),
        "Fee with change should be ~1430: got {}",
        fee
    );
}

pub fn test_select_utxos_for_commit_change_below_dust() {
    let base_tx = make_base_tx(0, 0);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let envelope = 330;

    // We need to craft the UTXO value so that:
    // 1. It's enough to cover script_output + fee_no_change
    // 2. But the leftover (change) is < envelope
    //
    // fee_no_change for 1 input, 1 output at 10 sat/vb:
    // ~100 vbytes = ~1000 sats
    // So if script_output = 1000, we need UTXO > 2000 but change < 330
    // UTXO = 2300 gives us: 2300 - 1000 - 1000 = 300 change (below 330)

    let utxos = make_utxos_with_values(&[2300]);
    let script_output = 1000;

    let result = select_utxos_for_commit(&base_tx, utxos, script_output, fee_rate, envelope);

    assert!(result.is_ok());
    let (selected, fee) = result.unwrap();
    let total: u64 = selected.iter().map(|(_, txo)| txo.value.to_sat()).sum();
    let change = total - script_output - fee;

    // Change should be below dust (no change output will be created)
    assert!(
        change < envelope,
        "Change {} should be < envelope {} (dust scenario)",
        change,
        envelope
    );

    // Fee should NOT include change output since change < envelope
    // At 10 sat/vb, 1 input + 1 output = ~100 vbytes = ~1000 sats
    assert!(
        (800..=1200).contains(&fee),
        "Fee without change should be ~1000: got {}",
        fee
    );
}

pub fn test_select_utxos_for_commit_fee_rate_affects_selection() {
    let base_tx = make_base_tx(0, 0);
    // UTXOs that might be sufficient at low fee rate but not at high
    let utxos = make_utxos_with_values(&[2000, 3000, 4000]);
    let script_output = 1000;
    let envelope = 330;

    let fee_rate_low = FeeRate::from_sat_per_vb(2).unwrap();
    let fee_rate_high = FeeRate::from_sat_per_vb(50).unwrap();

    let result_low = select_utxos_for_commit(
        &base_tx,
        utxos.clone(),
        script_output,
        fee_rate_low,
        envelope,
    );
    let result_high = select_utxos_for_commit(
        &base_tx,
        utxos.clone(),
        script_output,
        fee_rate_high,
        envelope,
    );

    assert!(result_low.is_ok(), "Should succeed at low fee rate");

    let (selected_low, fee_low) = result_low.unwrap();

    // High fee rate needs more UTXOs (if it succeeds) or higher fee
    if let Ok((selected_high, fee_high)) = result_high {
        assert!(
            fee_high > fee_low,
            "Higher fee rate should result in higher fee"
        );
        // May need more UTXOs at high fee rate
        assert!(
            selected_high.len() >= selected_low.len(),
            "High fee rate may need more UTXOs"
        );
    }
    // It's also valid for high fee rate to fail if UTXOs are insufficient
}

pub fn test_select_utxos_for_commit_script_output_value_affects_selection() {
    let base_tx = make_base_tx(0, 0);
    let utxos = make_utxos_with_values(&[5000, 10000, 15000]);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let envelope = 330;

    let result_small = select_utxos_for_commit(&base_tx, utxos.clone(), 1000, fee_rate, envelope);
    let result_large = select_utxos_for_commit(&base_tx, utxos.clone(), 20000, fee_rate, envelope);

    assert!(result_small.is_ok(), "Small script output should succeed");
    let (selected_small, _) = result_small.unwrap();

    // Large script output needs more UTXOs
    if let Ok((selected_large, _)) = result_large {
        assert!(
            selected_large.len() >= selected_small.len(),
            "Larger script output may need more UTXOs"
        );
    }
    // Large script output might fail if sum of UTXOs < required
}

pub fn test_select_utxos_for_commit_with_existing_base_tx() {
    // Base tx already has inputs/outputs - delta fees should be calculated correctly
    let base_tx = make_base_tx(2, 2);
    let utxos = make_utxos_with_values(&[50_000]);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let script_output = 1000;
    let envelope = 330;

    let result = select_utxos_for_commit(&base_tx, utxos, script_output, fee_rate, envelope);

    assert!(result.is_ok(), "Should succeed with existing base tx");
    let (selected, fee) = result.unwrap();
    assert_eq!(selected.len(), 1);

    // Fee should be for delta only (1 new input + 2 new outputs)
    // Not for the entire tx including existing inputs/outputs
    assert!(
        (1200..=1700).contains(&fee),
        "Delta fee should be ~1430: got {}",
        fee
    );
}

pub fn test_select_utxos_for_commit_returns_correct_subset() {
    let base_tx = make_base_tx(0, 0);
    // Create UTXOs with distinct values to verify correct subset is returned
    let utxos = make_utxos_with_values(&[1000, 2000, 3000, 4000, 5000]);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let script_output = 2000;
    let envelope = 330;

    let result =
        select_utxos_for_commit(&base_tx, utxos.clone(), script_output, fee_rate, envelope);

    assert!(result.is_ok());
    let (selected, _) = result.unwrap();

    // Verify selected UTXOs are from the original list (in order)
    for (i, (selected_op, selected_txo)) in selected.iter().enumerate() {
        let (orig_op, orig_txo) = &utxos[i];
        assert_eq!(selected_op, orig_op, "Outpoint should match");
        assert_eq!(
            selected_txo.value, orig_txo.value,
            "TxOut value should match"
        );
    }
}

pub fn test_select_utxos_for_commit_exact_amount_no_change() {
    let base_tx = make_base_tx(0, 0);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let envelope = 330;
    let script_output = 1000;

    // Calculate what we need for exact amount (no change scenario)
    // 1 input + 1 output (script) = ~100 vbytes = ~1000 sats fee
    // Total needed: 1000 (script) + 1000 (fee) = 2000 sats
    // If we have exactly 2000 sats, change = 0 (< envelope)

    let utxos = make_utxos_with_values(&[2000]);

    let result = select_utxos_for_commit(&base_tx, utxos, script_output, fee_rate, envelope);

    assert!(result.is_ok());
    let (selected, fee) = result.unwrap();
    let total: u64 = selected.iter().map(|(_, txo)| txo.value.to_sat()).sum();
    let remaining = total - script_output - fee;

    // Should have little to no change
    assert!(
        remaining < envelope,
        "Should have minimal change: {}",
        remaining
    );
}

pub fn test_select_utxos_for_commit_many_small_utxos() {
    let base_tx = make_base_tx(0, 0);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let envelope = 330;
    let script_output = 1000;

    // Many small UTXOs - each one adds fee, so need many to cover
    let utxos = make_utxos_with_values(&[500, 500, 500, 500, 500, 1000, 1000, 1000, 1000, 10000]);

    let result =
        select_utxos_for_commit(&base_tx, utxos.clone(), script_output, fee_rate, envelope);

    assert!(result.is_ok(), "Should eventually have enough");
    let (selected, fee) = result.unwrap();

    // May need several UTXOs because each input adds ~570 sats of fee
    // Total available: 500*5 + 1000*4 + 10000 = 16500 sats
    assert!(!selected.is_empty(), "Should select at least one UTXO");

    let total: u64 = selected.iter().map(|(_, txo)| txo.value.to_sat()).sum();
    assert!(
        total >= script_output + fee,
        "Total {} should cover script {} + fee {}",
        total,
        script_output,
        fee
    );
}

pub fn test_select_utxos_for_commit_envelope_affects_change_threshold() {
    let base_tx = make_base_tx(0, 0);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let script_output = 1000;

    // Same UTXOs but different envelope values
    let utxos = make_utxos_with_values(&[3000]);

    let result_low = select_utxos_for_commit(&base_tx, utxos.clone(), script_output, fee_rate, 100);
    let result_high =
        select_utxos_for_commit(&base_tx, utxos.clone(), script_output, fee_rate, 1000);

    assert!(result_low.is_ok());
    let (_, fee_low) = result_low.unwrap();

    // Higher envelope means higher dust threshold, might affect whether change is created
    // This affects which fee is returned (fee_with_change vs fee_no_change)
    if let Ok((_, fee_high)) = result_high {
        // Fees might differ based on whether change output is included
        // fee_with_change > fee_no_change because change output adds ~43 vbytes
        // Different envelope values may result in different change scenarios
        assert!(fee_low > 0 && fee_high > 0);
    }
}

pub fn test_select_utxos_for_commit_deterministic() {
    let base_tx = make_base_tx(0, 0);
    let utxos = make_utxos_with_values(&[5000, 10000, 15000]);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let script_output = 2000;
    let envelope = 330;

    let result1 =
        select_utxos_for_commit(&base_tx, utxos.clone(), script_output, fee_rate, envelope);
    let result2 = select_utxos_for_commit(&base_tx, utxos, script_output, fee_rate, envelope);

    assert!(result1.is_ok() && result2.is_ok());
    let (selected1, fee1) = result1.unwrap();
    let (selected2, fee2) = result2.unwrap();

    assert_eq!(selected1.len(), selected2.len(), "Should select same count");
    assert_eq!(fee1, fee2, "Fees should be identical");
}

pub fn test_select_utxos_for_commit_insufficient_with_fees() {
    // UTXOs sum might cover script output but not when fees are included
    let base_tx = make_base_tx(0, 0);
    let fee_rate = FeeRate::from_sat_per_vb(100).unwrap(); // Very high fee rate
    let envelope = 330;
    let script_output = 5000;

    // At 100 sat/vb, 1 input + 1 output = ~100 vbytes = ~10,000 sats fee
    // Total needed: 5000 + 10000 = 15000 sats minimum
    // But we only have 12000 sats
    let utxos = make_utxos_with_values(&[4000, 4000, 4000]);

    let result = select_utxos_for_commit(&base_tx, utxos, script_output, fee_rate, envelope);

    // This should fail because total (12000) < script_output (5000) + fee (~15000+ with 3 inputs)
    assert!(
        result.is_err(),
        "Should fail when UTXOs can't cover script + fees"
    );
}

pub fn test_select_utxos_for_commit_edge_case_change_equals_envelope() {
    let base_tx = make_base_tx(0, 0);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let envelope = 330;
    let script_output = 1000;

    // We want change to be exactly at envelope boundary
    // This is tricky because we need: total - script - fee_with_change = envelope
    // At 10 sat/vb with 1 input + 2 outputs: fee ~1430 sats
    // So: total = 1000 + 1430 + 330 = 2760

    let utxos = make_utxos_with_values(&[2800]); // Slightly above to ensure success

    let result = select_utxos_for_commit(&base_tx, utxos, script_output, fee_rate, envelope);

    assert!(result.is_ok());
    let (selected, fee) = result.unwrap();
    let total: u64 = selected.iter().map(|(_, txo)| txo.value.to_sat()).sum();
    let change = total - script_output - fee;

    // Change should be >= envelope (boundary case)
    assert!(
        change >= envelope,
        "Change {} should be >= envelope {} at boundary",
        change,
        envelope
    );
}

pub async fn test_select_utxos_for_commit_with_real_utxo(reg_tester: &mut RegTester) -> Result<()> {
    info!("test_select_utxos_for_commit_with_real_utxo");

    let identity = reg_tester.identity().await?;
    let (outpoint, prevout) = identity.next_funding_utxo;

    let base_tx = make_base_tx(0, 0);
    let utxos = vec![(outpoint, prevout.clone())];
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let script_output = 1000;
    let envelope = 330;

    let result = select_utxos_for_commit(&base_tx, utxos, script_output, fee_rate, envelope);

    // Real UTXO from regtest should have enough value
    assert!(
        result.is_ok(),
        "Should succeed with real UTXO: {:?}",
        result.err()
    );
    let (selected, fee) = result.unwrap();

    assert_eq!(selected.len(), 1);
    assert!(fee > 0);

    let total = prevout.value.to_sat();
    assert!(
        total >= script_output + fee + envelope,
        "Real UTXO should have enough: {} >= {} + {} + {}",
        total,
        script_output,
        fee,
        envelope
    );

    Ok(())
}

// ============================================================================
// calculate_reveal_fee_delta tests
// ============================================================================

/// Helper to create a dummy tap script of given size.
fn make_dummy_tap_script(size: usize) -> ScriptBuf {
    ScriptBuf::from_bytes(vec![0u8; size])
}

/// Helper to create a dummy control block of given size.
fn make_dummy_control_block(size: usize) -> Vec<u8> {
    vec![0u8; size]
}

/// Helper to create a fresh empty transaction for delta calculations.
fn make_empty_dummy_tx() -> Transaction {
    Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    }
}

pub fn test_calculate_reveal_fee_delta_single_participant_no_chained() {
    let mut dummy_tx = make_empty_dummy_tx();
    let tap_script = make_dummy_tap_script(100);
    let control_block = make_dummy_control_block(33);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let envelope = 330;

    let fee = calculate_reveal_fee_delta(
        &mut dummy_tx,
        &tap_script,
        &control_block,
        false,
        fee_rate,
        envelope,
    )
    .unwrap();

    assert!(fee > 0, "Fee should be non-zero");

    // Verify dummy tx was modified
    assert_eq!(dummy_tx.input.len(), 1, "Should have added 1 input");
    assert_eq!(
        dummy_tx.output.len(),
        1,
        "Should have added 1 output (change only, no chained)"
    );
}

pub fn test_calculate_reveal_fee_delta_single_participant_with_chained() {
    let mut dummy_tx = make_empty_dummy_tx();
    let tap_script = make_dummy_tap_script(100);
    let control_block = make_dummy_control_block(33);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let envelope = 330;

    let fee = calculate_reveal_fee_delta(
        &mut dummy_tx,
        &tap_script,
        &control_block,
        true,
        fee_rate,
        envelope,
    )
    .unwrap();

    assert!(fee > 0, "Fee should be non-zero");

    // Verify dummy tx was modified
    assert_eq!(dummy_tx.input.len(), 1, "Should have added 1 input");
    assert_eq!(
        dummy_tx.output.len(),
        2,
        "Should have added 2 outputs (chained + change)"
    );
}

pub fn test_calculate_reveal_fee_delta_chained_adds_output_fee() {
    let tap_script = make_dummy_tap_script(100);
    let control_block = make_dummy_control_block(33);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let envelope = 330;

    let mut dummy_no_chained = make_empty_dummy_tx();
    let fee_no_chained = calculate_reveal_fee_delta(
        &mut dummy_no_chained,
        &tap_script,
        &control_block,
        false,
        fee_rate,
        envelope,
    )
    .unwrap();

    let mut dummy_with_chained = make_empty_dummy_tx();
    let fee_with_chained = calculate_reveal_fee_delta(
        &mut dummy_with_chained,
        &tap_script,
        &control_block,
        true,
        fee_rate,
        envelope,
    )
    .unwrap();

    assert!(
        fee_with_chained > fee_no_chained,
        "Chained should cost more: {} vs {}",
        fee_with_chained,
        fee_no_chained
    );

    // Difference should be one P2TR output (~43 vbytes = 430 sats at 10 sat/vb)
    let diff = fee_with_chained - fee_no_chained;
    assert!(
        (400..=500).contains(&diff),
        "Chained output should add ~430 sats: got {}",
        diff
    );
}

pub fn test_calculate_reveal_fee_delta_fee_rate_scaling() {
    let tap_script = make_dummy_tap_script(100);
    let control_block = make_dummy_control_block(33);
    let envelope = 330;

    let mut dummy_5 = make_empty_dummy_tx();
    let fee_rate_5 = FeeRate::from_sat_per_vb(5).unwrap();
    let fee_5 = calculate_reveal_fee_delta(
        &mut dummy_5,
        &tap_script,
        &control_block,
        false,
        fee_rate_5,
        envelope,
    )
    .unwrap();

    let mut dummy_10 = make_empty_dummy_tx();
    let fee_rate_10 = FeeRate::from_sat_per_vb(10).unwrap();
    let fee_10 = calculate_reveal_fee_delta(
        &mut dummy_10,
        &tap_script,
        &control_block,
        false,
        fee_rate_10,
        envelope,
    )
    .unwrap();

    // Double fee rate = exactly double the fee
    assert_eq!(
        fee_10,
        fee_5 * 2,
        "Doubling fee rate should double fee: {} vs {}",
        fee_10,
        fee_5 * 2
    );
}

pub fn test_calculate_reveal_fee_delta_larger_script_higher_fee() {
    let control_block = make_dummy_control_block(33);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let envelope = 330;

    let mut dummy_small = make_empty_dummy_tx();
    let small_script = make_dummy_tap_script(50);
    let fee_small = calculate_reveal_fee_delta(
        &mut dummy_small,
        &small_script,
        &control_block,
        false,
        fee_rate,
        envelope,
    )
    .unwrap();

    let mut dummy_large = make_empty_dummy_tx();
    let large_script = make_dummy_tap_script(500);
    let fee_large = calculate_reveal_fee_delta(
        &mut dummy_large,
        &large_script,
        &control_block,
        false,
        fee_rate,
        envelope,
    )
    .unwrap();

    assert!(
        fee_large > fee_small,
        "Larger script should cost more: {} vs {}",
        fee_large,
        fee_small
    );
}

pub fn test_calculate_reveal_fee_delta_larger_control_block_higher_fee() {
    let tap_script = make_dummy_tap_script(100);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let envelope = 330;

    let mut dummy_small = make_empty_dummy_tx();
    let small_cb = make_dummy_control_block(33); // minimal
    let fee_small = calculate_reveal_fee_delta(
        &mut dummy_small,
        &tap_script,
        &small_cb,
        false,
        fee_rate,
        envelope,
    )
    .unwrap();

    let mut dummy_large = make_empty_dummy_tx();
    let large_cb = make_dummy_control_block(65); // deeper merkle tree
    let fee_large = calculate_reveal_fee_delta(
        &mut dummy_large,
        &tap_script,
        &large_cb,
        false,
        fee_rate,
        envelope,
    )
    .unwrap();

    assert!(
        fee_large > fee_small,
        "Larger control block should cost more: {} vs {}",
        fee_large,
        fee_small
    );
}

pub fn test_calculate_reveal_fee_delta_envelope_does_not_affect_fee() {
    let tap_script = make_dummy_tap_script(100);
    let control_block = make_dummy_control_block(33);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let mut dummy_small_env = make_empty_dummy_tx();
    let fee_small_env = calculate_reveal_fee_delta(
        &mut dummy_small_env,
        &tap_script,
        &control_block,
        false,
        fee_rate,
        330,
    )
    .unwrap();

    let mut dummy_large_env = make_empty_dummy_tx();
    let fee_large_env = calculate_reveal_fee_delta(
        &mut dummy_large_env,
        &tap_script,
        &control_block,
        false,
        fee_rate,
        100_000,
    )
    .unwrap();

    // Envelope value affects output amount, not vsize, so fees should be identical
    assert_eq!(
        fee_small_env, fee_large_env,
        "Envelope value should not affect fee: {} vs {}",
        fee_small_env, fee_large_env
    );
}

pub fn test_calculate_reveal_fee_delta_modifies_dummy_tx() {
    let mut dummy_tx = make_empty_dummy_tx();
    let tap_script = make_dummy_tap_script(100);
    let control_block = make_dummy_control_block(33);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    assert_eq!(dummy_tx.input.len(), 0);
    assert_eq!(dummy_tx.output.len(), 0);

    let _ = calculate_reveal_fee_delta(
        &mut dummy_tx,
        &tap_script,
        &control_block,
        true,
        fee_rate,
        330,
    )
    .unwrap();

    assert_eq!(dummy_tx.input.len(), 1, "Should have added input");
    assert_eq!(
        dummy_tx.output.len(),
        2,
        "Should have added chained + change outputs"
    );

    // Call again for second participant
    let _ = calculate_reveal_fee_delta(
        &mut dummy_tx,
        &tap_script,
        &control_block,
        false,
        fee_rate,
        330,
    )
    .unwrap();

    assert_eq!(dummy_tx.input.len(), 2, "Should have 2 inputs now");
    assert_eq!(
        dummy_tx.output.len(),
        3,
        "Should have 3 outputs now (2 + 1 change)"
    );
}

pub fn test_calculate_reveal_fee_delta_multiple_participants_sequential() {
    let mut dummy_tx = make_empty_dummy_tx();
    let tap_script = make_dummy_tap_script(100);
    let control_block = make_dummy_control_block(33);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let envelope = 330;

    // First participant
    let fee1 = calculate_reveal_fee_delta(
        &mut dummy_tx,
        &tap_script,
        &control_block,
        false,
        fee_rate,
        envelope,
    )
    .unwrap();

    // Second participant with same script
    let fee2 = calculate_reveal_fee_delta(
        &mut dummy_tx,
        &tap_script,
        &control_block,
        false,
        fee_rate,
        envelope,
    )
    .unwrap();

    // Third participant
    let fee3 = calculate_reveal_fee_delta(
        &mut dummy_tx,
        &tap_script,
        &control_block,
        false,
        fee_rate,
        envelope,
    )
    .unwrap();

    // All fees should be positive
    assert!(fee1 > 0 && fee2 > 0 && fee3 > 0);

    // With same script/control_block, sequential deltas should be similar
    // (slight variation possible due to varint encoding changes)
    let diff_1_2 = fee1.abs_diff(fee2);
    let diff_2_3 = fee2.abs_diff(fee3);
    assert!(
        diff_1_2 <= 50 && diff_2_3 <= 50,
        "Sequential fees should be similar: {} {} {}",
        fee1,
        fee2,
        fee3
    );
}

pub fn test_calculate_reveal_fee_delta_deterministic() {
    let tap_script = make_dummy_tap_script(100);
    let control_block = make_dummy_control_block(33);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let envelope = 330;

    let mut dummy1 = make_empty_dummy_tx();
    let fee1 = calculate_reveal_fee_delta(
        &mut dummy1,
        &tap_script,
        &control_block,
        true,
        fee_rate,
        envelope,
    )
    .unwrap();

    let mut dummy2 = make_empty_dummy_tx();
    let fee2 = calculate_reveal_fee_delta(
        &mut dummy2,
        &tap_script,
        &control_block,
        true,
        fee_rate,
        envelope,
    )
    .unwrap();

    assert_eq!(fee1, fee2, "Same inputs should produce same fee");
}

pub fn test_calculate_reveal_fee_delta_minimum_fee_rate() {
    let mut dummy_tx = make_empty_dummy_tx();
    let tap_script = make_dummy_tap_script(100);
    let control_block = make_dummy_control_block(33);
    let fee_rate = FeeRate::from_sat_per_vb(1).unwrap();

    let fee = calculate_reveal_fee_delta(
        &mut dummy_tx,
        &tap_script,
        &control_block,
        false,
        fee_rate,
        330,
    )
    .unwrap();

    assert!(fee > 0, "Even at 1 sat/vb, fee should be non-zero: {}", fee);
}

pub fn test_calculate_reveal_fee_delta_high_fee_rate() {
    let mut dummy_tx = make_empty_dummy_tx();
    let tap_script = make_dummy_tap_script(100);
    let control_block = make_dummy_control_block(33);
    let fee_rate = FeeRate::from_sat_per_vb(500).unwrap();

    let fee = calculate_reveal_fee_delta(
        &mut dummy_tx,
        &tap_script,
        &control_block,
        false,
        fee_rate,
        330,
    )
    .unwrap();

    // At 500 sat/vb, even a small participant should cost tens of thousands of sats
    assert!(
        fee > 30_000,
        "High fee rate should result in high fee: {}",
        fee
    );
}

pub fn test_calculate_reveal_fee_delta_very_large_script() {
    let mut dummy_tx = make_empty_dummy_tx();
    let tap_script = make_dummy_tap_script(10_000); // 10KB script
    let control_block = make_dummy_control_block(33);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let fee = calculate_reveal_fee_delta(
        &mut dummy_tx,
        &tap_script,
        &control_block,
        false,
        fee_rate,
        330,
    )
    .unwrap();

    // 10KB script in witness (1/4 weight discount) = ~2500 vbytes
    // Plus input overhead + output
    // At 10 sat/vb, expect > 25,000 sats
    assert!(fee > 20_000, "Large script should have high fee: {}", fee);
}

pub fn test_calculate_reveal_fee_delta_witness_structure() {
    // Verify the witness has correct structure: [signature, tap_script, control_block]
    let mut dummy_tx = make_empty_dummy_tx();
    let tap_script = make_dummy_tap_script(100);
    let control_block = make_dummy_control_block(33);
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let _ = calculate_reveal_fee_delta(
        &mut dummy_tx,
        &tap_script,
        &control_block,
        false,
        fee_rate,
        330,
    )
    .unwrap();

    let witness = &dummy_tx.input[0].witness;
    assert_eq!(witness.len(), 3, "Witness should have 3 elements");

    // First element is signature (64 bytes for Schnorr)
    assert_eq!(witness[0].len(), 64, "Signature should be 64 bytes");

    // Second element is tap script
    assert_eq!(witness[1].len(), 100, "Tap script should match input size");

    // Third element is control block
    assert_eq!(
        witness[2].len(),
        33,
        "Control block should match input size"
    );
}

pub async fn test_calculate_reveal_fee_delta_with_real_tap_script(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_calculate_reveal_fee_delta_with_real_tap_script");

    let identity = reg_tester.identity().await?;
    let keypair = identity.keypair;
    let (xonly, _parity) = keypair.x_only_public_key();

    // Build a real tap script
    let data = b"test data for reveal".to_vec();
    let (tap_script, _, control_block) =
        build_tap_script_and_script_address(xonly, data).expect("build tapscript");

    let mut dummy_tx = make_empty_dummy_tx();
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let fee = calculate_reveal_fee_delta(
        &mut dummy_tx,
        &tap_script,
        &control_block.serialize(),
        false,
        fee_rate,
        330,
    )?;

    assert!(fee > 0, "Fee should be non-zero with real tap script");

    // Verify witness structure with real data
    let witness = &dummy_tx.input[0].witness;
    assert_eq!(witness.len(), 3);
    assert_eq!(witness[0].len(), 64); // signature
    assert_eq!(witness[1].len(), tap_script.len()); // tap script
    assert_eq!(witness[2].len(), control_block.serialize().len()); // control block

    Ok(())
}

// ============================================================================
// calculate_op_return_fee_per_participant tests
// ============================================================================

pub fn test_calculate_op_return_fee_per_participant_no_op_return() {
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    // has_op_return = false should return 0
    let fee = calculate_op_return_fee_per_participant(false, 3, fee_rate).unwrap();

    assert_eq!(fee, 0, "No OP_RETURN should return 0 fee");
}

pub fn test_calculate_op_return_fee_per_participant_zero_participants() {
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    // num_participants = 0 should return 0
    let fee = calculate_op_return_fee_per_participant(true, 0, fee_rate).unwrap();

    assert_eq!(fee, 0, "Zero participants should return 0 fee");
}

pub fn test_calculate_op_return_fee_per_participant_single_participant() {
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let fee = calculate_op_return_fee_per_participant(true, 1, fee_rate).unwrap();

    // OP_RETURN vsize = 9 + 80 = 89 vbytes
    // At 10 sat/vb = 890 sats
    assert_eq!(
        fee, 890,
        "Single participant should pay full fee: got {}",
        fee
    );
}

pub fn test_calculate_op_return_fee_per_participant_two_participants() {
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let fee = calculate_op_return_fee_per_participant(true, 2, fee_rate).unwrap();

    // Total = 890 sats, split 2 ways = 445 each
    assert_eq!(
        fee, 445,
        "Two participants should split evenly: got {}",
        fee
    );
}

pub fn test_calculate_op_return_fee_per_participant_three_participants_rounds_up() {
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let fee = calculate_op_return_fee_per_participant(true, 3, fee_rate).unwrap();

    // Total = 890 sats, split 3 ways = 296.67 -> rounds up to 297
    assert_eq!(fee, 297, "Three participants should round up: got {}", fee);
}

pub fn test_calculate_op_return_fee_per_participant_many_participants() {
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let fee = calculate_op_return_fee_per_participant(true, 100, fee_rate).unwrap();

    // Total = 890 sats, split 100 ways = 8.9 -> rounds up to 9
    assert_eq!(
        fee, 9,
        "100 participants should get ~9 sats each: got {}",
        fee
    );
}

pub fn test_calculate_op_return_fee_per_participant_fee_rate_scaling() {
    // Double fee rate = double the per-participant fee
    let fee_rate_5 = FeeRate::from_sat_per_vb(5).unwrap();
    let fee_rate_10 = FeeRate::from_sat_per_vb(10).unwrap();

    let fee_5 = calculate_op_return_fee_per_participant(true, 1, fee_rate_5).unwrap();
    let fee_10 = calculate_op_return_fee_per_participant(true, 1, fee_rate_10).unwrap();

    assert_eq!(
        fee_10,
        fee_5 * 2,
        "Double fee rate should double fee: {} vs {}",
        fee_10,
        fee_5 * 2
    );
}

pub fn test_calculate_op_return_fee_per_participant_deterministic() {
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let fee1 = calculate_op_return_fee_per_participant(true, 5, fee_rate).unwrap();
    let fee2 = calculate_op_return_fee_per_participant(true, 5, fee_rate).unwrap();

    assert_eq!(fee1, fee2, "Same inputs should produce same output");
}

pub fn test_calculate_op_return_fee_per_participant_round_up_ensures_coverage() {
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    // Total = 890 sats
    // With 7 participants: 890 / 7 = 127.14 -> rounds up to 128
    // 128 * 7 = 896 >= 890 (covers the full fee)
    let fee = calculate_op_return_fee_per_participant(true, 7, fee_rate).unwrap();
    let total_collected = fee * 7;

    assert!(
        total_collected >= 890,
        "Round-up should ensure full coverage: {} * 7 = {} >= 890",
        fee,
        total_collected
    );
}

pub fn test_calculate_op_return_fee_per_participant_minimum_fee_rate() {
    let fee_rate = FeeRate::from_sat_per_vb(1).unwrap();

    let fee = calculate_op_return_fee_per_participant(true, 1, fee_rate).unwrap();

    // At 1 sat/vb, 89 vbytes = 89 sats
    assert_eq!(fee, 89, "At 1 sat/vb, fee should be 89 sats: got {}", fee);
}

pub fn test_calculate_op_return_fee_per_participant_high_fee_rate() {
    let fee_rate = FeeRate::from_sat_per_vb(500).unwrap();

    let fee = calculate_op_return_fee_per_participant(true, 1, fee_rate).unwrap();

    // At 500 sat/vb, 89 vbytes = 44,500 sats
    assert_eq!(
        fee, 44_500,
        "At 500 sat/vb, fee should be 44,500 sats: got {}",
        fee
    );
}

pub fn test_calculate_op_return_fee_per_participant_vsize_is_89_bytes() {
    // Verify the constant vsize calculation: 9 + MAX_OP_RETURN_BYTES (80) = 89
    let fee_rate = FeeRate::from_sat_per_vb(1).unwrap();

    let fee = calculate_op_return_fee_per_participant(true, 1, fee_rate).unwrap();

    // At 1 sat/vb, fee = vsize
    assert_eq!(fee, 89, "OP_RETURN vsize should be 89 bytes: got {}", fee);
}

pub fn test_calculate_op_return_fee_per_participant_large_participant_count() {
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    // With 1000 participants, each should pay very little
    let fee = calculate_op_return_fee_per_participant(true, 1000, fee_rate).unwrap();

    // Total = 890, split 1000 ways = 0.89 -> rounds up to 1
    assert_eq!(
        fee, 1,
        "1000 participants should each pay 1 sat: got {}",
        fee
    );
}

pub fn test_calculate_op_return_fee_per_participant_exact_division() {
    // Find a case where division is exact
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    // Total = 890 sats
    // 890 / 2 = 445 (exact)
    let fee = calculate_op_return_fee_per_participant(true, 2, fee_rate).unwrap();

    assert_eq!(fee, 445, "Exact division should work: got {}", fee);

    // Verify: 445 * 2 = 890 (exactly covers)
    assert_eq!(fee * 2, 890, "Should exactly cover the fee");
}
