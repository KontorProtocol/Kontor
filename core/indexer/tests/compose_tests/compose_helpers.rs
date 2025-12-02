use anyhow::Result;
use bitcoin::absolute::LockTime;
use bitcoin::script::Instruction;
use bitcoin::taproot::LeafVersion;
use bitcoin::transaction::{Transaction, TxIn, TxOut, Version};
use bitcoin::{Amount, FeeRate, OutPoint, ScriptBuf, Txid};
use indexer::api::compose::{
    RevealFeeEstimateInput, RevealInputs, RevealParticipantInputs, TapLeafScript, TapScriptPair,
    build_tap_script_and_script_address, compose_reveal, estimate_key_spend_fee,
    estimate_reveal_fees_delta,
};
use std::str::FromStr;
use testlib::RegTester;
use tracing::info;

// ============================================================================
// estimate_reveal_fees_delta tests
// ============================================================================

/// Helper to create a RevealFeeEstimateInput with a dummy tap script of given size.
fn make_reveal_fee_input(script_size: usize, has_chained: bool) -> RevealFeeEstimateInput {
    // Create a dummy script of the specified size
    let tap_script = ScriptBuf::from_bytes(vec![0u8; script_size]);
    // Control block is typically 33 bytes (1 byte leaf version + 32 bytes internal key)
    let control_block_bytes = vec![0u8; 33];
    RevealFeeEstimateInput {
        tap_script,
        control_block_bytes,
        has_chained,
    }
}

/// Helper to create a RevealFeeEstimateInput with realistic tap script from actual data.
fn make_realistic_reveal_fee_input(
    xonly: bitcoin::secp256k1::XOnlyPublicKey,
    data: Vec<u8>,
    has_chained: bool,
) -> RevealFeeEstimateInput {
    let (tap_script, _, _, control_block) =
        build_tap_script_and_script_address(xonly, data).expect("build tapscript");
    RevealFeeEstimateInput {
        tap_script,
        control_block_bytes: control_block.serialize(),
        has_chained,
    }
}

pub fn test_estimate_reveal_fees_delta_empty_participants_returns_empty() {
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let result = estimate_reveal_fees_delta(&[], fee_rate, false, 330).unwrap();
    assert!(
        result.is_empty(),
        "Empty participants should return empty fees"
    );
}

pub fn test_estimate_reveal_fees_delta_single_participant_returns_single_fee() {
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let input = make_reveal_fee_input(100, false);
    let result = estimate_reveal_fees_delta(&[input], fee_rate, false, 330).unwrap();

    assert_eq!(
        result.len(),
        1,
        "Single participant should return single fee"
    );
    assert!(result[0] > 0, "Fee should be non-zero");
}

pub fn test_estimate_reveal_fees_delta_fee_rate_scaling() {
    // Double fee rate should approximately double the fees
    let input = make_reveal_fee_input(100, false);

    let fee_rate_1 = FeeRate::from_sat_per_vb(5).unwrap();
    let fee_rate_2 = FeeRate::from_sat_per_vb(10).unwrap();

    let fees_1 = estimate_reveal_fees_delta(&[input.clone()], fee_rate_1, false, 330).unwrap();
    let fees_2 = estimate_reveal_fees_delta(&[input], fee_rate_2, false, 330).unwrap();

    // Fee at 10 sat/vb should be exactly 2x fee at 5 sat/vb
    assert_eq!(
        fees_2[0],
        fees_1[0] * 2,
        "Doubling fee rate should double the fee"
    );
}

pub fn test_estimate_reveal_fees_delta_larger_script_higher_fee() {
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let small_script = make_reveal_fee_input(50, false);
    let large_script = make_reveal_fee_input(500, false);

    let small_fees = estimate_reveal_fees_delta(&[small_script], fee_rate, false, 330).unwrap();
    let large_fees = estimate_reveal_fees_delta(&[large_script], fee_rate, false, 330).unwrap();

    assert!(
        large_fees[0] > small_fees[0],
        "Larger script should cost more: {} vs {}",
        large_fees[0],
        small_fees[0]
    );
}

pub fn test_estimate_reveal_fees_delta_chained_adds_output_fee() {
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let without_chained = make_reveal_fee_input(100, false);
    let with_chained = make_reveal_fee_input(100, true);

    let fees_without =
        estimate_reveal_fees_delta(&[without_chained], fee_rate, false, 330).unwrap();
    let fees_with = estimate_reveal_fees_delta(&[with_chained], fee_rate, false, 330).unwrap();

    assert!(
        fees_with[0] > fees_without[0],
        "Chained output should increase fee: {} vs {}",
        fees_with[0],
        fees_without[0]
    );

    // A P2TR output is 34 bytes, at 10 sat/vb that's 340 sats difference
    let difference = fees_with[0] - fees_without[0];
    assert!(
        difference >= 340,
        "Chained output should add at least 34 vbytes worth: diff={}",
        difference
    );
}

pub fn test_estimate_reveal_fees_delta_op_return_is_base_overhead() {
    // NOTE: The OP_RETURN is added to the dummy tx BEFORE measuring any participant's delta.
    // This means it's part of the base transaction overhead and NOT charged to any specific
    // participant in the per-participant fees. This is important to understand when using
    // this function - the OP_RETURN cost needs to be accounted for separately if needed.
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let input = make_reveal_fee_input(100, false);

    let fees_without_op_return =
        estimate_reveal_fees_delta(&[input.clone()], fee_rate, false, 330).unwrap();
    let fees_with_op_return = estimate_reveal_fees_delta(&[input], fee_rate, true, 330).unwrap();

    // Per-participant fees should be the same - OP_RETURN is base overhead
    assert_eq!(
        fees_with_op_return[0], fees_without_op_return[0],
        "OP_RETURN is base overhead, not charged to participant: {} vs {}",
        fees_with_op_return[0], fees_without_op_return[0]
    );
}

pub fn test_estimate_reveal_fees_delta_op_return_not_in_participant_fees() {
    // The OP_RETURN overhead is NOT included in any participant's fee.
    // It's added before vsize_before is measured for the first participant.
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let input1 = make_reveal_fee_input(100, false);
    let input2 = make_reveal_fee_input(100, false);

    // Without OP_RETURN
    let fees_no_op =
        estimate_reveal_fees_delta(&[input1.clone(), input2.clone()], fee_rate, false, 330)
            .unwrap();

    // With OP_RETURN
    let fees_with_op = estimate_reveal_fees_delta(&[input1, input2], fee_rate, true, 330).unwrap();

    // Both participants' fees should be the same regardless of OP_RETURN
    // because OP_RETURN is measured as part of "base" before any participant delta
    assert_eq!(
        fees_with_op[0], fees_no_op[0],
        "First participant fee should be same: {} vs {}",
        fees_with_op[0], fees_no_op[0]
    );
    assert_eq!(
        fees_with_op[1], fees_no_op[1],
        "Second participant fee should be same: {} vs {}",
        fees_with_op[1], fees_no_op[1]
    );
}

pub fn test_estimate_reveal_fees_delta_multiple_participants_independent_deltas() {
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    // Different sized scripts
    let small = make_reveal_fee_input(50, false);
    let medium = make_reveal_fee_input(200, false);
    let large = make_reveal_fee_input(500, false);

    let fees = estimate_reveal_fees_delta(&[small, medium, large], fee_rate, false, 330).unwrap();

    assert_eq!(fees.len(), 3);

    // Each participant pays for their own contribution
    // Since scripts are different sizes, fees should be different
    // Note: fees[0] includes base tx overhead, so it's higher than if we measured just the script
    assert!(fees[0] > 0);
    assert!(fees[1] > 0);
    assert!(fees[2] > 0);

    // Larger scripts should result in higher fees (but first includes base overhead)
    // Compare 2nd and 3rd which don't have base overhead
    assert!(
        fees[2] > fees[1],
        "Larger script participant should pay more: {} vs {}",
        fees[2],
        fees[1]
    );
}

pub fn test_estimate_reveal_fees_delta_deterministic() {
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let inputs = vec![
        make_reveal_fee_input(100, false),
        make_reveal_fee_input(200, true),
        make_reveal_fee_input(150, false),
    ];

    let fees1 = estimate_reveal_fees_delta(&inputs, fee_rate, true, 330).unwrap();
    let fees2 = estimate_reveal_fees_delta(&inputs, fee_rate, true, 330).unwrap();

    assert_eq!(fees1, fees2, "Same inputs should produce same outputs");
}

pub fn test_estimate_reveal_fees_delta_envelope_value_does_not_affect_fee() {
    // The envelope value is used for output values in the dummy tx, but shouldn't affect vsize
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let input = make_reveal_fee_input(100, false);

    let fees_small_envelope =
        estimate_reveal_fees_delta(&[input.clone()], fee_rate, false, 330).unwrap();
    let fees_large_envelope =
        estimate_reveal_fees_delta(&[input], fee_rate, false, 100_000).unwrap();

    assert_eq!(
        fees_small_envelope[0], fees_large_envelope[0],
        "Envelope value should not affect fee calculation"
    );
}

pub fn test_estimate_reveal_fees_delta_minimum_fee_rate() {
    // Test with minimum practical fee rate (1 sat/vb)
    let fee_rate = FeeRate::from_sat_per_vb(1).unwrap();
    let input = make_reveal_fee_input(100, false);

    let fees = estimate_reveal_fees_delta(&[input], fee_rate, false, 330).unwrap();

    assert!(fees[0] > 0, "Even at 1 sat/vb, fee should be non-zero");
}

pub fn test_estimate_reveal_fees_delta_high_fee_rate() {
    // Test with high fee rate (100 sat/vb)
    let fee_rate = FeeRate::from_sat_per_vb(100).unwrap();
    let input = make_reveal_fee_input(100, false);

    let fees = estimate_reveal_fees_delta(&[input], fee_rate, false, 330).unwrap();

    // At 100 sat/vb, even a small input should cost thousands of sats
    assert!(
        fees[0] > 1000,
        "High fee rate should result in high fees: {}",
        fees[0]
    );
}

pub fn test_estimate_reveal_fees_delta_mixed_chained_participants() {
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    let no_chain = make_reveal_fee_input(100, false);
    let with_chain = make_reveal_fee_input(100, true);

    let fees = estimate_reveal_fees_delta(
        &[no_chain.clone(), with_chain.clone()],
        fee_rate,
        false,
        330,
    )
    .unwrap();

    // The chained participant should pay more
    assert!(
        fees[1] > fees[0],
        "Chained participant should pay more: {} vs {}",
        fees[1],
        fees[0]
    );

    // Reversing order should swap which participant pays more
    let fees_reversed =
        estimate_reveal_fees_delta(&[with_chain, no_chain], fee_rate, false, 330).unwrap();

    assert!(
        fees_reversed[0] > fees_reversed[1],
        "First (chained) should pay more than second: {} vs {}",
        fees_reversed[0],
        fees_reversed[1]
    );
}

pub fn test_estimate_reveal_fees_delta_very_large_script() {
    // Test with a large script (close to max)
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();
    let large_input = make_reveal_fee_input(10_000, false); // 10KB script

    let fees = estimate_reveal_fees_delta(&[large_input], fee_rate, false, 330).unwrap();

    // 10KB script should cost significant fees
    // Witness data is discounted (1/4 weight), so ~2500 vbytes for 10KB
    // At 10 sat/vb, that's ~25,000 sats minimum
    assert!(
        fees[0] > 20_000,
        "Large script should have high fee: {}",
        fees[0]
    );
}

pub fn test_estimate_reveal_fees_delta_many_participants() {
    let fee_rate = FeeRate::from_sat_per_vb(5).unwrap();

    // 10 participants with varying script sizes
    let inputs: Vec<RevealFeeEstimateInput> = (0..10)
        .map(|i| make_reveal_fee_input(50 + i * 50, i % 2 == 0))
        .collect();

    let fees = estimate_reveal_fees_delta(&inputs, fee_rate, false, 330).unwrap();

    assert_eq!(fees.len(), 10, "Should have fee for each participant");

    // All fees should be non-zero
    for (i, fee) in fees.iter().enumerate() {
        assert!(*fee > 0, "Participant {} fee should be non-zero", i);
    }

    // Total fees should be reasonable (sum of individual contributions)
    let total: u64 = fees.iter().sum();
    assert!(
        total > fees[0],
        "Total fees should be more than first participant alone"
    );
}

pub fn test_estimate_reveal_fees_delta_control_block_size_matters() {
    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    // Same tap script but different control block sizes
    let tap_script = ScriptBuf::from_bytes(vec![0u8; 100]);

    let small_cb = RevealFeeEstimateInput {
        tap_script: tap_script.clone(),
        control_block_bytes: vec![0u8; 33], // Minimal control block
        has_chained: false,
    };

    let large_cb = RevealFeeEstimateInput {
        tap_script,
        control_block_bytes: vec![0u8; 65], // Larger control block (deeper tree)
        has_chained: false,
    };

    let fees_small = estimate_reveal_fees_delta(&[small_cb], fee_rate, false, 330).unwrap();
    let fees_large = estimate_reveal_fees_delta(&[large_cb], fee_rate, false, 330).unwrap();

    assert!(
        fees_large[0] > fees_small[0],
        "Larger control block should cost more: {} vs {}",
        fees_large[0],
        fees_small[0]
    );
}

/// Test with realistic tap scripts built from actual data
pub async fn test_estimate_reveal_fees_delta_with_realistic_scripts(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_estimate_reveal_fees_delta_with_realistic_scripts");
    let identity = reg_tester.identity().await?;
    let keypair = identity.keypair;
    let (xonly, _parity) = keypair.x_only_public_key();

    let fee_rate = FeeRate::from_sat_per_vb(10).unwrap();

    // Create realistic inputs with actual tap scripts
    let small_data = b"small".to_vec();
    let large_data = vec![0xABu8; 1000]; // 1KB data

    let small_input = make_realistic_reveal_fee_input(xonly, small_data, false);
    let large_input = make_realistic_reveal_fee_input(xonly, large_data, true);

    let fees = estimate_reveal_fees_delta(&[small_input, large_input], fee_rate, false, 330)?;

    assert_eq!(fees.len(), 2);
    assert!(fees[0] > 0);
    assert!(fees[1] > 0);

    // Large input with chained should cost significantly more
    assert!(
        fees[1] > fees[0],
        "Large chained input should cost more: {} vs {}",
        fees[1],
        fees[0]
    );

    Ok(())
}

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
    let diff = if delta_1_to_2 > delta_2_to_3 {
        delta_1_to_2 - delta_2_to_3
    } else {
        delta_2_to_3 - delta_1_to_2
    };
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
        fee >= 65 && fee <= 75,
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
    let (tap_script, tap_info, script_addr, _control_block) =
        build_tap_script_and_script_address(xonly, data.clone()).expect("build tapscript");
    // Control block should be derivable
    let _cb = tap_info
        .control_block(&(tap_script.clone(), LeafVersion::TapScript))
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
        let (tap_script, _info, _addr, _control_block) =
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
    let (_tap, _info, addr, _control_block) =
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
    let (tap_script, _tap_info, script_addr, control_block) =
        build_tap_script_and_script_address(xonly, commit_data.clone()).expect("build");
    let commit_prevout = bitcoin::TxOut {
        value: Amount::from_sat(10_000),
        script_pubkey: script_addr.script_pubkey(),
    };
    // Build TapScriptPair for the commit script data
    let commit_tap_script_pair = TapScriptPair {
        tap_leaf_script: TapLeafScript {
            leaf_version: LeafVersion::TapScript,
            script: tap_script,
            control_block: ScriptBuf::from_bytes(control_block.serialize()),
        },
        script_data_chunk: commit_data.clone(),
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
        .commit_tap_script_pair(commit_tap_script_pair)
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
