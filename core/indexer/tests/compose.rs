use anyhow::Result;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{FeeRate, TapSighashType};
use bitcoin::{OutPoint, consensus::encode::serialize as serialize_tx, key::Secp256k1};
use indexer::api::compose::{RevealInputs, RevealParticipantInputs, compose, compose_reveal};

use bitcoin::Psbt;
use indexer::api::compose::{ComposeInputs, InstructionInputs};
use indexer::test_utils;
use indexer::witness_data::TokenBalance;
use indexer_types::{OpReturnData, serialize};

use testlib::*;
use tracing::info;

mod compose_tests;

use compose_tests::commit_reveal::test_commit_reveal;
use compose_tests::commit_reveal_random_keypair::test_commit_reveal_ordinals;
use compose_tests::compose_api::{
    test_compose, test_compose_all_fields, test_compose_duplicate_address_and_duplicate_utxo,
    test_compose_insufficient_funds, test_compose_invalid_address, test_compose_missing_params,
    test_compose_nonexistent_utxo, test_compose_param_bounds_and_fee_rate,
    test_reveal_with_op_return_mempool_accept,
};
use compose_tests::compose_commit_unit::{
    test_compose_commit_psbt_inputs_have_metadata,
    test_compose_commit_unique_vout_mapping_even_with_identical_chunks,
};
use compose_tests::compose_helpers::{
    test_build_tap_script_address_type_is_p2tr,
    test_build_tap_script_and_script_address_empty_data_errs,
    test_build_tap_script_and_script_address_multi_push_and_structure,
    test_build_tap_script_chunk_boundaries_push_count,
    test_calculate_op_return_fee_per_participant_deterministic,
    test_calculate_op_return_fee_per_participant_exact_division,
    test_calculate_op_return_fee_per_participant_fee_rate_scaling,
    test_calculate_op_return_fee_per_participant_high_fee_rate,
    test_calculate_op_return_fee_per_participant_large_participant_count,
    test_calculate_op_return_fee_per_participant_many_participants,
    test_calculate_op_return_fee_per_participant_minimum_fee_rate,
    test_calculate_op_return_fee_per_participant_no_op_return,
    test_calculate_op_return_fee_per_participant_round_up_ensures_coverage,
    test_calculate_op_return_fee_per_participant_single_participant,
    test_calculate_op_return_fee_per_participant_three_participants_rounds_up,
    test_calculate_op_return_fee_per_participant_two_participants,
    test_calculate_op_return_fee_per_participant_vsize_is_89_bytes,
    test_calculate_op_return_fee_per_participant_zero_participants,
    test_calculate_reveal_fee_delta_chained_adds_output_fee,
    test_calculate_reveal_fee_delta_deterministic,
    test_calculate_reveal_fee_delta_envelope_does_not_affect_fee,
    test_calculate_reveal_fee_delta_fee_rate_scaling,
    test_calculate_reveal_fee_delta_high_fee_rate,
    test_calculate_reveal_fee_delta_larger_control_block_higher_fee,
    test_calculate_reveal_fee_delta_larger_script_higher_fee,
    test_calculate_reveal_fee_delta_minimum_fee_rate,
    test_calculate_reveal_fee_delta_modifies_dummy_tx,
    test_calculate_reveal_fee_delta_multiple_participants_sequential,
    test_calculate_reveal_fee_delta_single_participant_no_chained,
    test_calculate_reveal_fee_delta_single_participant_with_chained,
    test_calculate_reveal_fee_delta_very_large_script,
    test_calculate_reveal_fee_delta_with_real_tap_script,
    test_calculate_reveal_fee_delta_witness_structure,
    test_compose_reveal_op_return_size_validation, test_estimate_key_spend_fee_deterministic,
    test_estimate_key_spend_fee_does_not_modify_original_tx, test_estimate_key_spend_fee_empty_tx,
    test_estimate_key_spend_fee_fee_rate_scaling, test_estimate_key_spend_fee_high_fee_rate,
    test_estimate_key_spend_fee_many_inputs, test_estimate_key_spend_fee_minimum_fee_rate,
    test_estimate_key_spend_fee_more_outputs_higher_fee,
    test_estimate_key_spend_fee_multiple_inputs_scales_linearly,
    test_estimate_key_spend_fee_overwrites_existing_witness,
    test_estimate_key_spend_fee_signature_size_is_64_bytes,
    test_estimate_key_spend_fee_single_input, test_estimate_key_spend_fee_with_real_commit_tx,
    test_estimate_participant_commit_fees_change_output_difference,
    test_estimate_participant_commit_fees_deterministic,
    test_estimate_participant_commit_fees_does_not_modify_base_tx,
    test_estimate_participant_commit_fees_empty_utxos,
    test_estimate_participant_commit_fees_fee_rate_scaling,
    test_estimate_participant_commit_fees_high_fee_rate,
    test_estimate_participant_commit_fees_input_vsize_delta,
    test_estimate_participant_commit_fees_many_utxos,
    test_estimate_participant_commit_fees_minimum_fee_rate,
    test_estimate_participant_commit_fees_multiple_utxos,
    test_estimate_participant_commit_fees_output_vsize,
    test_estimate_participant_commit_fees_single_utxo,
    test_estimate_participant_commit_fees_with_existing_base_tx,
    test_estimate_participant_commit_fees_with_real_utxos,
    test_select_utxos_for_commit_change_above_dust, test_select_utxos_for_commit_change_below_dust,
    test_select_utxos_for_commit_deterministic,
    test_select_utxos_for_commit_edge_case_change_equals_envelope,
    test_select_utxos_for_commit_empty_utxos_errors,
    test_select_utxos_for_commit_envelope_affects_change_threshold,
    test_select_utxos_for_commit_exact_amount_no_change,
    test_select_utxos_for_commit_fee_rate_affects_selection,
    test_select_utxos_for_commit_insufficient_with_fees,
    test_select_utxos_for_commit_many_small_utxos,
    test_select_utxos_for_commit_multiple_utxos_selects_minimum,
    test_select_utxos_for_commit_returns_correct_subset,
    test_select_utxos_for_commit_script_output_value_affects_selection,
    test_select_utxos_for_commit_selects_in_order,
    test_select_utxos_for_commit_single_utxo_insufficient,
    test_select_utxos_for_commit_single_utxo_sufficient,
    test_select_utxos_for_commit_with_existing_base_tx,
    test_select_utxos_for_commit_with_real_utxo,
};
use compose_tests::legacy_commit_reveal_p2wsh::test_legacy_commit_reveal_p2wsh;
use compose_tests::legacy_segwit_envelope::{
    test_legacy_segwit_envelope_psbt_inscription,
    test_legacy_segwit_psbt_inscription_invalid_token_data,
    test_legacy_segwit_psbt_inscription_with_wrong_internal_key_without_checksig,
    test_legacy_segwit_psbt_inscription_without_checksig,
    test_legacy_segwit_psbt_inscription_wrong_internal_key,
};
use compose_tests::legacy_segwit_swap::{
    test_legacy_segwit_swap_psbt_with_incorrect_prefix,
    test_legacy_segwit_swap_psbt_with_insufficient_funds,
    test_legacy_segwit_swap_psbt_with_long_witness_stack,
    test_legacy_segwit_swap_psbt_with_malformed_witness_script,
    test_legacy_segwit_swap_psbt_with_secret, test_legacy_segwit_swap_psbt_with_wrong_token_name,
    test_legacy_segwit_swap_psbt_without_prefix, test_legacy_segwit_swap_psbt_without_secret,
    test_legacy_segwit_swap_psbt_without_token_balance,
};
use compose_tests::legacy_taproot_envelope::{
    test_legacy_taproot_envelope_psbt_inscription,
    test_legacy_taproot_inscription_with_wrong_internal_key_without_checksig,
    test_legacy_taproot_inscription_without_checksig,
    test_legacy_taproot_inscription_wrong_internal_key,
    test_legacy_tapscript_inscription_invalid_token_data,
};
use compose_tests::legacy_taproot_swap::{
    test_legacy_taproot_swap, test_taproot_swap_psbt_with_incorrect_prefix,
    test_taproot_swap_with_long_witness_stack, test_taproot_swap_with_wrong_token,
    test_taproot_swap_with_wrong_token_amount, test_taproot_swap_without_control_block,
    test_taproot_swap_without_tapscript, test_taproot_swap_without_token_balance,
};
use compose_tests::multi_psbt_integration::test_portal_coordinated_commit_reveal_flow_integration;
use compose_tests::multi_psbt_integration_breakdown::test_portal_coordinated_compose_flow;
use compose_tests::multi_psbt_security::{
    test_async_node_sign_and_merge_flows, test_commit_outputs_whitelist_including_portal,
    test_commit_psbt_security_invariants,
    test_commit_shortfall_is_offset_by_reveal_surplus_after_signing, test_inputs_sequences_are_rbf,
    test_portal_reveal_fairness_base_plus_witness, test_pre_sign_estimated_commit_fee_is_covered,
    test_psbt_hygiene_and_witness_utxo_presence, test_reveal_outputs_whitelist_and_counts,
    test_reveal_psbt_security_invariants, test_script_address_hrp_across_networks,
    test_script_address_hrp_matches_network,
    test_script_output_funds_dust_plus_reveal_fee_estimate,
    test_sighash_default_encoding_for_signatures,
    test_tap_internal_key_set_on_commit_and_reveal_inputs,
    test_tapscript_builder_rejects_empty_data,
    test_tapscript_prefix_structure_pubkey_then_op_checksig,
    test_witness_stack_shapes_commit_and_reveal,
};
use compose_tests::multi_psbt_tx_validation::{
    test_node_cannot_steal_in_reveal_rejected, test_portal_cannot_steal_change_rejected,
    test_portal_reorders_commit_inputs_before_sign_rejected,
    test_pre_sign_node_refuses_on_reveal_output_remap,
    test_pre_sign_node_refuses_on_underfunded_script_output,
    test_reordering_commit_inputs_rejected, test_reordering_commit_outputs_rejected,
};
use compose_tests::regtest_commit_reveal::test_taproot_transaction_regtest;
use compose_tests::signature_replay_fails::{
    test_psbt_signature_replay_fails, test_signature_replay_fails,
};
use compose_tests::size_limit::test_compose_progressive_size_limit_testnet;
use compose_tests::swap::test_swap_psbt;

use crate::compose_tests::compose_api::test_compose_attach_and_detach;
use crate::compose_tests::swap::test_swap_integrity;

async fn test_commit_reveal_chained_reveal(reg_tester: &mut RegTester) -> Result<()> {
    info!("test_commit_reveal_chained_reveal");
    let secp = Secp256k1::new();

    let identity = reg_tester.identity().await?;
    let seller_address = identity.address;
    let keypair = identity.keypair;
    let (internal_key, _parity) = keypair.x_only_public_key();
    let (out_point, utxo_for_output) = identity.next_funding_utxo;

    // Create token balance data
    let token_value = 1000;
    let token_balance = TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let serialized_token_balance = serialize(&token_balance)?;

    let compose_params = ComposeInputs::builder()
        .instructions(vec![InstructionInputs {
            address: seller_address.clone(),
            x_only_public_key: internal_key,
            funding_utxos: vec![(out_point, utxo_for_output.clone())],
            instruction: b"Hello, world!".to_vec(),
            chained_instruction: Some(serialized_token_balance.clone()),
        }])
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .envelope(546)
        .build();

    let compose_outputs = compose(compose_params)?;

    let mut commit_tx = compose_outputs.commit_transaction;
    let tap_script = compose_outputs.per_participant[0]
        .commit_tap_leaf_script
        .script
        .clone();
    let mut reveal_tx = compose_outputs.reveal_transaction;
    let chained_tap_script = compose_outputs.per_participant[0]
        .chained_tap_leaf_script
        .as_ref()
        .unwrap()
        .script
        .clone();

    let transfer_data = OpReturnData::PubKey(internal_key);
    let transfer_bytes = serialize(&transfer_data)?;

    let chained_reveal_tx = compose_reveal(
        RevealInputs::builder()
            .commit_tx(reveal_tx.clone())
            .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
            .participants(vec![
                RevealParticipantInputs::builder()
                    .address(seller_address.clone())
                    .x_only_public_key(internal_key)
                    .commit_outpoint(OutPoint {
                        txid: reveal_tx.compute_txid(),
                        vout: 0,
                    })
                    .commit_prevout(reveal_tx.output[0].clone())
                    .commit_tap_leaf_script(
                        compose_outputs.per_participant[0]
                            .chained_tap_leaf_script
                            .as_ref()
                            .unwrap()
                            .clone(),
                    )
                    .build(),
            ])
            .envelope(546)
            .op_return_data(transfer_bytes)
            .build(),
    )?;

    // 1. SIGN THE ORIGINAL COMMIT
    test_utils::sign_key_spend(
        &secp,
        &mut commit_tx,
        &[utxo_for_output],
        &keypair,
        0,
        Some(TapSighashType::All),
    )?;

    let spend_tx_prevouts = vec![commit_tx.output[0].clone()];

    // 2. SIGN THE REVEAL

    // sign the script_spend input for the reveal transaction
    let reveal_taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, internal_key)
        .expect("Failed to finalize Taproot tree");

    test_utils::sign_script_spend(
        &secp,
        &reveal_taproot_spend_info,
        &tap_script,
        &mut reveal_tx,
        &spend_tx_prevouts,
        &keypair,
        0,
    )?;

    let mut chained_reveal_tx = chained_reveal_tx.transaction;

    // 3. SIGN THE CHAINED REVEAL
    let reveal_tx_prevouts = vec![reveal_tx.output[0].clone()];

    // sign the script_spend input for the chained reveal transaction
    let chained_taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, chained_tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, internal_key)
        .expect("Failed to finalize Taproot tree");

    test_utils::sign_script_spend(
        &secp,
        &chained_taproot_spend_info,
        &chained_tap_script,
        &mut chained_reveal_tx,
        &reveal_tx_prevouts,
        &keypair,
        0,
    )?;
    println!("commit_tx:!!!!!!!!!!!!!!!!!!!!!!!!!!! {:#?}", commit_tx);
    println!("reveal_tx:!!!!!!!!!!!!!!!!!!!!!!!!!!! {:#?}", reveal_tx);
    println!(
        "chained_reveal_tx:!!!!!!!!!!!!!!!!!!!!!!!!!!! {:#?}",
        chained_reveal_tx
    );

    let commit_tx_hex = hex::encode(serialize_tx(&commit_tx));
    let reveal_tx_hex = hex::encode(serialize_tx(&reveal_tx));
    let chained_reveal_tx_hex = hex::encode(serialize_tx(&chained_reveal_tx));

    let result = reg_tester
        .mempool_accept_result(&[commit_tx_hex, reveal_tx_hex, chained_reveal_tx_hex])
        .await?;

    assert_eq!(
        result.len(),
        3,
        "Expected exactly three transaction results"
    );

    println!("result:!!!!!!!!!!!!!!!!!!!!!!!!!!! {:#?}", result);

    assert!(
        result[0].allowed,
        "Commit transaction was rejected: {:?}",
        result[0].reject_reason
    );
    assert!(
        result[1].allowed,
        "Reveal transaction was rejected: {:?}",
        result[1].reject_reason
    );
    assert!(
        result[2].allowed,
        "Chained reveal transaction was rejected: {:?}",
        result[2].reject_reason
    );

    Ok(())
}

async fn test_compose_end_to_end_mapping_and_reveal_psbt_hex_decodes(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_compose_end_to_end_mapping_and_reveal_psbt_hex_decodes");
    let (nodes, _secrets) =
        indexer::multi_psbt_test_utils::get_node_addresses(&mut reg_tester.clone()).await?;

    let mut instructions = Vec::new();
    for n in nodes.iter() {
        let instruction = indexer::api::compose::InstructionInputs::builder()
            .address(n.address.clone())
            .x_only_public_key(n.internal_key)
            .funding_utxos(vec![(n.next_funding_utxo.clone())])
            .instruction(b"hello-world".to_vec())
            .build();
        instructions.push(instruction);
    }

    let params = ComposeInputs::builder()
        .instructions(instructions.clone())
        .fee_rate(bitcoin::FeeRate::from_sat_per_vb(2).unwrap())
        .envelope(600)
        .build();

    let outputs = compose(params)?;

    assert_eq!(outputs.per_participant.len(), instructions.len());
    for (i, p) in outputs.per_participant.iter().enumerate() {
        assert_eq!(p.address, instructions[i].address.to_string());
        assert_eq!(
            p.x_only_public_key,
            instructions[i].x_only_public_key.to_string()
        );
    }

    // Decode PSBTs
    let commit_psbt: Psbt = Psbt::deserialize(&hex::decode(&outputs.commit_psbt_hex)?)?;
    let reveal_psbt: Psbt = Psbt::deserialize(&hex::decode(&outputs.reveal_psbt_hex)?)?;

    // Txids match between PSBTs and returned transactions
    assert_eq!(
        commit_psbt.unsigned_tx.compute_txid(),
        outputs.commit_transaction.compute_txid()
    );
    assert_eq!(
        reveal_psbt.unsigned_tx.compute_txid(),
        outputs.reveal_transaction.compute_txid()
    );

    // Inputs/outputs counts are consistent
    assert_eq!(
        commit_psbt.inputs.len(),
        outputs.commit_transaction.input.len()
    );
    assert_eq!(
        commit_psbt.outputs.len(),
        outputs.commit_transaction.output.len()
    );
    assert_eq!(
        reveal_psbt.inputs.len(),
        outputs.reveal_transaction.input.len()
    );
    assert_eq!(
        reveal_psbt.outputs.len(),
        outputs.reveal_transaction.output.len()
    );

    // Required PSBT metadata is present
    assert!(commit_psbt.inputs.iter().all(|i| i.witness_utxo.is_some()));
    assert!(
        commit_psbt
            .inputs
            .iter()
            .all(|i| i.tap_internal_key.is_some())
    );
    assert!(reveal_psbt.inputs.iter().all(|i| i.witness_utxo.is_some()));
    assert!(
        reveal_psbt
            .inputs
            .iter()
            .all(|i| i.tap_internal_key.is_some())
    );

    Ok(())
}

#[testlib::test(contracts_dir = "test-contracts", mode = "regtest")]
async fn test_compose_regtest() -> Result<()> {
    test_commit_reveal_chained_reveal(&mut reg_tester.clone()).await?;
    test_compose_end_to_end_mapping_and_reveal_psbt_hex_decodes(&mut reg_tester.clone()).await?;

    info!("commit_reveal_random_keypair");
    test_commit_reveal_ordinals(&mut reg_tester.clone()).await?;

    info!("commit_reveal");
    test_commit_reveal(&mut reg_tester.clone()).await?;

    info!("compose_commit_unit");
    test_compose_commit_unique_vout_mapping_even_with_identical_chunks(&mut reg_tester.clone())
        .await?;
    test_compose_commit_psbt_inputs_have_metadata(&mut reg_tester.clone()).await?;

    info!("compose_helpers");
    test_build_tap_script_and_script_address_empty_data_errs(&mut reg_tester.clone()).await?;
    test_build_tap_script_and_script_address_multi_push_and_structure(&mut reg_tester.clone())
        .await?;
    test_build_tap_script_address_type_is_p2tr(&mut reg_tester.clone()).await?;
    test_compose_reveal_op_return_size_validation(&mut reg_tester.clone()).await?;
    test_build_tap_script_chunk_boundaries_push_count(&mut reg_tester.clone()).await?;

    info!("estimate_key_spend_fee");
    test_estimate_key_spend_fee_empty_tx();
    test_estimate_key_spend_fee_single_input();
    test_estimate_key_spend_fee_multiple_inputs_scales_linearly();
    test_estimate_key_spend_fee_fee_rate_scaling();
    test_estimate_key_spend_fee_more_outputs_higher_fee();
    test_estimate_key_spend_fee_deterministic();
    test_estimate_key_spend_fee_overwrites_existing_witness();
    test_estimate_key_spend_fee_does_not_modify_original_tx();
    test_estimate_key_spend_fee_minimum_fee_rate();
    test_estimate_key_spend_fee_high_fee_rate();
    test_estimate_key_spend_fee_many_inputs();
    test_estimate_key_spend_fee_signature_size_is_64_bytes();
    test_estimate_key_spend_fee_with_real_commit_tx(&mut reg_tester.clone()).await?;

    info!("estimate_participant_commit_fees");
    test_estimate_participant_commit_fees_empty_utxos();
    test_estimate_participant_commit_fees_single_utxo();
    test_estimate_participant_commit_fees_multiple_utxos();
    test_estimate_participant_commit_fees_fee_rate_scaling();
    test_estimate_participant_commit_fees_with_existing_base_tx();
    test_estimate_participant_commit_fees_deterministic();
    test_estimate_participant_commit_fees_does_not_modify_base_tx();
    test_estimate_participant_commit_fees_minimum_fee_rate();
    test_estimate_participant_commit_fees_high_fee_rate();
    test_estimate_participant_commit_fees_many_utxos();
    test_estimate_participant_commit_fees_change_output_difference();
    test_estimate_participant_commit_fees_input_vsize_delta();
    test_estimate_participant_commit_fees_output_vsize();
    test_estimate_participant_commit_fees_with_real_utxos(&mut reg_tester.clone()).await?;

    info!("select_utxos_for_commit");
    test_select_utxos_for_commit_empty_utxos_errors();
    test_select_utxos_for_commit_single_utxo_sufficient();
    test_select_utxos_for_commit_single_utxo_insufficient();
    test_select_utxos_for_commit_multiple_utxos_selects_minimum();
    test_select_utxos_for_commit_selects_in_order();
    test_select_utxos_for_commit_change_above_dust();
    test_select_utxos_for_commit_change_below_dust();
    test_select_utxos_for_commit_fee_rate_affects_selection();
    test_select_utxos_for_commit_script_output_value_affects_selection();
    test_select_utxos_for_commit_with_existing_base_tx();
    test_select_utxos_for_commit_returns_correct_subset();
    test_select_utxos_for_commit_exact_amount_no_change();
    test_select_utxos_for_commit_many_small_utxos();
    test_select_utxos_for_commit_envelope_affects_change_threshold();
    test_select_utxos_for_commit_deterministic();
    test_select_utxos_for_commit_insufficient_with_fees();
    test_select_utxos_for_commit_edge_case_change_equals_envelope();
    test_select_utxos_for_commit_with_real_utxo(&mut reg_tester.clone()).await?;

    info!("calculate_reveal_fee_delta");
    test_calculate_reveal_fee_delta_single_participant_no_chained();
    test_calculate_reveal_fee_delta_single_participant_with_chained();
    test_calculate_reveal_fee_delta_chained_adds_output_fee();
    test_calculate_reveal_fee_delta_fee_rate_scaling();
    test_calculate_reveal_fee_delta_larger_script_higher_fee();
    test_calculate_reveal_fee_delta_larger_control_block_higher_fee();
    test_calculate_reveal_fee_delta_envelope_does_not_affect_fee();
    test_calculate_reveal_fee_delta_modifies_dummy_tx();
    test_calculate_reveal_fee_delta_multiple_participants_sequential();
    test_calculate_reveal_fee_delta_deterministic();
    test_calculate_reveal_fee_delta_minimum_fee_rate();
    test_calculate_reveal_fee_delta_high_fee_rate();
    test_calculate_reveal_fee_delta_very_large_script();
    test_calculate_reveal_fee_delta_witness_structure();
    test_calculate_reveal_fee_delta_with_real_tap_script(&mut reg_tester.clone()).await?;

    info!("calculate_op_return_fee_per_participant");
    test_calculate_op_return_fee_per_participant_no_op_return();
    test_calculate_op_return_fee_per_participant_zero_participants();
    test_calculate_op_return_fee_per_participant_single_participant();
    test_calculate_op_return_fee_per_participant_two_participants();
    test_calculate_op_return_fee_per_participant_three_participants_rounds_up();
    test_calculate_op_return_fee_per_participant_many_participants();
    test_calculate_op_return_fee_per_participant_fee_rate_scaling();
    test_calculate_op_return_fee_per_participant_deterministic();
    test_calculate_op_return_fee_per_participant_round_up_ensures_coverage();
    test_calculate_op_return_fee_per_participant_minimum_fee_rate();
    test_calculate_op_return_fee_per_participant_high_fee_rate();
    test_calculate_op_return_fee_per_participant_vsize_is_89_bytes();
    test_calculate_op_return_fee_per_participant_large_participant_count();
    test_calculate_op_return_fee_per_participant_exact_division();

    info!("legacy_taproot_envelope");
    test_legacy_taproot_envelope_psbt_inscription(&mut reg_tester.clone()).await?;
    test_legacy_taproot_inscription_without_checksig(&mut reg_tester.clone()).await?;
    test_legacy_taproot_inscription_with_wrong_internal_key_without_checksig(
        &mut reg_tester.clone(),
    )
    .await?;
    test_legacy_taproot_inscription_wrong_internal_key(&mut reg_tester.clone()).await?;
    test_legacy_tapscript_inscription_invalid_token_data(&mut reg_tester.clone()).await?;

    info!("legacy_taproot_swap");
    test_legacy_taproot_swap(&mut reg_tester.clone()).await?;
    test_taproot_swap_without_tapscript(&mut reg_tester.clone()).await?;
    test_taproot_swap_without_control_block(&mut reg_tester.clone()).await?;
    test_taproot_swap_with_long_witness_stack(&mut reg_tester.clone()).await?;
    test_taproot_swap_psbt_with_incorrect_prefix(&mut reg_tester.clone()).await?;
    test_taproot_swap_with_wrong_token_amount(&mut reg_tester.clone()).await?;
    test_taproot_swap_without_token_balance(&mut reg_tester.clone()).await?;
    test_taproot_swap_with_wrong_token(&mut reg_tester.clone()).await?;

    info!("multi_psbt_integration_breakdown");
    test_portal_coordinated_compose_flow(&mut reg_tester.clone()).await?;
    test_portal_coordinated_commit_reveal_flow_integration(&mut reg_tester.clone()).await?;

    info!("multi_psbt_security");
    test_commit_psbt_security_invariants(&mut reg_tester.clone()).await?;
    test_reveal_psbt_security_invariants(&mut reg_tester.clone()).await?;
    test_inputs_sequences_are_rbf(&mut reg_tester.clone()).await?;
    test_commit_outputs_whitelist_including_portal(&mut reg_tester.clone()).await?;
    test_script_address_hrp_matches_network(&mut reg_tester.clone()).await?;
    test_portal_reveal_fairness_base_plus_witness(&mut reg_tester.clone()).await?;
    test_psbt_hygiene_and_witness_utxo_presence(&mut reg_tester.clone()).await?;
    test_tapscript_prefix_structure_pubkey_then_op_checksig(&mut reg_tester.clone()).await?;
    test_tapscript_builder_rejects_empty_data(&mut reg_tester.clone()).await?;
    test_async_node_sign_and_merge_flows(&mut reg_tester.clone()).await?;
    test_sighash_default_encoding_for_signatures(&mut reg_tester.clone()).await?;
    test_reveal_outputs_whitelist_and_counts(&mut reg_tester.clone()).await?;
    test_script_output_funds_dust_plus_reveal_fee_estimate(&mut reg_tester.clone()).await?;
    test_pre_sign_estimated_commit_fee_is_covered(&mut reg_tester.clone()).await?;
    test_commit_shortfall_is_offset_by_reveal_surplus_after_signing(&mut reg_tester.clone())
        .await?;
    test_tap_internal_key_set_on_commit_and_reveal_inputs(&mut reg_tester.clone()).await?;
    test_witness_stack_shapes_commit_and_reveal(&mut reg_tester.clone()).await?;
    test_script_address_hrp_across_networks(&mut reg_tester.clone()).await?;

    info!("multi_psbt_tx_validation");
    test_pre_sign_node_refuses_on_underfunded_script_output(&mut reg_tester.clone()).await?;
    test_pre_sign_node_refuses_on_reveal_output_remap(&mut reg_tester.clone()).await?;
    test_reordering_commit_inputs_rejected(&mut reg_tester.clone()).await?;
    test_reordering_commit_outputs_rejected(&mut reg_tester.clone()).await?;
    test_portal_cannot_steal_change_rejected(&mut reg_tester.clone()).await?;
    test_node_cannot_steal_in_reveal_rejected(&mut reg_tester.clone()).await?;
    test_portal_reorders_commit_inputs_before_sign_rejected(&mut reg_tester.clone()).await?;

    info!("regtest_commit_reveal");
    test_taproot_transaction_regtest(&mut reg_tester.clone()).await?;

    info!("size_limit");
    test_compose_progressive_size_limit_testnet(&mut reg_tester.clone()).await?;

    info!("swap");
    test_swap_psbt(&mut reg_tester.clone()).await?;
    test_swap_integrity(&mut reg_tester.clone()).await?;

    info!("legacy_commit_reveal_p2wsh");
    test_legacy_commit_reveal_p2wsh(&mut reg_tester.clone()).await?;

    info!("legacy_segwit_envelope");
    test_legacy_segwit_envelope_psbt_inscription(&mut reg_tester.clone()).await?;
    test_legacy_segwit_psbt_inscription_invalid_token_data(&mut reg_tester.clone()).await?;
    test_legacy_segwit_psbt_inscription_wrong_internal_key(&mut reg_tester.clone()).await?;
    test_legacy_segwit_psbt_inscription_without_checksig(&mut reg_tester.clone()).await?;
    test_legacy_segwit_psbt_inscription_with_wrong_internal_key_without_checksig(
        &mut reg_tester.clone(),
    )
    .await?;

    info!("legacy_segwit_swap");
    test_legacy_segwit_swap_psbt_with_secret(&mut reg_tester.clone()).await?;
    test_legacy_segwit_swap_psbt_without_secret(&mut reg_tester.clone()).await?;
    test_legacy_segwit_swap_psbt_with_secret(&mut reg_tester.clone()).await?;
    test_legacy_segwit_swap_psbt_with_long_witness_stack(&mut reg_tester.clone()).await?;
    test_legacy_segwit_swap_psbt_with_wrong_token_name(&mut reg_tester.clone()).await?;
    test_legacy_segwit_swap_psbt_with_malformed_witness_script(&mut reg_tester.clone()).await?;
    test_legacy_segwit_swap_psbt_without_token_balance(&mut reg_tester.clone()).await?;
    test_legacy_segwit_swap_psbt_without_prefix(&mut reg_tester.clone()).await?;
    test_legacy_segwit_swap_psbt_with_incorrect_prefix(&mut reg_tester.clone()).await?;
    test_legacy_segwit_swap_psbt_with_insufficient_funds(&mut reg_tester.clone()).await?;

    info!("signature_replay_fails");
    test_signature_replay_fails(&mut reg_tester.clone()).await?;
    test_psbt_signature_replay_fails(&mut reg_tester.clone()).await?;

    info!("compose_api");
    test_compose(&mut reg_tester.clone()).await?;
    test_compose_all_fields(&mut reg_tester.clone()).await?;
    test_compose_nonexistent_utxo(&mut reg_tester.clone()).await?;
    test_compose_invalid_address(&mut reg_tester.clone()).await?;
    test_compose_insufficient_funds(&mut reg_tester.clone()).await?;
    test_compose_missing_params(&mut reg_tester.clone()).await?;
    test_compose_duplicate_address_and_duplicate_utxo(&mut reg_tester.clone()).await?;
    test_compose_param_bounds_and_fee_rate(&mut reg_tester.clone()).await?;
    test_reveal_with_op_return_mempool_accept(&mut reg_tester.clone()).await?;
    test_compose_attach_and_detach(&mut reg_tester.clone()).await?;

    Ok(())
}
