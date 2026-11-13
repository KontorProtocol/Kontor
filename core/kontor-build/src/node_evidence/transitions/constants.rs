pub(super) const TRANSITION_FLAGS: &[&str] = &[
    "bitcoin_follower_continuity",
    "http_rpc_continuity",
    "matching_closure_and_state",
    "reapplied_migration",
    "restored_p1_in_fresh_era",
    "retained_history_unchanged",
    "same_listeners",
];
pub(super) const JOIN_FLAGS: &[&str] = &[
    "matching_verified_prefix",
    "required_promoted_vote",
    "same_listener",
    "separate_wals",
    "source_already_p2",
    "stalled_without_quorum",
];
pub(super) const STATE_TABLES: &[&str] = &[
    "block_execution_usage",
    "blocks",
    "bls_keys",
    "contract_provenance",
    "contract_results",
    "contract_state",
    "contracts",
    "current_contract_state",
    "depositor_footprint",
    "nonces",
    "signers",
    "transaction_execution_usage",
    "transactions",
    "x_only_pubkeys",
];
pub(super) const BUILD_RECORD_FLAGS: &[&str] = &[
    "changed_bindings_rejected",
    "embedded_record_verified",
    "incomplete_graphs_rejected",
    "missing_record_rejected",
];
pub(super) const RECOVERY_FLAGS: &[&str] = &[
    "activation_write_failure_atomic",
    "actual_p2_migration",
    "invalid_input_rejected_after_reopen",
    "reopened_state_matches",
    "successor_gated_until_closure",
];
pub(super) const UNSUPPORTED_FLAGS: &[&str] = &[
    "bitcoin_progress_resumed",
    "old_protocol_preserved",
    "signed_cancel_certified",
    "unsupported_block_not_proposed",
    "unsupported_proposal_rejected",
];
pub(super) const CRASH_STAGES: &[&str] =
    &["certified", "activated", "closed", "engine-ready", "signed"];
pub(super) const CRASH_FLAGS: &[&str] = &[
    "certificate_preserved",
    "conflict_rejected",
    "process_killed",
    "state_matches",
    "successor_started",
];
pub(super) const EMPTY_SUCCESSOR_FLAGS: &[&str] = &[
    "activation_committed",
    "empty_successor_gated",
    "paid_exit_confirmed",
    "reopen_preserves_gate",
    "retained_certificate_unchanged",
];
pub(super) const COMMON_CONTRACT_FLAGS: &[&str] = &[
    "failed_call_consistent",
    "fixture_initialized",
    "common_token_schema_preserved",
    "gas_escrow_refunded",
    "migration_from_populated_p1",
    "paid_mint_transfer_burn",
    "reopened_state_matches",
    "self_transfer",
    "utxo_attach_detach",
];
pub(super) const CONFIRMATION_FLAGS: &[&str] = &[
    "confirmation_without_execution",
    "p1_paid_transaction",
    "p2_batch_at_h",
    "reopened_state_matches",
    "unchanged_usage_and_receipts",
];
pub(super) const REPLACEMENT_FLAGS: &[&str] = &[
    "migration_replayed",
    "one_canonical_charge",
    "original_removed",
    "p2_replacement_execution",
    "reopened_state_matches",
    "same_outpoint_replacement",
];
pub(super) const SUPPORT_FLAGS: &[&str] = &[
    "full_successor_accepted",
    "insufficient_subset_rejected",
    "nonempty_changed_successor",
    "old_quorum_certificate",
    "paid_exit_in_h_lifecycle",
    "reopen_preserves_committee_and_frontier",
];
pub(super) const REPLAY_FLAGS: &[&str] = &[
    "actual_p2_activation",
    "reopened_state_matches",
    "retained_decisions_unchanged",
    "same_bitcoin_history",
];
pub(super) const AUTHORIZATION_FLAGS: &[&str] = &[
    "authorization_test",
    "certificates_unchanged",
    "fresh_p1_batch_replayed",
    "orphaned_p2_batch_not_replayed",
    "reopened_state_matches",
    "schedule_retracted",
];
