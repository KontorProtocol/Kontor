"""Validate the managed P1/P2 transition result, separately from the P1 oracle."""

import hashlib

from recipes import executor_graphs


TRANSITION_FLAGS = {
    'same_listeners', 'matching_closure_and_state', 'restored_p1_in_fresh_era',
    'reapplied_migration', 'retained_history_unchanged',
    'http_rpc_continuity', 'bitcoin_follower_continuity',
}
JOIN_FLAGS = {
    'source_already_p2', 'same_listener', 'matching_verified_prefix',
    'separate_wals', 'required_promoted_vote', 'stalled_without_quorum',
}


def verify_join(result):
    keys = JOIN_FLAGS | {'validators', 'initial_signers', 'verified_floor',
                         'signed_decision', 'promotion_generation', 'promoted_runtime'}
    if not isinstance(result, dict) or set(result) != keys:
        raise ValueError('validator join evidence missing or incomplete')
    if (any(result[key] is not True for key in JOIN_FLAGS)
            or any(type(result[key]) is not int for key in keys - JOIN_FLAGS - {'promoted_runtime'})
            or result['validators'] != 4 or result['initial_signers'] != 3
            or result['promotion_generation'] != 2
            or not 0 < result['verified_floor'] < result['signed_decision']):
        raise ValueError('validator join did not verify progress before promotion and signing')
    runtime = result['promoted_runtime']
    if (not isinstance(runtime, dict) or set(runtime) != {
            'authority', 'consensus_height', 'committee_member', 'required_join_height'}
            or runtime['authority'] != 'validator' or runtime['committee_member'] is not True
            or runtime['required_join_height'] is not None
            or not decimal(runtime['consensus_height'])
            or int(runtime['consensus_height']) < result['signed_decision']):
        raise ValueError('promoted runtime diagnostics are incomplete')
    # Empty batches can shift consensus heights between independent live runs.
    return {key: result[key] for key in keys - {'verified_floor', 'signed_decision', 'promoted_runtime'}}


STATE_TABLES = {
    'block_execution_usage', 'blocks', 'bls_keys', 'contract_provenance',
    'contract_results', 'contract_state', 'contracts', 'current_contract_state',
    'depositor_footprint', 'nonces', 'signers', 'transaction_execution_usage',
    'transactions', 'x_only_pubkeys',
}


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def is_digest(value):
    return (isinstance(value, str) and len(value) == 64
            and all(character in '0123456789abcdef' for character in value))


def decimal(value):
    return isinstance(value, str) and value.isascii() and value.isdecimal()


def verify_client_contexts(contexts, first, second, provenance):
    fields = {'protocol_id', 'execution_definition', 'application_ordinal', 'lineage',
              'bitcoin_height', 'bitcoin_hash', 'checkpoint_height', 'checkpoint_hash',
              'receipt_epoch', 'rollback_generation', 'simulation_height'}
    if not isinstance(contexts, list) or len(contexts) != 4:
        raise ValueError('four execution-bound client contexts required')
    for item, protocol, label, height in zip(contexts, [first, second, first, second],
                                           ['publication', 'upgraded'] * 2, [1, 2, 1, 2]):
        if (not isinstance(item, dict) or set(item) != fields
                or item['protocol_id'] != protocol
                or item['execution_definition'] != provenance[label]['effective_artifact']['execution_definition']
                or item['bitcoin_height'] != str(height) or item['simulation_height'] != str(height + 1)
                or not all(is_digest(item[key]) for key in ['lineage', 'bitcoin_hash', 'receipt_epoch'])
                or not decimal(item['application_ordinal']) or int(item['application_ordinal']) == 0
                or not decimal(item['rollback_generation'])
                or (item['checkpoint_height'] is not None and not decimal(item['checkpoint_height']))
                or (item['checkpoint_height'] is None) != (item['checkpoint_hash'] is None)
                # SQLite's hex() checkpoint representation is uppercase.
                or (item['checkpoint_hash'] is not None and
                    (not isinstance(item['checkpoint_hash'], str)
                     or not is_digest(item['checkpoint_hash'].lower())))):
            raise ValueError('client context does not match execution selection')
    if (contexts[0]['rollback_generation'] == contexts[2]['rollback_generation']
            or contexts[1]['lineage'] == contexts[3]['lineage']):
        raise ValueError('client context did not distinguish rollback and reactivation')


def verify_transition(result, root):
    keys = TRANSITION_FLAGS | {
        'validators', 'closed_decisions', 'block_decisions', 'handoff_heights', 'first_protocol',
        'second_protocol', 'authorization_test', 'scope', 'native_provenance', 'state', 'client_contexts',
    }
    if not isinstance(result, dict) or set(result) != keys:
        raise ValueError('transition evidence missing or incomplete')
    blocks = result['block_decisions']
    if (not isinstance(blocks, list) or len(blocks) != 6
            or any(type(height) is not int or height <= 0 for height in blocks)
            or blocks[0] != 1 or any(left >= right for left, right in zip(blocks, blocks[1:]))):
        raise ValueError('transition checks require six ordered certified block decisions')
    if (any(result[key] is not True for key in TRANSITION_FLAGS)
            or result['validators'] != 3
            or type(result['closed_decisions']) is not int or result['closed_decisions'] != blocks[-1]
            or result['handoff_heights'] != [blocks[index] + 1 for index in (1, 3, 4)]
            or result['authorization_test'] is not False):
        raise ValueError('transition checks did not complete with the required scope')
    first, second = result['first_protocol'], result['second_protocol']
    if not is_digest(first) or not is_digest(second) or first == second:
        raise ValueError('transition must exercise distinct protocol identities')
    provenance = result['native_provenance']
    if (not isinstance(provenance, dict) or set(provenance) != {
            'publication', 'upgraded', 'restored_on_rollback', 'unaffected_native_uses_publication'}
            or provenance['restored_on_rollback'] is not True
            or provenance['unaffected_native_uses_publication'] is not True):
        raise ValueError('transition provenance checks missing')
    recipes = executor_graphs('managed-node')
    published = sha256(root / recipes['first'].source_root /
                       'core/indexer/src/protocol/v1/native/token.wasm.br')
    for label, graph, protocol, artifact_path, source in (
        ('publication', 'first', first,
         'core/indexer/src/protocol/v1/native/token.wasm.br', 'publication'),
        ('upgraded', 'observer', second,
         'core/indexer/src/protocol/v2/native/token.wasm.br', 'protocol_native'),
    ):
        recipe = recipes[graph]
        graph_root = root / recipe.source_root
        definition = (graph_root / 'protocol-bundles' / recipe.directory / 'definition.bin').read_bytes()
        expected = {
            'sha256': sha256(graph_root / artifact_path), 'published_sha256': published,
            'source': source, 'protocol_id': protocol,
            'execution_definition': hashlib.sha256(b'kontor/execution-definition/v1\0' + definition).hexdigest(),
        }
        entry = provenance[label]
        if (not isinstance(entry, dict) or set(entry) != {'entries', 'effective_artifact'}
                or entry['effective_artifact'] != expected):
            raise ValueError(f'transition {label} does not match the selected executor and native artifact')
    if (not provenance['publication']['entries']
            or provenance['publication']['entries'] != provenance['upgraded']['entries']):
        raise ValueError('native replacement changed the original publication claims')
    verify_client_contexts(result['client_contexts'], first, second, provenance)
    state = result['state']
    if (not isinstance(state, dict) or set(state) != STATE_TABLES
            or any(not isinstance(value, list) or len(value) != 2
                   or type(value[0]) is not int or value[0] < 0 or not is_digest(value[1])
                   for value in state.values())):
        raise ValueError('transition application-state comparison is incomplete')
    return result


def transition_semantics(result, root):
    checked = verify_transition(result, root)
    # Live peers can certify idle batches between follower polls. Validate each
    # observed C+1 above; compare outcomes, not a wall-clock-dependent transcript.
    return {key: value for key, value in checked.items()
            if key not in {'closed_decisions', 'block_decisions', 'handoff_heights', 'client_contexts'}}


BUILD_RECORD_FLAGS = {
    'embedded_record_verified', 'missing_record_rejected',
    'changed_bindings_rejected', 'incomplete_graphs_rejected',
}
RECOVERY_FLAGS = {
    'activation_write_failure_atomic', 'actual_p2_migration', 'invalid_input_rejected_after_reopen',
    'reopened_state_matches', 'successor_gated_until_closure',
}
UNSUPPORTED_FLAGS = {
    'unsupported_block_not_proposed', 'unsupported_proposal_rejected',
    'signed_cancel_certified', 'bitcoin_progress_resumed', 'old_protocol_preserved',
}
CRASH_STAGES = ['certified', 'activated', 'closed', 'engine-ready', 'signed']
CRASH_FLAGS = {
    'process_killed', 'state_matches', 'certificate_preserved',
    'successor_started', 'conflict_rejected',
}
EMPTY_SUCCESSOR_FLAGS = {
    'paid_exit_confirmed', 'activation_committed', 'empty_successor_gated',
    'reopen_preserves_gate', 'retained_certificate_unchanged',
}
TOKEN_COUNT_FLAGS = {
    'migration_from_populated_p1', 'paid_mint_transfer_burn', 'self_transfer',
    'gas_escrow_refunded', 'utxo_attach_detach', 'failed_call_consistent',
    'full_ledger_count_matches', 'reopened_state_matches',
}
CONFIRMATION_FLAGS = {
    "p1_paid_transaction", "p2_batch_at_h", "confirmation_without_execution",
    "unchanged_usage_and_receipts", "reopened_state_matches",
}
REPLACEMENT_FLAGS = {
    'same_outpoint_replacement', 'original_removed', 'p2_replacement_execution',
    'one_canonical_charge', 'migration_replayed', 'reopened_state_matches',
}
SUPPORT_FLAGS = {
    'old_quorum_certificate', 'paid_exit_in_h_lifecycle', 'nonempty_changed_successor',
    'insufficient_subset_rejected', 'full_successor_accepted', 'reopen_preserves_committee_and_frontier',
}
REPLAY_FLAGS = {
    'same_bitcoin_history', 'reopened_state_matches', 'actual_p2_activation', 'retained_decisions_unchanged',
}


def verify_recovery(result):
    keys = RECOVERY_FLAGS | {'schema', 'scope', 'closed_decisions', 'successor_height', 'finality_replay', 'token_count', 'empty_successor', 'successor_support', 'unsupported_cancel', 'process_crashes', 'build_record'}
    if (not isinstance(result, dict) or set(result) != keys or result['schema'] != 1
            or result['closed_decisions'] != 1 or result['successor_height'] != 2
            or any(result[key] is not True for key in RECOVERY_FLAGS)):
        raise ValueError('managed recovery evidence missing or incomplete')
    build = result['build_record']
    if (not isinstance(build, dict) or set(build) != BUILD_RECORD_FLAGS
            or any(build[key] is not True for key in BUILD_RECORD_FLAGS)):
        raise ValueError('embedded build record verification incomplete')
    unsupported = result['unsupported_cancel']
    if (not isinstance(unsupported, dict) or set(unsupported) != UNSUPPORTED_FLAGS | {'validators'}
            or type(unsupported['validators']) is not int or unsupported['validators'] != 1
            or any(unsupported[key] is not True for key in UNSUPPORTED_FLAGS)):
        raise ValueError('unsupported-target cancellation evidence missing or incomplete')
    crashes = result['process_crashes']
    if not isinstance(crashes, list) or len(crashes) != len(CRASH_STAGES):
        raise ValueError('process-crash checkpoints missing')
    for case, stage in zip(crashes, CRASH_STAGES):
        if (not isinstance(case, dict)
                or set(case) != CRASH_FLAGS | {'stage', 'signature_retry_preserved'}
                or case['stage'] != stage
                or any(case[key] is not True for key in CRASH_FLAGS)
                or case['signature_retry_preserved'] is not (stage == 'signed')):
            raise ValueError('process-crash recovery evidence incomplete')
    successor = result['empty_successor']
    support = result['successor_support']
    positions = {'activation_height': 13, 'closed_decisions': 14, 'old_signed_power': 300,
                 'old_total_power': 400, 'supporting_successor_power': 100, 'successor_total_power': 200}
    if (not isinstance(support, dict) or set(support) != SUPPORT_FLAGS | set(positions) | {'scope'}
            or support['scope'] != 'composed support assumption, not live mixed binaries'
            or any(support[key] is not True for key in SUPPORT_FLAGS)
            or any(type(support[key]) is not int or support[key] != value for key, value in positions.items())):
        raise ValueError('successor support mismatch evidence incomplete')
    positions = {'activation_height': 13, 'authenticated_decisions': 14, 'closed_decisions': 13}
    if (not isinstance(successor, dict) or set(successor) != EMPTY_SUCCESSOR_FLAGS | set(positions)
            or any(successor[key] is not True for key in EMPTY_SUCCESSOR_FLAGS)
            or any(type(successor[key]) is not int or successor[key] != value
                   for key, value in positions.items())):
        raise ValueError('empty successor authority gate evidence missing or incomplete')
    token = result['token_count']
    if (not isinstance(token, dict)
            or set(token) != TOKEN_COUNT_FLAGS | {'checked_snapshots', 'closed_decisions'}
            or token['checked_snapshots'] != 7 or token['closed_decisions'] != 7
            or any(token[key] is not True for key in TOKEN_COUNT_FLAGS)):
        raise ValueError('managed token count mutation evidence missing or incomplete')
    cases = result['finality_replay']
    expected = [('SurvivingSchedule', 8), ('UndoCancel', 9), ('UndoPostpone', 9)]
    if not isinstance(cases, list) or len(cases) != len(expected):
        raise ValueError('managed recovery replay cases missing')
    for case, (name, height) in zip(cases, expected):
        case_keys = REPLAY_FLAGS | {'scenario', 'closed_decisions'}
        if name == 'SurvivingSchedule':
            case_keys |= {'confirmation'}
        if (not isinstance(case, dict) or set(case) != case_keys
                or case['scenario'] != name or case['closed_decisions'] != height
                or any(case[key] is not True for key in REPLAY_FLAGS)):
            raise ValueError('managed recovery replay case incomplete')
        if name == 'SurvivingSchedule':
            confirmation = case['confirmation']
            if (not isinstance(confirmation, dict)
                    or set(confirmation) != CONFIRMATION_FLAGS | {'confirmation_height', 'closed_decisions', 'replacement'}
                    or confirmation['confirmation_height'] != 3 or confirmation['closed_decisions'] != 5
                    or any(confirmation[key] is not True for key in CONFIRMATION_FLAGS)):
                raise ValueError('cross-activation confirmation evidence incomplete')
            replacement = confirmation['replacement']
            positions = {'replacement_height': 3, 'finality_height': 7, 'closed_decisions': 8}
            if (not isinstance(replacement, dict) or set(replacement) != REPLACEMENT_FLAGS | set(positions)
                    or any(replacement[key] is not True for key in REPLACEMENT_FLAGS)
                    or any(type(replacement[key]) is not int or replacement[key] != value
                           for key, value in positions.items())):
                raise ValueError('cross-activation replacement evidence incomplete')
    return result


AUTHORIZATION_FLAGS = {
    'authorization_test', 'schedule_retracted', 'orphaned_p2_batch_not_replayed',
    'fresh_p1_batch_replayed', 'certificates_unchanged', 'reopened_state_matches',
}


def verify_authorization(result):
    expected = {'schema': 1, 'notice_blocks': 1008, 'activation_height': 1009,
                'closed_decisions': 2028}
    if (not isinstance(result, dict) or set(result) != AUTHORIZATION_FLAGS | set(expected) | {'successive_upgrades'}
            or any(type(result[key]) is not int or result[key] != value
                   for key, value in expected.items())
            or any(result[key] is not True for key in AUTHORIZATION_FLAGS)):
        raise ValueError('managed authorization replay evidence missing or incomplete')
    successive = result['successive_upgrades']
    flags = {'qualification_only_p3', 'fresh_second_approval', 'p2_p3_share_executor',
             'reopen_and_genesis_replay_match', 'node_local_epoch_excluded'}
    expected = {'second_notice_blocks': 1008, 'migration_applications': 2, 'closed_decisions': 2019}
    if (not isinstance(successive, dict) or set(successive) != flags | set(expected) | {'activation_heights', 'protocols'}
            or any(successive[key] is not True for key in flags)
            or any(type(successive[key]) is not int or successive[key] != value for key, value in expected.items())
            or successive['activation_heights'] != [1009, 2017]
            or not isinstance(successive['protocols'], list) or len(successive['protocols']) != 3
            or not all(is_digest(value) for value in successive['protocols'])
            or len(set(successive['protocols'])) != 3):
        raise ValueError('two successive authorized upgrades and replay are incomplete')
    return result
