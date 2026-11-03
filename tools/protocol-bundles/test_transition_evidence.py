import copy
import hashlib
import unittest

from transition_evidence import JOIN_FLAGS, REPLACEMENT_FLAGS, SUPPORT_FLAGS, verify_join

from build import ROOT
from recipes import executor_graphs
from transition_evidence import STATE_TABLES, TRANSITION_FLAGS, RECOVERY_FLAGS, REPLAY_FLAGS, CONFIRMATION_FLAGS, AUTHORIZATION_FLAGS, TOKEN_COUNT_FLAGS, EMPTY_SUCCESSOR_FLAGS, UNSUPPORTED_FLAGS, CRASH_STAGES, CRASH_FLAGS, BUILD_RECORD_FLAGS, verify_transition, transition_semantics, verify_recovery, verify_authorization


def join_sample():
    return {**{key: True for key in JOIN_FLAGS}, 'validators': 4, 'initial_signers': 3,
            'promotion_generation': 2, 'verified_floor': 3, 'signed_decision': 6,
            'promoted_runtime': {'authority': 'validator', 'consensus_height': '7',
                                 'committee_member': True, 'required_join_height': None}}


class JoinEvidence(unittest.TestCase):
    def test_requires_complete_success_and_signing_after_the_verified_floor(self):
        verify_join(join_sample())
        for key in join_sample():
            missing = join_sample()
            missing.pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError):
                verify_join(missing)
            changed = join_sample()
            changed[key] = False
            with self.subTest(false=key), self.assertRaises(ValueError):
                verify_join(changed)
        for floor, signed in [(0, 6), (3, 3), (7, 6)]:
            with self.subTest(floor=floor, signed=signed), self.assertRaises(ValueError):
                verify_join({**join_sample(), 'verified_floor': floor, 'signed_decision': signed})


def transition_sample():
    """Synthetic verifier input, never evidence that a managed node ran."""
    protocols = ['11' * 32, '22' * 32]
    provenance = {'restored_on_rollback': True, 'unaffected_native_uses_publication': True}
    recipes = executor_graphs('managed-node')
    published = hashlib.sha256((ROOT / recipes['first'].source_root /
                               'core/indexer/src/protocol/v1/native/token.wasm.br').read_bytes()).hexdigest()
    for label, graph, protocol, version, source in (
        ('publication', 'first', protocols[0], 'v1', 'publication'),
        ('upgraded', 'observer', protocols[1], 'v2', 'protocol_native'),
    ):
        recipe = recipes[graph]
        root = ROOT / recipe.source_root
        definition = (root / 'protocol-bundles' / recipe.directory / 'definition.bin').read_bytes()
        artifact = (root / f'core/indexer/src/protocol/{version}/native/token.wasm.br').read_bytes()
        provenance[label] = {'entries': [{'synthetic': 'publication claim'}], 'effective_artifact': {
            'source': source, 'protocol_id': protocol, 'published_sha256': published,
            'sha256': hashlib.sha256(artifact).hexdigest(),
            'execution_definition': hashlib.sha256(b'kontor/execution-definition/v1\0' + definition).hexdigest(),
        }}
    contexts = [
        {'protocol_id': protocols[index % 2],
         'execution_definition': provenance[label]['effective_artifact']['execution_definition'],
         'application_ordinal': str(index + 1), 'lineage': str(index + 1) * 64,
         'bitcoin_height': str(height), 'bitcoin_hash': str(index + 5) * 64,
         'checkpoint_height': str(height), 'checkpoint_hash': 'AB' * 32, 'receipt_epoch': 'aa' * 32,
         'rollback_generation': str(index // 2), 'simulation_height': str(height + 1)}
        for index, (label, height) in enumerate(zip(['publication', 'upgraded'] * 2, [1, 2, 1, 2]))]
    return {**{key: True for key in TRANSITION_FLAGS}, 'validators': 3,
            'closed_decisions': 6, 'block_decisions': [1, 2, 3, 4, 5, 6], 'handoff_heights': [3, 5, 6],
            'first_protocol': protocols[0], 'second_protocol': protocols[1],
            'authorization_test': False, 'scope': 'synthetic gate input',
            'native_provenance': provenance, 'client_contexts': contexts,
            'state': {table: [1, '33' * 32] for table in STATE_TABLES}}


def recovery_sample():
    """Synthetic verifier input, never runtime evidence."""
    result = {**{key: True for key in RECOVERY_FLAGS}, 'schema': 1, 'scope': 'synthetic gate input',
            'closed_decisions': 1, 'successor_height': 2, 'finality_replay': [
                {**{key: True for key in REPLAY_FLAGS}, 'scenario': name, 'closed_decisions': height}
                for name, height in [('SurvivingSchedule', 8), ('UndoCancel', 9), ('UndoPostpone', 9)]]}
    result['finality_replay'][0]['confirmation'] = {
        **{key: True for key in CONFIRMATION_FLAGS}, 'confirmation_height': 3, 'closed_decisions': 5,
        'replacement': {**{key: True for key in REPLACEMENT_FLAGS},
                        'replacement_height': 3, 'finality_height': 7, 'closed_decisions': 8}}
    result['empty_successor'] = {**{key: True for key in EMPTY_SUCCESSOR_FLAGS},
        'activation_height': 13, 'authenticated_decisions': 14, 'closed_decisions': 13}
    result['successor_support'] = {**{key: True for key in SUPPORT_FLAGS},
        'scope': 'composed support assumption, not live mixed binaries',
        'activation_height': 13, 'closed_decisions': 14, 'old_signed_power': 300,
        'old_total_power': 400, 'supporting_successor_power': 100, 'successor_total_power': 200}
    result['build_record'] = {key: True for key in BUILD_RECORD_FLAGS}
    result['unsupported_cancel'] = {**{key: True for key in UNSUPPORTED_FLAGS}, 'validators': 1}
    result['process_crashes'] = [
        {**{key: True for key in CRASH_FLAGS}, 'stage': stage,
         'signature_retry_preserved': stage == 'signed'} for stage in CRASH_STAGES]
    result['token_count'] = {
        **{key: True for key in TOKEN_COUNT_FLAGS}, 'checked_snapshots': 7, 'closed_decisions': 7}
    return result


def authorization_sample():
    """Synthetic verifier input, never runtime evidence."""
    return {**{key: True for key in AUTHORIZATION_FLAGS}, 'schema': 1,
            'notice_blocks': 1008, 'activation_height': 1009, 'closed_decisions': 2028,
            'successive_upgrades': {'qualification_only_p3': True, 'fresh_second_approval': True,
                'p2_p3_share_executor': True, 'reopen_and_genesis_replay_match': True,
                'node_local_epoch_excluded': True, 'second_notice_blocks': 1008,
                'migration_applications': 2, 'closed_decisions': 2019,
                'activation_heights': [1009, 2017], 'protocols': ['11' * 32, '22' * 32, '33' * 32]}}


class TransitionEvidence(unittest.TestCase):
    def test_requires_build_record_checks(self):
        for field in BUILD_RECORD_FLAGS:
            for missing in (True, False):
                value = recovery_sample()
                if missing:
                    value['build_record'].pop(field)
                else:
                    value['build_record'][field] = False
                with self.subTest(field=field, missing=missing), self.assertRaises(ValueError):
                    verify_recovery(value)

    def test_requires_unsupported_cancel_progress(self):
        for field in UNSUPPORTED_FLAGS | {'validators'}:
            for missing in (True, False):
                sample = recovery_sample()
                if missing:
                    sample['unsupported_cancel'].pop(field)
                else:
                    sample['unsupported_cancel'][field] = False
                with self.subTest(field=field, missing=missing), self.assertRaises(ValueError):
                    verify_recovery(sample)

    def test_requires_all_process_crash_checkpoints(self):
        mutations = [lambda value: value.pop('process_crashes'),
                     lambda value: value['process_crashes'].pop(),
                     lambda value: value['process_crashes'].reverse()]
        for index in range(len(CRASH_STAGES)):
            for field in CRASH_FLAGS | {'stage', 'signature_retry_preserved'}:
                mutations.append(lambda value, i=index, f=field: value['process_crashes'][i].pop(f))
                mutations.append(lambda value, i=index, f=field: value['process_crashes'][i].update(
                    {f: 'wrong' if f == 'stage' else not value['process_crashes'][i][f]}))
        for mutate in mutations:
            sample = recovery_sample()
            mutate(sample)
            with self.assertRaises(ValueError):
                verify_recovery(sample)

    def test_requires_empty_successor_gate(self):
        for field in EMPTY_SUCCESSOR_FLAGS | {'activation_height', 'authenticated_decisions', 'closed_decisions'}:
            for missing in (True, False):
                sample = recovery_sample()
                if missing:
                    sample['empty_successor'].pop(field)
                else:
                    sample['empty_successor'][field] = False
                with self.subTest(field=field, missing=missing), self.assertRaises(ValueError):
                    verify_recovery(sample)


    def test_requires_real_token_mutation_observations(self):
        for field in TOKEN_COUNT_FLAGS | {'checked_snapshots', 'closed_decisions'}:
            for missing in (True, False):
                sample = recovery_sample()
                if missing:
                    sample['token_count'].pop(field)
                else:
                    sample['token_count'][field] = False
                with self.subTest(field=field, missing=missing), self.assertRaises(ValueError):
                    verify_recovery(sample)

    def test_live_idle_batches_do_not_replace_c_plus_one_checks(self):
        original = transition_sample()
        delayed = copy.deepcopy(original)
        delayed.update(block_decisions=[1, 4, 7, 11, 14, 18],
                       closed_decisions=18, handoff_heights=[5, 12, 15])
        self.assertEqual(transition_semantics(original, ROOT), transition_semantics(delayed, ROOT))
        for field, invalid in [('block_decisions', [1, 4, 7, 7, 14, 18]),
                               ('block_decisions', [1, 4, 7, 11, 14]),
                               ('closed_decisions', 17),
                               ('handoff_heights', [4, 12, 15]),
                               ('handoff_heights', [5, 13, 15])]:
            changed = copy.deepcopy(delayed)
            changed[field] = invalid
            with self.subTest(field=field, invalid=invalid), self.assertRaises(ValueError):
                transition_semantics(changed, ROOT)

    def test_authorization_requires_notice_orphan_exclusion_and_fresh_replay(self):
        original = authorization_sample()
        verify_authorization(original)
        for key in original:
            value = copy.deepcopy(original)
            value.pop(key)
            with self.subTest(missing=key), self.assertRaises(ValueError):
                verify_authorization(value)
            value = copy.deepcopy(original)
            value[key] = False if key in AUTHORIZATION_FLAGS or key == 'successive_upgrades' else value[key] - 1
            with self.subTest(changed=key), self.assertRaises(ValueError):
                verify_authorization(value)

    def test_rejects_reactivation_in_place_of_a_second_upgrade(self):
        for field, value in [('protocols', ['11' * 32, '22' * 32, '22' * 32]),
                             ('migration_applications', 1), ('second_notice_blocks', 0),
                             ('fresh_second_approval', False), ('reopen_and_genesis_replay_match', False)]:
            sample = authorization_sample()
            sample['successive_upgrades'][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_authorization(sample)

    def test_rejects_context_from_another_execution_or_before_rollback(self):
        for field, value in [('protocol_id', 'ff' * 32), ('execution_definition', 'ff' * 32),
                             ('simulation_height', '2'), ('application_ordinal', 4),
                             ('checkpoint_hash', 'not a digest'), ('checkpoint_hash', 12),
                             ('checkpoint_height', None)]:
            sample = transition_sample()
            sample['client_contexts'][1][field] = value
            with self.subTest(field=field), self.assertRaises(ValueError):
                verify_transition(sample, ROOT)
        sample = transition_sample()
        sample['client_contexts'][2]['rollback_generation'] = sample['client_contexts'][0]['rollback_generation']
        with self.assertRaises(ValueError):
            verify_transition(sample, ROOT)

    def test_requires_complete_distinct_protocol_and_artifact_results(self):
        original = transition_sample()
        verify_transition(original, ROOT)
        for mutation in ('missing', 'flag', 'decision', 'same_protocol', 'same_executor',
                         'old_artifact', 'publication', 'state', 'authorization'):
            value = copy.deepcopy(original)
            if mutation == 'missing':
                value.pop('native_provenance')
            elif mutation == 'flag':
                value['restored_p1_in_fresh_era'] = False
            elif mutation == 'decision':
                value['closed_decisions'] = 5
            elif mutation == 'same_protocol':
                value['second_protocol'] = value['first_protocol']
            elif mutation in ('same_executor', 'old_artifact'):
                field = 'execution_definition' if mutation == 'same_executor' else 'sha256'
                value['native_provenance']['upgraded']['effective_artifact'][field] = value['native_provenance']['publication']['effective_artifact'][field]
            elif mutation == 'publication':
                value['native_provenance']['upgraded']['entries'] = []
            elif mutation == 'state':
                value['state'].pop('contract_state')
            else:
                value['authorization_test'] = True
            with self.subTest(mutation=mutation), self.assertRaises(ValueError):
                verify_transition(value, ROOT)


    def test_transition_requires_live_rpc_and_follower(self):
        for field in ('http_rpc_continuity', 'bitcoin_follower_continuity'):
            for missing in (False, True):
                sample = transition_sample()
                if missing:
                    sample.pop(field)
                else:
                    sample[field] = False
                with self.subTest(field=field, missing=missing), self.assertRaises(ValueError):
                    verify_transition(sample, ROOT)

    def test_recovery_requires_atomicity_and_all_distinct_replay_cases(self):
        original = recovery_sample()
        verify_recovery(original)
        mutations = [lambda value: value.pop('finality_replay'),
                     lambda value: value['finality_replay'].pop(),
                     lambda value: value['finality_replay'].reverse(),
                     lambda value: value['finality_replay'][1].update(scenario='SurvivingSchedule'),
                     lambda value: value['finality_replay'][0].update(closed_decisions=7)]
        mutations += [lambda value: value['finality_replay'][0].pop('confirmation'),
                      lambda value: value['finality_replay'][0]['confirmation'].update(closed_decisions=4)]
        mutations += [lambda value, key=key: value['finality_replay'][0]['confirmation'].update({key: False})
                      for key in CONFIRMATION_FLAGS]
        mutations += [lambda value: value['finality_replay'][0]['confirmation'].pop('replacement'),
                      lambda value: value['finality_replay'][0]['confirmation']['replacement'].update(replacement_height=2)]
        mutations += [lambda value, key=key: value['finality_replay'][0]['confirmation']['replacement'].update({key: False})
                      for key in REPLACEMENT_FLAGS]
        mutations += [lambda value: value.pop('successor_support'),
                      lambda value: value['successor_support'].update(scope='live mixed binaries'),
                      lambda value: value['successor_support'].update(supporting_successor_power=200)]
        mutations += [lambda value, key=key: value['successor_support'].update({key: False})
                      for key in SUPPORT_FLAGS]
        mutations += [lambda value, key=key: value.update({key: False}) for key in RECOVERY_FLAGS]
        mutations += [lambda value, key=key: value['finality_replay'][0].update({key: False}) for key in REPLAY_FLAGS]
        for mutate in mutations:
            value = copy.deepcopy(original)
            mutate(value)
            with self.assertRaises(ValueError):
                verify_recovery(value)
