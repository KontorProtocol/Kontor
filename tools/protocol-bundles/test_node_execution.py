import json
import copy
import hashlib
from pathlib import Path
import sys
import tempfile
import unittest

from build import ROOT, digest
from qualify_node import CASES, CERTIFIED_CHECKS, execute_node, verify_certified_history, verify_managed_startup
from test_semantic_baseline import sample_observation


def certified_sample(link_set="k4-node"):
    """Synthetic gate input, never evidence that the Rust fixture ran."""
    def hashed(domain, value):
        return hashlib.sha256(domain + b'\0' + value).hexdigest()
    executor = hashed(b'kontor/execution-definition/v1',
                      (ROOT / 'protocol-bundles/executor-observer/definition.bin').read_bytes())
    chain = bytes([7]) * 32
    consensus_path = ('core/indexer/src/protocol/coordinator/managed/definitions/first.json'
                      if link_set == 'managed-node' else
                      'core/indexer/src/protocol/coordinator/baseline/consensus.json')
    consensus = bytes.fromhex(hashed(b'kontor/consensus-definition/v1', (ROOT / consensus_path).read_bytes()))
    manifest = b'KPM1' + chain + (1).to_bytes(8, 'big') + bytes(32) + bytes.fromhex(executor) + consensus + bytes(132)
    protocol = hashed(b'kontor/protocol-manifest/v1', manifest)
    checks = CERTIFIED_CHECKS | ({'migration_rehearsal_cli'} if link_set == 'managed-node' else set())
    return {**{key: True for key in checks}, 'authenticated': 15, 'closed': 15,
            'executor_definition': executor, 'manifest': manifest.hex(), 'chain': chain.hex(),
            'protocol': protocol, 'era': hashed(b'kontor/genesis-era/v1', chain + bytes.fromhex(protocol))}


def managed_sample(history):
    return {**{name: history[name] for name in ('chain', 'protocol', 'era', 'executor_definition')},
            'rounds_started': 2, 'engines_joined': 2, 'next_generation': 3,
            'same_listener': True, 'same_era_wal': True, 'database_remained_available': True,
            'competing_writer_rejected': True}


class NodeExecution(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binary = self.root / 'kontor'
        self.report = self.root / 'node-build.json'
        self.success = self.root / 'node-execution.json'
        self.observations = {'schema': 1, 'cases': sorted(CASES), 'executors': [
            {'graph': 'first', 'observations': sample_observation()},
            {'graph': 'second', 'observations': sample_observation()}]}
        self.observations['storage_contracts'] = {'rejected_before_construction': [
            f'{graph}:{mutation}' for graph in ('first', 'second')
            for mutation in ('missing', 'unknown', 'changed', 'multiple')]}

    def prepare(self, status=0):
        self.binary.write_text(f'#!{sys.executable}\nimport sys\nprint({json.dumps(self.observations)!r})\nsys.exit({status})\n')
        self.binary.chmod(0o755)
        self.report.write_text(json.dumps({'target': 'test-target', 'profile': 'dev',
            'graphs': [{'graph': 'first'}, {'graph': 'second'}], 'node': {
                'qualification_command': True, 'executable_sha256': digest(self.binary),
                'installed': {'path': str(self.binary), 'sha256': digest(self.binary)}}}))
        self.success.write_text('stale success')

    def test_certified_gate_requires_complete_observer_bound_evidence(self):
        original = certified_sample()
        verify_certified_history({'certified_history': original}, 'k4-node')
        for mutation in ('missing', 'check', 'count', 'executor', 'protocol', 'era', 'manifest'):
            altered = copy.deepcopy(original)
            if mutation == 'missing':
                altered = None
            elif mutation == 'check':
                altered['ack_after_durable_input'] = False
            elif mutation == 'count':
                altered['closed'] = 14
            elif mutation == 'manifest':
                altered['manifest'] = altered['manifest'][:-2]
            else:
                altered['executor_definition' if mutation == 'executor' else mutation] = '00' * 32
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                verify_certified_history({'certified_history': altered}, 'k4-node')
        with self.assertRaisesRegex(RuntimeError, 'legacy qualification'):
            verify_certified_history({'certified_history': original}, 'legacy-qualification')

    def test_consensus_definition_cannot_be_substituted_between_link_sets(self):
        for selected, other in (('managed-node', 'k4-node'), ('k4-node', 'managed-node')):
            verify_certified_history({'certified_history': certified_sample(selected)}, selected)
            substituted = certified_sample(other)
            if selected == 'managed-node':
                substituted['migration_rehearsal_cli'] = True
            else:
                substituted.pop('migration_rehearsal_cli')
            with self.assertRaisesRegex(RuntimeError, 'baseline identity'):
                verify_certified_history({'certified_history': substituted}, selected)

    def test_managed_history_requires_successful_rehearsal_cli(self):
        original = certified_sample('managed-node')
        for replacement in (False, None):
            changed = dict(original, migration_rehearsal_cli=replacement)
            with self.assertRaises(RuntimeError):
                verify_certified_history({'certified_history': changed}, 'managed-node')
        del original['migration_rehearsal_cli']
        with self.assertRaises(RuntimeError):
            verify_certified_history({'certified_history': original}, 'managed-node')

    def test_managed_startup_requires_actual_results_for_the_selected_protocol(self):
        history = certified_sample('managed-node')
        original = managed_sample(history)
        observations = {'certified_history': history, 'managed_startup': original}
        verify_managed_startup(observations, 'managed-node')
        for field, replacement in (('protocol', 'another protocol'), ('engines_joined', 1),
                                   ('same_listener', False), ('next_generation', 2),
                                   ('competing_writer_rejected', False)):
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, 'managed startup evidence'):
                verify_managed_startup(dict(observations, managed_startup={**original, field: replacement}), 'managed-node')
        with self.assertRaisesRegex(RuntimeError, 'managed startup evidence'):
            verify_managed_startup({'certified_history': history}, 'managed-node')
        with self.assertRaisesRegex(RuntimeError, 'unmanaged qualification'):
            verify_managed_startup(observations, 'k4-node')

    def test_k4_execution_rejects_missing_certified_evidence(self):
        self.observations['executors'][1]['graph'] = 'observer'
        self.observations['storage_contracts']['rejected_before_construction'] = [
            f'{graph}:{mutation}' for graph in ('first', 'observer')
            for mutation in ('missing', 'unknown', 'changed', 'multiple')]
        self.prepare()
        report = json.loads(self.report.read_text())
        report['link_set'] = 'k4-node'
        report['graphs'][1]['graph'] = 'observer'
        self.report.write_text(json.dumps(report))
        with self.assertRaisesRegex(RuntimeError, 'certified history evidence'):
            execute_node(self.report, 'k4-node')
        self.assertFalse(self.success.exists())

    def test_pass_binds_raw_output_and_audited_binary(self):
        self.prepare()
        evidence = execute_node(self.report)
        self.assertEqual(evidence['node_build_sha256'], digest(self.report))
        self.assertEqual(evidence['executable_sha256'], digest(self.binary))
        self.assertEqual(evidence['stdout_sha256'], digest(self.root / 'node-execution.stdout.json'))
        self.assertEqual(json.loads(self.success.read_text()), evidence)

    def test_altered_installed_binary_rejects_stale_success(self):
        self.prepare()
        self.binary.write_text('changed')
        with self.assertRaisesRegex(RuntimeError, 'differs from'):
            execute_node(self.report)
        self.assertFalse(self.success.exists())

    def test_failed_process_cannot_pass_with_valid_json(self):
        self.prepare(status=1)
        with self.assertRaisesRegex(RuntimeError, 'execution failed'):
            execute_node(self.report)
        self.assertFalse(self.success.exists())

    def test_agreeing_graphs_cannot_replace_historical_behavior(self):
        for graph in self.observations['executors']:
            graph['observations']['malformed_transaction'] = 'changed error'
        self.prepare()
        with self.assertRaisesRegex(ValueError, 'historical semantic comparison differs'):
            execute_node(self.report)
        self.assertFalse(self.success.exists())

    def test_missing_graph_case_and_disagreement_are_rejected(self):
        for kind in ('graph', 'case', 'mismatch', 'storage'):
            with self.subTest(kind=kind):
                original = json.loads(json.dumps(self.observations))
                if kind == 'graph':
                    self.observations['executors'].pop()
                elif kind == 'case':
                    self.observations['cases'].pop()
                elif kind == 'storage':
                    self.observations['storage_contracts']['rejected_before_construction'].pop()
                else:
                    self.observations['executors'][1]['observations']['state'] = 'different'
                self.prepare()
                with self.assertRaises(RuntimeError):
                    execute_node(self.report)
                self.assertFalse(self.success.exists())
                self.observations = original


if __name__ == '__main__':
    unittest.main()
