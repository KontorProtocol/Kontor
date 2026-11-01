import json
from pathlib import Path
import sys
import tempfile
import unittest

from build import digest
from qualify_node import CASES, execute_node


class NodeExecution(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.binary = self.root / 'kontor'
        self.report = self.root / 'node-build.json'
        self.success = self.root / 'node-execution.json'
        self.observations = {'schema': 1, 'cases': sorted(CASES), 'executors': [
            {'graph': 'first', 'observations': {'state': 'same'}},
            {'graph': 'second', 'observations': {'state': 'same'}}]}

    def prepare(self, status=0):
        self.binary.write_text(f'#!{sys.executable}\nimport sys\nprint({json.dumps(self.observations)!r})\nsys.exit({status})\n')
        self.binary.chmod(0o755)
        self.report.write_text(json.dumps({'target': 'test-target', 'profile': 'dev',
            'graphs': [{'graph': 'first'}, {'graph': 'second'}], 'node': {
                'qualification_command': True, 'executable_sha256': digest(self.binary),
                'installed': {'path': str(self.binary), 'sha256': digest(self.binary)}}}))
        self.success.write_text('stale success')

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

    def test_missing_graph_case_and_disagreement_are_rejected(self):
        for kind in ('graph', 'case', 'mismatch'):
            with self.subTest(kind=kind):
                original = json.loads(json.dumps(self.observations))
                if kind == 'graph':
                    self.observations['executors'].pop()
                elif kind == 'case':
                    self.observations['cases'].pop()
                else:
                    self.observations['executors'][1]['observations']['state'] = 'different'
                self.prepare()
                with self.assertRaises(RuntimeError):
                    execute_node(self.report)
                self.assertFalse(self.success.exists())
                self.observations = original


if __name__ == '__main__':
    unittest.main()
