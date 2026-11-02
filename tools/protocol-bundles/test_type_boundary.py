import json
from pathlib import Path
import tempfile
import unittest

from provenance import sha
from type_boundary import ADAPTER_TESTS, ADAPTED_EXECUTOR_PROBES, CONSENSUS_PROBES, PROBES, adapter_tests_passed, check_diagnostics, inputs_for, probes_for


class Diagnostics(unittest.TestCase):
    def test_executor_interface_controls_follow_the_explicit_graph_pair(self):
        self.assertIs(probes_for([{'graph': name} for name in ('first', 'second')]), PROBES)
        selected = probes_for([{'graph': name} for name in ('first', 'observer')])
        self.assertIs(selected, ADAPTED_EXECUTOR_PROBES)
        self.assertEqual(selected['structural-factories'][0], 'E0308')
        self.assertIsNone(selected['adapted-factories'][0])

    def test_adapter_test_evidence_requires_both_bundles_and_successful_exit(self):
        summary = f'test result: ok. {len(ADAPTER_TESTS)} passed; 0 failed; 0 ignored;'
        output = '\n'.join(f'test {name} ... ok' for name in ADAPTER_TESTS) + '\n' + summary
        self.assertTrue(adapter_tests_passed(0, output))
        self.assertFalse(adapter_tests_passed(1, output))
        self.assertFalse(adapter_tests_passed(0, summary))
        self.assertFalse(adapter_tests_passed(0, output.replace(ADAPTER_TESTS[-1], 'unrelated_test')))
        self.assertFalse(adapter_tests_passed(0, output.replace('0 ignored', '1 ignored')))

    def error(self, code):
        return json.dumps({'level': 'error', 'code': {'code': code}})

    def test_expected_type_or_privacy_errors(self):
        check_diagnostics(0, '', None)
        check_diagnostics(1, self.error('E0308'), 'E0308')
        check_diagnostics(1, self.error('E0603'), 'E0603')

    def test_missing_dependency_is_not_a_successful_negative_control(self):
        for text in (self.error('E0463'), self.error('E0308') + '\n' + self.error('E0463')):
            with self.assertRaises(RuntimeError):
                check_diagnostics(1, text, 'E0308')

    def test_success_or_crash_cannot_satisfy_expected_rejection(self):
        for status, text in ((0, ''), (-9, ''), (0, self.error('E0308'))):
            with self.assertRaises(RuntimeError):
                check_diagnostics(status, text, 'E0308')


class ConsensusLibraries(unittest.TestCase):
    def test_actual_staged_hashes_and_private_tokio_are_required_without_wasmtime(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            graphs = []
            for label in ('first', 'second'):
                inputs = root / label
                inputs.mkdir()
                facade = inputs / f'libconsensus_{label}.rlib'
                tokio = inputs / 'libtokio-123.rlib'
                for path in (facade, tokio):
                    path.write_bytes(label.encode())
                graphs.append({'graph': label, 'identity': {'kind': 'consensus'},
                               'facade': str(facade), 'link_inputs': str(inputs),
                               'artifacts': [{'path': str(path), 'sha256': sha(path)} for path in (facade, tokio)]})
            self.assertEqual(probes_for(graphs), CONSENSUS_PROBES)
            arguments, libraries = inputs_for(graphs, True)
            self.assertEqual(set(libraries), {'first', 'second', 'first_tokio', 'second_tokio'})
            self.assertIn('dependency=' + graphs[0]['link_inputs'], arguments)
            facade.write_bytes(b'replaced')
            with self.assertRaisesRegex(RuntimeError, 'library changed'):
                inputs_for(graphs, True)
            del graphs[0]['identity']
            with self.assertRaisesRegex(RuntimeError, 'both consensus graphs'):
                inputs_for(graphs, False)


if __name__ == '__main__':
    unittest.main()
