import copy
import json
from pathlib import Path
import tempfile
import unittest

import test_coordinator_definition
from managed_definition import BUILD_INPUTS, DESTINATION, GRAPH, destination, graph_manifest, reference, verify


class ManagedDefinitionTests(unittest.TestCase):
    def fixture(self, root):
        node, node_lock = test_coordinator_definition.CoordinatorDefinitionTests().fixture(root)
        for name in (*BUILD_INPUTS, GRAPH, 'protocol-bundles/consensus/lib.rs',
                     'core/indexer/src/protocol/migration_work.rs',
                     'core/indexer/src/protocol/coordinator/activation.rs',
                     'core/indexer/src/protocol/coordinator/certified_decision.rs',
                     'core/indexer/src/protocol/coordinator/certified_decision/proof_stream.rs',
                     'core/indexer/src/protocol/coordinator/control.rs',
                     'core/indexer/src/protocol/coordinator/manifest.rs',
                     'core/indexer/src/protocol/coordinator/certified_input.rs'):
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('source')
        packages = [
            {'id': 'first', 'name': 'kontor-consensus-first', 'version': '0.1.0',
             'source': None, 'manifest_path': str(root / GRAPH)},
            {'id': 'engine', 'name': 'arc-malachitebft-engine', 'version': '0.9.0',
             'source': 'git+example#revision'},
            {'id': 'transitive', 'name': 'transitive', 'version': '1.0.0',
             'source': 'registry+example'},
        ]
        graph = {'packages': packages, 'resolve': {'root': 'first', 'nodes': [
            {'id': 'first', 'features': [], 'deps': [{'name': 'engine', 'pkg': 'engine'}]},
            {'id': 'engine', 'features': ['serde'], 'deps': [
                {'name': 'transitive', 'pkg': 'transitive',
                 'dep_kinds': [{'kind': None, 'target': 'cfg(unix)'}]}]},
            {'id': 'transitive', 'features': ['std'], 'deps': []},
        ]}}
        graph_lock = {'package': [
            {key: value for key, value in package.items() if key in ('name', 'version', 'source')}
            for package in packages]}
        graph_lock['package'][-1]['checksum'] = '01' * 32
        return node, node_lock, graph, graph_lock

    def test_second_graph_is_distinct_and_verified_against_its_own_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node, node_lock, first, first_lock = self.fixture(root)
            second, second_lock = copy.deepcopy(first), copy.deepcopy(first_lock)
            second['packages'][0]['name'] = 'kontor-consensus-second'
            second['packages'][0]['manifest_path'] = str(root / graph_manifest('second'))
            second_lock['package'][0]['name'] = 'kontor-consensus-second'
            path = root / graph_manifest('second')
            path.parent.mkdir(parents=True)
            path.write_text('second graph manifest')
            original = reference(root, node, node_lock, first, first_lock)
            successor = reference(root, node, node_lock, second, second_lock, 'second')
            self.assertNotEqual(original, successor)
            output = root / destination('second')
            output.parent.mkdir(parents=True, exist_ok=True)
            output.write_bytes(successor)
            verify(root, node, node_lock, second, second_lock, 'second')
            with self.assertRaisesRegex(ValueError, 'requires the consensus-first'):
                reference(root, node, node_lock, second, second_lock)
            output.write_bytes(original)
            with self.assertRaisesRegex(ValueError, 'reference differs'):
                verify(root, node, node_lock, second, second_lock, 'second')

    def test_consensus_dependency_identity_features_and_edges_are_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node, node_lock, graph, graph_lock = self.fixture(root)
            original = reference(root, node, node_lock, graph, graph_lock)
            for change in ('features', 'alias', 'target', 'revision', 'checksum'):
                with self.subTest(change=change):
                    changed, changed_lock = copy.deepcopy(graph), copy.deepcopy(graph_lock)
                    engine = changed['resolve']['nodes'][1]
                    if change == 'features':
                        engine['features'].append('other')
                    elif change == 'alias':
                        engine['deps'][0]['name'] = 'renamed'
                    elif change == 'target':
                        engine['deps'][0]['dep_kinds'][0]['target'] = 'cfg(windows)'
                    elif change == 'revision':
                        changed['packages'][1]['source'] = 'git+example#other'
                        changed_lock['package'][1]['source'] = 'git+example#other'
                    else:
                        changed_lock['package'][-1]['checksum'] = '02' * 32
                    self.assertNotEqual(original, reference(root, node, node_lock, changed, changed_lock))

    def test_sources_are_bound_without_recursive_generated_references(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            inputs = self.fixture(root)
            original = reference(root, *inputs)
            destination = root / DESTINATION
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(original)
            self.assertEqual(original, reference(root, *inputs))
            verify(root, *inputs)
            destination.with_name('second.json').write_text('unregistered successor')
            self.assertEqual(original, reference(root, *inputs))
            for name in (*BUILD_INPUTS, GRAPH, 'protocol-bundles/consensus/lib.rs',
                         'core/indexer/src/protocol/coordinator/certified_decision/proof_stream.rs',
                         'core/indexer/src/protocol/coordinator/activation.rs',
                         'core/indexer/src/protocol/coordinator/control.rs',
                         'core/indexer/src/protocol/coordinator/certified_input.rs'):
                with self.subTest(name=name):
                    path = root / name
                    content = path.read_bytes()
                    path.write_bytes(content + b'changed')
                    self.assertNotEqual(original, reference(root, *inputs))
                    with self.assertRaisesRegex(ValueError, 'reference differs'):
                        verify(root, *inputs)
                    path.write_bytes(content)
            self.assertEqual(destination.read_bytes(), original)

    def test_relocation_and_unreachable_dependency_do_not_change_identity(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first, second = Path(first), Path(second)
            inputs = self.fixture(first)
            original = reference(first, *inputs)
            self.assertEqual(original, reference(second, *self.fixture(second)))
            inputs[2]['packages'].append({'id': 'unrelated', 'name': 'unrelated',
                                         'version': '1', 'source': 'registry+unrelated'})
            inputs[2]['resolve']['nodes'].append({'id': 'unrelated', 'features': [], 'deps': []})
            self.assertEqual(original, reference(first, *inputs))
            # Metadata ordering is not part of protocol identity.
            inputs[2]['packages'].reverse()
            inputs[2]['resolve']['nodes'].reverse()
            self.assertEqual(original, reference(first, *inputs))
            self.assertEqual(json.loads(original)['consensus']['root'],
                             'kontor-consensus-first@0.1.0:' + GRAPH)

    def test_wrong_graph_missing_checksum_and_missing_lock_entry_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node, node_lock, graph, graph_lock = self.fixture(root)
            changed = copy.deepcopy(graph)
            changed['packages'][0]['name'] = 'kontor-consensus-second'
            with self.assertRaisesRegex(ValueError, 'requires the consensus-first graph'):
                reference(root, node, node_lock, changed, graph_lock)
            changed_lock = copy.deepcopy(graph_lock)
            changed_lock['package'][-1].pop('checksum')
            with self.assertRaisesRegex(ValueError, 'lacks checksum'):
                reference(root, node, node_lock, graph, changed_lock)
            changed_lock['package'].pop()
            with self.assertRaisesRegex(ValueError, 'absent from lock'):
                reference(root, node, node_lock, graph, changed_lock)

    def test_escaping_and_cyclic_consensus_sources_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            inputs = self.fixture(root)
            source = root / 'protocol-bundles/consensus/lib.rs'
            source.unlink()
            external = Path(outside) / 'lib.rs'
            external.write_text('external')
            source.symlink_to(external)
            with self.assertRaisesRegex(RuntimeError, 'escapes'):
                reference(root, *inputs)
            source.unlink()
            source.symlink_to(source.parent, target_is_directory=True)
            with self.assertRaisesRegex(RuntimeError, 'cyclic'):
                reference(root, *inputs)


if __name__ == '__main__':
    unittest.main()
