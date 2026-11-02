import copy
from pathlib import Path
import tempfile
import unittest

from coordinator_definition import DESTINATION, FILES, ROOTS, TREES, reference, verify


class CoordinatorDefinitionTests(unittest.TestCase):
    def fixture(self, root):
        for name in TREES:
            directory = root / name
            directory.mkdir(parents=True, exist_ok=True)
            (directory / 'rules.rs').write_text('actual rules')
        for name in FILES:
            path = root / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('policy')
        names = sorted(ROOTS | {'arc-malachitebft-engine', 'transitive', 'unrelated-http'})
        packages = [{'id': name, 'name': name, 'version': '1.0.0',
                     'source': 'registry+example'} for name in names]
        packages.append({'id': 'node', 'name': 'kontor-node', 'version': '1.0.0', 'source': None})
        nodes = [{'id': name, 'features': ['std'], 'deps': []} for name in names]
        next(item for item in nodes if item['id'] == 'arc-malachitebft-engine')['deps'] = [
            {'name': 'transitive', 'pkg': 'transitive'}]
        nodes.append({'id': 'node', 'features': [], 'deps': [
            {'name': 'malachitebft_engine' if name.startswith('arc-') else name, 'pkg': name}
            for name in names if name != 'transitive']})
        lock = {'package': [{'name': name, 'version': '1.0.0', 'source': 'registry+example',
                             'checksum': '01' * 32} for name in names]}
        return {'packages': packages, 'resolve': {'nodes': nodes}}, lock

    def test_actual_sources_features_and_transitive_checksums_are_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            metadata, lock = self.fixture(root)
            original = reference(root, metadata, lock)
            changed = copy.deepcopy(metadata)
            next(item for item in changed['resolve']['nodes'] if item['id'] == 'transitive')['features'].append('changed')
            self.assertNotEqual(original, reference(root, changed, lock))
            changed = copy.deepcopy(lock)
            next(item for item in changed['package'] if item['name'] == 'transitive')['checksum'] = '02' * 32
            self.assertNotEqual(original, reference(root, metadata, changed))
            changed = copy.deepcopy(metadata)
            edge = next(item for item in changed['resolve']['nodes'] if item['id'] == 'arc-malachitebft-engine')['deps'][0]
            edge['name'] = 'different_alias'
            self.assertNotEqual(original, reference(root, changed, lock))
            edge['name'] = 'transitive'
            edge['dep_kinds'] = [{'kind': None, 'target': 'cfg(unix)'}]
            self.assertNotEqual(original, reference(root, changed, lock))
            (root / TREES[0] / 'rules.rs').write_text('changed rules')
            self.assertNotEqual(original, reference(root, metadata, lock))

    def test_unrelated_node_dependency_and_relocation_do_not_change_identity(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first, second = Path(first), Path(second)
            metadata, lock = self.fixture(first)
            other, other_lock = self.fixture(second)
            original = reference(first, metadata, lock)
            self.assertEqual(original, reference(second, other, other_lock))
            next(item for item in lock['package'] if item['name'] == 'unrelated-http')['checksum'] = 'ff' * 32
            next(item for item in metadata['resolve']['nodes'] if item['id'] == 'unrelated-http')['features'].append('http3')
            self.assertEqual(original, reference(first, metadata, lock))
            destination = first / DESTINATION
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_bytes(original)
            verify(first, metadata, lock)
            destination.write_bytes(b'stale')
            with self.assertRaisesRegex(ValueError, 'reference differs'):
                verify(first, metadata, lock)

    def test_missing_root_checksum_and_escaping_source_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory, tempfile.TemporaryDirectory() as outside:
            root = Path(directory)
            metadata, lock = self.fixture(root)
            changed = copy.deepcopy(lock)
            next(item for item in changed['package'] if item['name'] == 'transitive').pop('checksum')
            with self.assertRaisesRegex(ValueError, 'lacks checksum'):
                reference(root, metadata, changed)
            changed = copy.deepcopy(metadata)
            changed['resolve']['nodes'][-1]['deps'] = [item for item in changed['resolve']['nodes'][-1]['deps'] if item['name'] != 'bitcoin']
            with self.assertRaisesRegex(ValueError, 'missing consensus'):
                reference(root, changed, lock)
            (Path(outside) / 'escape.rs').write_text('outside')
            (root / TREES[0] / 'escape.rs').symlink_to(Path(outside) / 'escape.rs')
            with self.assertRaises(ValueError):
                reference(root, metadata, lock)


if __name__ == '__main__':
    unittest.main()
