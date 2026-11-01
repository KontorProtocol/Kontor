from pathlib import Path
import unittest
from unittest.mock import patch

import bundle_qualification_scope as scope


class BundleScopeTests(unittest.TestCase):
    def selected(self, paths):
        with patch.object(scope, 'changed_paths', return_value=paths):
            return scope.select('pull_request', {}, Path.cwd())['required']

    def test_evidence_only_changes_do_not_rebuild_node(self):
        with patch.object(scope, 'changed_paths', return_value=[
                'tools/protocol-bundles/compare_node.py', 'tools/protocol-bundles/test_node_comparison.py']):
            result = scope.select('pull_request', {}, Path.cwd())
        self.assertFalse(result['required'])
        self.assertTrue(result['controls'])
        self.assertFalse(self.selected(['docs/design/protocol-upgrades/bundle-maintenance.md']))

    def test_unrelated_changes_skip_both_expensive_builds_and_controls(self):
        with patch.object(scope, 'changed_paths', return_value=['sdk/src/client.ts']):
            result = scope.select('pull_request', {}, Path.cwd())
        self.assertFalse(result['required'])
        self.assertFalse(result['controls'])

    def test_execution_build_and_mixed_changes_require_node(self):
        for path in ['core/indexer/src/protocol_qualification.rs',
                     'core/indexer/src/config.rs', 'core/indexer/src/api/handlers/info.rs',
                     'tools/protocol-bundles/build.py', 'tools/protocol-bundles/qualify_node.py',
                     'protocol-bundles/node/Cargo.lock', 'core/.cargo/config.toml',
                     'core/numerics/src/lib.rs', 'tools/ci/bundle_qualification_scope.py']:
            with self.subTest(path=path):
                self.assertTrue(self.selected([path, 'tools/protocol-bundles/compare_node.py']))

    def test_manual_or_unavailable_history_requires_node(self):
        self.assertTrue(scope.select('workflow_dispatch', {}, Path.cwd())['required'])
        self.assertTrue(scope.select('pull_request', {}, Path.cwd())['required'])


if __name__ == '__main__':
    unittest.main()
