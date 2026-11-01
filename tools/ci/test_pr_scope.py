import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import pr_scope as scope

ROOT = Path(__file__).resolve().parents[2]


class PrScopeTests(unittest.TestCase):
    def test_repository_artifact_dependency_coverage(self):
        scope.validate_repro_dependencies(ROOT)

    def test_real_dependency_closure_is_used_by_selection(self):
        with patch.object(scope, 'changed_paths', return_value=['README.md']):
            result = scope.select('pull_request', {}, ROOT)
        self.assertFalse(any(result['jobs'].values()), result)

    def test_docs_sdk_and_node_changes_have_distinct_checks(self):
        self.assertEqual(scope.classify('docs/upgrade.md'), set())
        self.assertEqual(scope.classify('README.md'), set())
        self.assertEqual(scope.classify('sdk/src/client.ts'), {'sdk'})
        self.assertEqual(scope.classify('core/indexer/src/reactor/engine.rs'), {'rust', 'sdk'})
        self.assertEqual(scope.classify('core/indexer/src/database/init.rs'), {'rust', 'sdk'})

    def test_artifact_changes_include_embedded_wit_and_generated_outputs(self):
        for path in (
            'core/indexer/src/runtime/wit/deps/built-in/common.wit',
            'core/indexer/src/runtime/wit/deps/built-in/native.wit',
            'core/macros/src/interface.rs', 'core/kontor-build/src/lib.rs',
            'native-contracts/binaries/staking.wasm.br', 'test-contracts/proxy/src/lib.rs',
            'sdk/src/component/kontor-sdk.core.wasm', 'sdk/src/bindings.d.ts',
            'sdk/package-lock.json', 'tools/build.json', 'tools/native-crypto/compare-sdk.mjs',
        ):
            with self.subTest(path=path):
                self.assertIn('reproducible', scope.classify(path))

    def test_dependency_configuration_and_unknown_inputs_are_conservative(self):
        for path in ('core/Cargo.lock', 'new-crate/Cargo.toml', 'core/.cargo/config.toml',
                     'rust-toolchain.toml', 'unknown/input', '.github/workflows/ci.yml',
                     'tools/ci/pr_scope.py', '.github/actions/setup-docker/action.yml'):
            with self.subTest(path=path):
                self.assertEqual(scope.classify(path), set(scope.JOBS))

    def test_fetch_cache_tracks_target_discovery_without_compiling_sources(self):
        for path in ('core/indexer/src/lib.rs', 'core/thing/build.rs',
                     'core/thing/examples/new.rs', 'core/thing/src/bin/tool.rs',
                     'core/thing/tests/new.rs', 'protocol-bundles/node/Cargo.lock'):
            self.assertIn('docker_cache', scope.classify(path))
        self.assertNotIn('docker_cache', scope.classify('core/indexer/src/runtime/call.rs'))
        self.assertIn('docker_cache', scope.classify('core/thing/custom.rs', {'core/thing/custom.rs'}))
        self.assertIn('core/indexer/src/main.rs', scope.docker_target_paths(ROOT))

    def test_mixed_changes_union_jobs_and_failed_scope_never_skips(self):
        with patch.object(scope, 'changed_paths', return_value=[
                'docs/upgrade.md', 'core/macros/src/interface.rs', 'sdk/src/client.ts']):
            result = scope.select('pull_request', {}, ROOT)
        self.assertTrue(result['jobs']['rust'])
        self.assertTrue(result['jobs']['sdk'])
        self.assertTrue(result['jobs']['reproducible'])
        self.assertTrue(all(scope.select('pull_request', {}, ROOT)['jobs'].values()))
        self.assertTrue(all(scope.select('workflow_dispatch', {}, ROOT)['jobs'].values()))
        with patch.object(scope, 'validate_repro_dependencies', side_effect=ValueError('uncovered')):
            self.assertTrue(all(scope.select('pull_request', {}, ROOT)['jobs'].values()))


class DependencyCoverageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.write('native-contracts/Cargo.toml', '[workspace]\nmembers=[]')
        self.write('test-contracts/Cargo.toml', '[workspace]\nmembers=[]')
        self.write('core/Cargo.toml', '[workspace]\nmembers=["kontor-build", "kontor-sdk-wasm"]')
        self.write('core/kontor-build/Cargo.toml', '[package]\nname="builder"\nversion="1.0.0"')
        self.write('core/kontor-sdk-wasm/Cargo.toml', '[package]\nname="sdk"\nversion="1.0.0"')
        self.write('core/new-dependency/Cargo.toml', '[package]\nname="new"\nversion="1.0.0"')

    def write(self, path, text):
        file = self.root / path
        file.parent.mkdir(parents=True, exist_ok=True)
        file.write_text(text)

    def append(self, path, text):
        file = self.root / path
        file.write_text(file.read_text() + '\n' + text)

    def test_target_build_and_dev_dependencies_cannot_escape(self):
        file = self.root / 'core/kontor-sdk-wasm/Cargo.toml'
        original = file.read_text()
        for table in ('dependencies', 'build-dependencies', 'dev-dependencies',
                      "target.'cfg(unix)'.dependencies"):
            with self.subTest(table=table):
                file.write_text(original + f'\n[{table}]\nnew={{path="../new-dependency"}}')
                with self.assertRaisesRegex(ValueError, 'uncovered artifact dependency'):
                    scope.validate_repro_dependencies(self.root)

    def test_workspace_inherited_path_dependency_cannot_escape(self):
        self.append('core/Cargo.toml', '[workspace.dependencies]\nnew={path="new-dependency"}')
        self.append('core/kontor-sdk-wasm/Cargo.toml', '[dependencies]\nnew={workspace=true}')
        with self.assertRaisesRegex(ValueError, 'uncovered artifact dependency'):
            scope.validate_repro_dependencies(self.root)

    def test_local_patches_cannot_escape(self):
        self.append('core/Cargo.toml', '[patch.crates-io]\nnew={path="new-dependency"}')
        with self.assertRaisesRegex(ValueError, 'uncovered artifact dependency'):
            scope.validate_repro_dependencies(self.root)

    def test_invalid_manifest_and_missing_workspace_dependency_fail_open(self):
        self.append('core/kontor-sdk-wasm/Cargo.toml', '[dependencies]\nnew={workspace=true}')
        self.assertTrue(all(scope.select('pull_request', {}, self.root)['jobs'].values()))
        self.write('core/kontor-sdk-wasm/Cargo.toml', 'invalid toml = [')
        self.assertTrue(all(scope.select('pull_request', {}, self.root)['jobs'].values()))

    def test_explicit_target_and_build_script_paths(self):
        self.append('core/kontor-sdk-wasm/Cargo.toml', '''
[lib]
path="custom/library.rs"
[[bin]]
name="tool"
path="custom/entry.rs"
''')
        self.write('core/kontor-build/Cargo.toml', '[package]\nname="builder"\nversion="1.0.0"\nbuild="custom/build-script.rs"')
        targets = scope.docker_target_paths(self.root)
        self.assertEqual(targets, {'core/kontor-sdk-wasm/custom/library.rs',
                                  'core/kontor-sdk-wasm/custom/entry.rs',
                                  'core/kontor-build/custom/build-script.rs'})


class WorkflowGateTests(unittest.TestCase):
    def test_required_gate_rejects_failed_cancelled_or_missing_selected_jobs(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        gate = workflow.split('  required-checks:\n', 1)[1].split('  docker-cache-deps:', 1)[0]
        self.assertIn('    if: always()\n', gate)
        raw = gate.split("python3 - <<'PY_CHECK'\n", 1)[1].rsplit('PY_CHECK', 1)[0]
        program = '\n'.join(line[10:] for line in raw.splitlines())
        dependencies = gate.split('    needs: [', 1)[1].split(']', 1)[0].split(', ')
        flags = {'rust': 'false', 'sdk': 'false', 'reproducible': 'false'}
        needs = {name: {'result': 'skipped'} for name in dependencies}
        needs['scope'] = {'result': 'success', 'outputs': flags}

        def passes():
            return subprocess.run([sys.executable, '-c', program],
                                  env={**os.environ, 'NEEDS': json.dumps(needs)},
                                  capture_output=True).returncode == 0

        self.assertTrue(passes())
        flags['sdk'] = 'true'
        self.assertFalse(passes())
        needs['sdk']['result'] = 'success'
        self.assertTrue(passes())
        for result in ('failure', 'cancelled', 'skipped'):
            needs['sdk']['result'] = result
            self.assertFalse(passes())
        needs['sdk']['result'] = 'success'
        needs['scope']['result'] = 'failure'
        self.assertFalse(passes())
        needs['scope']['result'] = 'success'
        flags['rust'] = ''
        self.assertFalse(passes())

    def test_scope_does_not_gate_main_image_publication(self):
        workflow = (ROOT / '.github/workflows/ci.yml').read_text()
        cache_job = workflow.split('  docker-cache-deps:\n', 1)[1].split('  docker-build:', 1)[0]
        self.assertNotIn('    needs:', cache_job)
        self.assertIn('    needs: docker-cache-deps\n', workflow)
        cache = (ROOT / '.github/workflows/docker-cache.yml').read_text()
        self.assertIn('  pull_request:\n  workflow_dispatch:', cache)


if __name__ == '__main__':
    unittest.main()
