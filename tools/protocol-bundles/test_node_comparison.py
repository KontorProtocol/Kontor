import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from build import ROOT, digest, write_json
from compare_node import OWNERSHIP, TARGETS, compare, sources as validate_sources
from provenance import fingerprint, package_sources, repository_sources
from qualify_node import CASES
from recipes import EXECUTOR_GRAPHS, identity
from symbol_tool import TOOLCHAIN


class NodeComparison(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {kind: {'qualification_sources': repository_sources(ROOT, kind),
                             'packages': [{'package': 'path+file://<repository>/core/numerics#0.1.0',
                                           'files': package_sources(ROOT / 'core/numerics')}],
                             'inherited_manifests_and_configuration': {
                                 '/fixture/core/Cargo.toml': digest(ROOT / 'core/Cargo.toml'),
                                 '/fixture/core/numerics/Cargo.toml': digest(ROOT / 'core/numerics/Cargo.toml'),
                                 '/cargo/git/checkouts/wasmtime/crates/core/Cargo.toml': 'external workspace',
                                 **{f'/fixture/protocol-bundles/{name}/Cargo.toml':
                                    digest(ROOT / f'protocol-bundles/{name}/Cargo.toml')
                                    for name in ('node', 'executor-first', 'executor-second')}}}
                       for kind in ('node', 'executor')}

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cells = [self.cell(target) for target in sorted(TARGETS)]

    def cell(self, target, profile='release'):
        directory = self.root / f'{target}-{profile}'
        node_dir = directory / 'node'
        node_dir.mkdir(parents=True)
        graphs = []
        for name in EXECUTOR_GRAPHS:
            graph_dir = directory / name
            graph_dir.mkdir()
            write_json(graph_dir / 'source-inputs.json', self.sources['executor'])
            (graph_dir / 'build.log').write_text('synthetic successful build transcript')
            graph_identity = identity(ROOT, name, EXECUTOR_GRAPHS)
            graph = {'graph': name, 'identity': graph_identity,
                     'lock_sha256': graph_identity['lock_sha256'], 'manifest_sha256': graph_identity['manifest_sha256'],
                     'source_inputs_sha256': fingerprint(self.sources['executor']),
                     'build_log_sha256': digest(graph_dir / 'build.log'),
                     'wrapper_sha256': digest(ROOT / 'tools/protocol-bundles/rustc-wrapper.py')}
            write_json(graph_dir / 'build-inputs.json', graph)
            graphs.append(graph)
        node = {'qualification_command': True, 'executable_sha256': 'synthetic-binary-hash',
                'installed': {'sha256': 'synthetic-binary-hash'},
                'source_inputs_sha256': fingerprint(self.sources['node']),
                'lock_sha256': digest(ROOT / 'protocol-bundles/node/Cargo.lock'),
                'wrapper_sha256': digest(ROOT / 'tools/protocol-bundles/node-rustc-wrapper.py')}
        write_json(node_dir / 'source-inputs.json', self.sources['node'])
        (node_dir / 'build.log').write_text('synthetic node build transcript')
        node['build_log_sha256'] = digest(node_dir / 'build.log')
        spec = {'features': ['protocol-qualification'], 'lock_sha256': node['lock_sha256'],
                'source_inputs_sha256': node['source_inputs_sha256'],
                'graphs': [{'graph': graph['graph'], 'build_inputs_sha256': fingerprint(graph)} for graph in graphs]}
        write_json(node_dir / 'link-spec.json', spec)
        node['link_spec_sha256'] = digest(node_dir / 'link-spec.json')
        write_json(node_dir / 'root-objects.json', {'spec_sha256': node['link_spec_sha256']})
        node['root_codegen_sha256'] = digest(node_dir / 'root-objects.json')
        node['ownership'] = {}
        for name in OWNERSHIP:
            write_json(node_dir / name, {'synthetic': name})
            node['ownership'][name] = digest(node_dir / name)
        compiler = f'rustc {TOOLCHAIN}\nrelease: {TOOLCHAIN}\nhost: {target}\ncommit-hash: test-commit\nLLVM version: test-llvm\n'
        build = {'target': target, 'profile': profile, 'compiler': compiler,
                 'toolchain_inputs': {'compiler': compiler}, 'node': node, 'graphs': graphs}
        write_json(directory / 'node-build.json', build)
        observations = {'schema': 1, 'cases': sorted(CASES), 'executors': [
            {'graph': name, 'observations': {'gas': 17, 'state': 'same'}} for name in EXECUTOR_GRAPHS]}
        write_json(directory / 'node-execution.stdout.json', observations)
        (directory / 'node-execution.stderr.log').write_text('synthetic execution log')
        execution = {'schema': 1, 'matching_observations': True, 'target': target, 'profile': profile,
                     'executable_sha256': node['executable_sha256'], 'cases': observations['cases'],
                     'graphs': list(EXECUTOR_GRAPHS)}
        write_json(directory / 'node-execution.json', execution)
        self.bind(directory)
        return directory

    def bind(self, directory):
        execution = json.loads((directory / 'node-execution.json').read_text())
        for key, name in [('node_build_sha256', 'node-build.json'),
                          ('stdout_sha256', 'node-execution.stdout.json'), ('stderr_sha256', 'node-execution.stderr.log')]:
            execution[key] = digest(directory / name)
        write_json(directory / 'node-execution.json', execution)

    def test_explicit_release_and_full_policies(self):
        self.assertEqual(len(compare(self.root, ROOT, 'release', 'success')['cells']), 3)
        with self.assertRaisesRegex(ValueError, 'missing required'):
            compare(self.root, ROOT, 'full', 'success')
        for target in TARGETS:
            self.cell(target, 'dev')
        self.assertEqual(len(compare(self.root, ROOT, 'full', 'success')['cells']), 6)
        with self.assertRaisesRegex(ValueError, 'unexpected'):
            compare(self.root, ROOT, 'release', 'success')

    def test_missing_duplicate_and_failed_upstream_reject(self):
        with self.assertRaisesRegex(ValueError, 'upstream'):
            compare(self.root, ROOT, 'release', 'failure')
        duplicate = self.root / 'duplicate'
        shutil.copytree(self.cells[0], duplicate)
        with self.assertRaisesRegex(ValueError, 'duplicate'):
            compare(self.root, ROOT, 'release', 'success')
        shutil.rmtree(duplicate)
        shutil.rmtree(self.cells[0])
        with self.assertRaisesRegex(ValueError, 'missing required'):
            compare(self.root, ROOT, 'release', 'success')

    def test_rehashed_cross_platform_mismatch_rejects(self):
        path = self.cells[0] / 'node-execution.stdout.json'
        observations = json.loads(path.read_text())
        for graph in observations['executors']:
            graph['observations']['gas'] += 1
        write_json(path, observations)
        self.bind(self.cells[0])
        with self.assertRaisesRegex(ValueError, 'cross-platform execution'):
            compare(self.root, ROOT, 'release', 'success')

    def test_raw_logs_and_ownership_are_bound(self):
        for relative in ['node-execution.stderr.log', 'node/build.log', 'first/build.log',
                         'node/final-ownership.json', 'node/root-objects.json']:
            with self.subTest(relative=relative):
                path = self.cells[0] / relative
                original = path.read_bytes()
                path.write_bytes(original + b'changed')
                with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                    compare(self.root, ROOT, 'release', 'success')
                path.write_bytes(original)

    def test_rehashed_stale_checkout_sources_reject(self):
        directory = self.cells[0]
        source = copy.deepcopy(self.sources['node'])
        source['qualification_sources']['core/indexer/src/main.rs'] = 'stale source'
        write_json(directory / 'node/source-inputs.json', source)
        build = json.loads((directory / 'node-build.json').read_text())
        build['node']['source_inputs_sha256'] = fingerprint(source)
        write_json(directory / 'node-build.json', build)
        self.bind(directory)
        with self.assertRaisesRegex(ValueError, 'checked-out qualification inputs'):
            compare(self.root, ROOT, 'release', 'success')

    def test_missing_case_rejects(self):
        directory = self.cells[0]
        path = directory / 'node-execution.stdout.json'
        observations = json.loads(path.read_text())
        observations['cases'].pop()
        write_json(path, observations)
        self.bind(directory)
        with self.assertRaisesRegex(ValueError, 'case set'):
            compare(self.root, ROOT, 'release', 'success')

    def test_changed_compiler_rejects(self):
        directory = self.cells[0]
        build = json.loads((directory / 'node-build.json').read_text())
        build['compiler'] = build['compiler'].replace(TOOLCHAIN, '0.0.0')
        build['toolchain_inputs']['compiler'] = build['compiler']
        write_json(directory / 'node-build.json', build)
        self.bind(directory)
        with self.assertRaisesRegex(ValueError, 'wrong compiler'):
            compare(self.root, ROOT, 'release', 'success')

    def test_stale_local_dependency_source_rejects(self):
        directory = self.cells[0]
        source = copy.deepcopy(self.sources['node'])
        source['packages'][0]['files']['src/lib.rs'] = 'stale numerical semantics'
        write_json(directory / 'node/source-inputs.json', source)
        build = json.loads((directory / 'node-build.json').read_text())
        build['node']['source_inputs_sha256'] = fingerprint(source)
        write_json(directory / 'node-build.json', build)
        self.bind(directory)
        with self.assertRaisesRegex(ValueError, 'local package source differs'):
            compare(self.root, ROOT, 'release', 'success')

    def test_comparator_only_changes_preserve_valid_runtime_evidence(self):
        directory = self.cells[0]
        source = copy.deepcopy(self.sources['node'])
        source['qualification_sources']['tools/protocol-bundles/compare_node.py'] = 'previous comparator'
        write_json(directory / 'node/source-inputs.json', source)
        build = json.loads((directory / 'node-build.json').read_text())
        build['node']['source_inputs_sha256'] = fingerprint(source)
        spec = json.loads((directory / 'node/link-spec.json').read_text())
        spec['source_inputs_sha256'] = fingerprint(source)
        write_json(directory / 'node/link-spec.json', spec)
        build['node']['link_spec_sha256'] = digest(directory / 'node/link-spec.json')
        write_json(directory / 'node/root-objects.json', {'spec_sha256': build['node']['link_spec_sha256']})
        build['node']['root_codegen_sha256'] = digest(directory / 'node/root-objects.json')
        write_json(directory / 'node-build.json', build)
        self.bind(directory)
        self.assertEqual(compare(self.root, ROOT, 'release', 'success')['status'], 'passed')

    def test_external_core_workspace_cannot_mask_changed_repository_workspace(self):
        directory = self.cells[0]
        source = copy.deepcopy(self.sources['node'])
        inherited = source['inherited_manifests_and_configuration']
        inherited['/cargo/git/checkouts/wasmtime/crates/core/Cargo.toml'] = digest(ROOT / 'core/Cargo.toml')
        inherited['/fixture/core/Cargo.toml'] = 'changed workspace'
        write_json(directory / 'node/source-inputs.json', source)
        build = json.loads((directory / 'node-build.json').read_text())
        build['node']['source_inputs_sha256'] = fingerprint(source)
        write_json(directory / 'node-build.json', build)
        self.bind(directory)
        with self.assertRaisesRegex(ValueError, 'inherited core workspace changed'):
            compare(self.root, ROOT, 'release', 'success')

    def test_new_inherited_configuration_invalidates_old_artifact(self):
        checkout = self.root / 'checkout'
        source = self.sources['node']
        for recorded in source['inherited_manifests_and_configuration']:
            if recorded.startswith('/fixture/'):
                relative = recorded.removeprefix('/fixture/')
                destination = checkout / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, destination)
        shutil.copytree(ROOT / 'core/numerics', checkout / 'core/numerics', dirs_exist_ok=True)
        report = {'source_inputs_sha256': fingerprint(source)}
        with patch('compare_node.repository_sources', return_value=source['qualification_sources']):
            validate_sources(self.cells[0] / 'node', report, checkout, 'node')
            config = checkout / 'core/.cargo/config.toml'
            config.parent.mkdir()
            config.write_text('[build]\nrustflags = ["-C", "opt-level=1"]\n')
            with self.assertRaisesRegex(ValueError, 'inherited repository input changed: core/.cargo/config.toml'):
                validate_sources(self.cells[0] / 'node', report, checkout, 'node')


if __name__ == '__main__':
    unittest.main()
