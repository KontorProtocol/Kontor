import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

from build import linker_wrapper_source_hash, ROOT, digest, write_json
from compare_node import OWNERSHIP, TARGETS, compare, sources as validate_sources
from provenance import fingerprint, package_sources, repository_sources
from qualify_node import CASES, baseline_graphs
from recipes import CONSENSUS_GRAPHS, EXECUTOR_GRAPHS, executor_graphs, graph_root, identity
from semantic_baseline import verify as verify_semantics
from test_node_execution import sample_observation
from test_node_execution import certified_sample, managed_sample
from test_node_execution import transition_sample, recovery_sample, authorization_sample, join_sample
from symbol_tool import TOOLCHAIN
from type_boundary import ADAPTER_TESTS, PROBES, inputs_for, probes_for


class NodeComparison(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.sources = {kind: {'qualification_sources': repository_sources(ROOT, kind),
                             'rust_build_tools': package_sources(ROOT / 'core/kontor-build', root=ROOT),
                             'packages': [{'package': 'path+file://<repository>/core/numerics#0.1.0',
                                           'files': package_sources(ROOT / 'core/numerics')}],
                             'inherited_manifests_and_configuration': {
                                 '/fixture/core/Cargo.toml': digest(ROOT / 'core/Cargo.toml'),
                                 '/fixture/core/numerics/Cargo.toml': digest(ROOT / 'core/numerics/Cargo.toml'),
                                 '/cargo/git/checkouts/wasmtime/crates/core/Cargo.toml': 'external workspace',
                                 **{f'/fixture/protocol-bundles/{name}/Cargo.toml':
                                    digest(ROOT / f'protocol-bundles/{name}/Cargo.toml')
                                    for name in ('node', *(graph.directory for graph in EXECUTOR_GRAPHS.values()),
                                                 *(graph.directory for graph in CONSENSUS_GRAPHS.values()))}}}
                       for kind in ('node', 'executor', 'consensus')}

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.cells = [self.cell(target) for target in sorted(TARGETS)]

    def cell(self, target, profile='release', link_set=None):
        directory = self.root / f'{target}-{profile}'
        if link_set == 'managed-node':
            directory /= 'executors/managed-node'
        node_dir = directory / 'node'
        node_dir.mkdir(parents=True)
        graphs = []
        consensus = []
        recipes = executor_graphs(link_set)
        entries = [('executor', name, recipe, recipes) for name, recipe in recipes.items()]
        if link_set == 'managed-node':
            entries += [('consensus', name, recipe, CONSENSUS_GRAPHS) for name, recipe in CONSENSUS_GRAPHS.items()]
        for role, name, recipe, selected in entries:
            graph_dir = directory.parents[1] / 'consensus' / name if role == 'consensus' else directory / name
            graph_dir.mkdir(parents=True)
            source = self.sources[role]
            if link_set is not None:
                source_root = graph_root(ROOT, recipe)
                source = copy.deepcopy(source)
                source['qualification_sources'] = repository_sources(source_root, role)
                source['packages'][0]['files'] = package_sources(source_root / 'core/numerics', root=source_root)
                source['inherited_manifests_and_configuration'] = {
                    name: digest(source_root / name.removeprefix('/fixture/'))
                    for name in source['inherited_manifests_and_configuration']
                    if name.startswith('/fixture/') and (source_root / name.removeprefix('/fixture/')).is_file()}
                source['inherited_manifests_and_configuration'][f'/fixture/protocol-bundles/{recipe.directory}/Cargo.toml'] = digest(
                    source_root / f'protocol-bundles/{recipe.directory}/Cargo.toml')
                if source_root != ROOT:
                    source['build_tools'] = package_sources(ROOT / 'tools/protocol-bundles', root=ROOT)
            write_json(graph_dir / 'source-inputs.json', source)
            (graph_dir / 'build.log').write_text('synthetic successful build transcript')
            graph_identity = identity(ROOT, name, selected)
            graph = {'graph': name, 'identity': graph_identity,
                     'lock_sha256': graph_identity['lock_sha256'], 'manifest_sha256': graph_identity['manifest_sha256'],
                     'source_inputs_sha256': fingerprint(source),
                     'build_log_sha256': digest(graph_dir / 'build.log'),
                     'wrapper_sha256': digest(ROOT / 'core/kontor-build/src/bin/kontor-graph-rustc.rs'),
                     'wrapper_binary_sha256': 'ab' * 32,
                     'wrapper': '/synthetic/compiler-wrapper/' + 'ab' * 32 + '/kontor-graph-rustc'}
            graph['link_inputs'] = f'/synthetic/{role}/{name}'
            graph['facade'] = f'/synthetic/{role}/{name}/libkontor_{role}_{name}.rlib'
            dependencies = ('tokio',) if role == 'consensus' else ('wasmtime', 'tokio')
            paths = [graph['facade']] + [f'/synthetic/{role}/{name}/lib{dep}-test.rlib' for dep in dependencies]
            graph['artifacts'] = [{'path': path, 'sha256': 'synthetic-' + path} for path in paths]
            write_json(graph_dir / 'build-inputs.json', graph)
            (consensus if role == 'consensus' else graphs).append(graph)
        node = {'qualification_command': True, 'executable_sha256': 'ef' * 32,
                'installed': {'sha256': 'ef' * 32},
                'source_inputs_sha256': fingerprint(self.sources['node']),
                'lock_sha256': digest(ROOT / 'protocol-bundles/node/Cargo.lock'),
                'wrapper_sha256': digest(ROOT / 'core/kontor-build/src/bin/kontor-node-rustc.rs'),
                'linker_wrapper_sha256': linker_wrapper_source_hash(ROOT),
                'linker_wrapper_binary_sha256': 'cd' * 32}
        write_json(node_dir / 'source-inputs.json', self.sources['node'])
        (node_dir / 'build.log').write_text('synthetic node build transcript')
        node['build_log_sha256'] = digest(node_dir / 'build.log')
        spec = {'features': ['protocol-qualification'], 'lock_sha256': node['lock_sha256'], 'link_set': link_set,
                'linker_wrapper_sha256': node['linker_wrapper_binary_sha256'],
                'linker_wrapper': '/synthetic/compiler-wrapper/' + 'cd' * 32 + '/kontor-node-linker',
                'source_inputs_sha256': node['source_inputs_sha256'],
                'graphs': [{'graph': graph['graph'], 'role': role, 'build_inputs_sha256': fingerprint(graph)}
                           for role, group in (('executor', graphs), ('consensus', consensus)) for graph in group]}
        node['wrapper_binary_sha256'] = 'bc' * 32
        node['wrapper'] = '/synthetic/rustc-wrapper-' + fingerprint(spec) + '-' + node['wrapper_binary_sha256']
        write_json(node_dir / 'link-spec.json', spec)
        node['link_spec_sha256'] = digest(node_dir / 'link-spec.json')
        link = {'schema': 1, 'spec_sha256': node['link_spec_sha256'],
                'output_sha256': node['executable_sha256'], 'output': '/synthetic/kontor',
                'arguments': ['-o', '/synthetic/kontor'], 'expanded_arguments': ['-o', '/synthetic/kontor'],
                'working_directory': '/synthetic',
                'driver': {'invocation_path': '/synthetic/cc', 'path': '/synthetic/cc', 'sha256': 'ab' * 32},
                'backend': {'invocation_path': '/synthetic/ld', 'path': '/synthetic/ld', 'sha256': 'cd' * 32},
                'selection': {'method': 'compiler-driver-plan',
                              'command': ['/synthetic/cc', '-###', '-o', '/synthetic/kontor'],
                              'stderr': 'synthetic driver plan'}}
        write_json(node_dir / 'linker-record.json', link)
        node['linker_record_sha256'] = digest(node_dir / 'linker-record.json')
        write_json(node_dir / 'root-objects.json', {'spec_sha256': node['link_spec_sha256'],
                                                  'linker_record_sha256': node['linker_record_sha256'],
                                                  'compiler_output': {'path': link['output'], 'sha256': node['executable_sha256']}})
        node['root_codegen_sha256'] = digest(node_dir / 'root-objects.json')
        node['ownership'] = {}
        for name in OWNERSHIP:
            write_json(node_dir / name, {'synthetic': name})
            node['ownership'][name] = digest(node_dir / name)
        compiler = f'rustc {TOOLCHAIN}\nrelease: {TOOLCHAIN}\nhost: {target}\ncommit-hash: test-commit\nLLVM version: test-llvm\n'
        def interface(group, checks):
            checks.mkdir(parents=True)
            probes = probes_for(group)
            controls = {}
            for name, (expected, source) in probes.items():
                source_path = checks / f'{name}.rs'
                source_path.write_text(source)
                log = checks / f'{name}.log'
                log.write_text(json.dumps({'level': 'error', 'code': {'code': expected}}) if expected else '')
                controls[name] = {'expected_error': expected, 'returncode': 1 if expected else 0,
                                  'source_sha256': digest(source_path), 'diagnostics_sha256': digest(log)}
            write_json(checks / 'result.json', {'schema': 1, 'status': 'passed', 'target': target,
                       'libraries': inputs_for(group, False)[1],
                       'graph_inputs': {graph['graph']: fingerprint(graph) for graph in group}, 'controls': controls})
            return {'report_sha256': digest(checks / 'result.json'), 'controls': list(probes)}
        node['interface_checks'] = interface(graphs, node_dir / 'type-boundary')
        if consensus:
            node['consensus_interface_checks'] = interface(consensus, node_dir / 'consensus/type-boundary')
            adapter = node_dir / 'consensus/node-adapter'
            adapter.mkdir()
            (adapter / 'adapter.rs').write_text('mod managed {\n' + ''.join(
                f'#[path = "/fixture/core/indexer/src/protocol/coordinator/managed/{name}.rs"]\npub(crate) mod {name};\n'
                for name in ('types', 'adapter')) + '}\n')
            (adapter / 'compile.log').write_text('synthetic successful compile')
            (adapter / 'test.log').write_text('\n'.join(f'test {name} ... ok' for name in ADAPTER_TESTS)
                                             + f'\ntest result: ok. {len(ADAPTER_TESTS)} passed; 0 failed; 0 ignored;')
            node['consensus_adapter_checks'] = {
                'tests': ADAPTER_TESTS, 'source_sha256': digest(adapter / 'adapter.rs'),
                'compiler_log_sha256': digest(adapter / 'compile.log'), 'test_log_sha256': digest(adapter / 'test.log'),
                'libraries': inputs_for(consensus, False)[1],
                'graph_inputs': {graph['graph']: fingerprint(graph) for graph in consensus}}
        build = {'target': target, 'profile': profile, 'compiler': compiler, 'link_set': link_set,
                 'toolchain_inputs': {'compiler': compiler}, 'node': node, 'graphs': graphs, 'consensus_graphs': consensus}
        write_json(directory / 'node-build.json', build)
        observations = {'schema': 1, 'cases': sorted(CASES), 'executors': [
            {'graph': name, 'observations': sample_observation()} for name in baseline_graphs(link_set)]}
        observations['storage_contracts'] = {'rejected_before_construction': [
            f'{graph}:{mutation}' for graph in recipes
            for mutation in ('missing', 'unknown', 'changed', 'multiple')]}
        if link_set in ('k4-node', 'managed-node'):
            observations['certified_history'] = certified_sample(link_set)
        if link_set == 'managed-node':
            observations['managed_startup'] = managed_sample(observations['certified_history'])
        write_json(directory / 'node-execution.stdout.json', observations)
        (directory / 'node-execution.stderr.log').write_text('synthetic execution log')
        execution = {'schema': 1, 'matching_observations': True, 'target': target, 'profile': profile, 'link_set': link_set,
                     'executable_sha256': node['executable_sha256'], 'cases': observations['cases'],
                     'graphs': list(recipes), 'semantic_baseline': verify_semantics(observations, ROOT, baseline_graphs(link_set))}
        if link_set == 'managed-node':
            write_json(directory / 'node-authorization.stdout.json', authorization_sample())
            write_json(directory / 'node-join.stdout.json', join_sample())
            (directory / 'node-join.stderr.log').write_text('synthetic join log')
            execution['join'] = {'stdout_sha256': digest(directory / 'node-join.stdout.json'),
                                 'stderr_sha256': digest(directory / 'node-join.stderr.log')}
            (directory / 'node-authorization.stderr.log').write_text('synthetic authorization log')
            execution['authorization'] = {'stdout_sha256': digest(directory / 'node-authorization.stdout.json'),
                                         'stderr_sha256': digest(directory / 'node-authorization.stderr.log')}
            write_json(directory / 'node-recovery.stdout.json', recovery_sample())
            (directory / 'node-recovery.stderr.log').write_text('synthetic recovery log')
            execution['recovery'] = {'stdout_sha256': digest(directory / 'node-recovery.stdout.json'),
                                     'stderr_sha256': digest(directory / 'node-recovery.stderr.log')}
            write_json(directory / 'node-transition.stdout.json', transition_sample())
            (directory / 'node-transition.stderr.log').write_text('synthetic transition log')
            execution['transition'] = {
                'stdout_sha256': digest(directory / 'node-transition.stdout.json'),
                'stderr_sha256': digest(directory / 'node-transition.stderr.log')}
        write_json(directory / 'node-execution.json', execution)
        self.bind(directory)
        return directory

    def test_managed_comparison_requires_transition_raw_evidence(self):
        for cell in self.cells:
            shutil.rmtree(cell)
        cells = [self.cell(target, link_set='managed-node') for target in sorted(TARGETS)]
        directory = cells[0]
        path = directory / 'node-execution.json'
        original = json.loads(path.read_text())
        changed = copy.deepcopy(original)
        changed.pop('transition')
        write_json(path, changed)
        with self.assertRaisesRegex(ValueError, 'missing managed transition evidence'):
            compare(self.root, ROOT, 'release', 'success', 'managed-node')
        write_json(path, original)
        raw = directory / 'node-transition.stdout.json'
        result = json.loads(raw.read_text())
        result['closed_decisions'] = 5
        write_json(raw, result)
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            compare(self.root, ROOT, 'release', 'success', 'managed-node')
        original['transition']['stdout_sha256'] = digest(raw)
        write_json(path, original)
        with self.assertRaisesRegex(ValueError, 'transition checks'):
            compare(self.root, ROOT, 'release', 'success', 'managed-node')

    def test_managed_comparison_requires_join_raw_evidence(self):
        for cell in self.cells:
            shutil.rmtree(cell)
        cells = [self.cell(target, link_set='managed-node') for target in sorted(TARGETS)]
        directory = cells[0]
        path = directory / 'node-execution.json'
        original = json.loads(path.read_text())
        changed = copy.deepcopy(original)
        changed.pop('join')
        write_json(path, changed)
        with self.assertRaisesRegex(ValueError, 'missing managed join evidence'):
            compare(self.root, ROOT, 'release', 'success', 'managed-node')
        write_json(path, original)
        raw = directory / 'node-join.stdout.json'
        result = json.loads(raw.read_text())
        result['required_promoted_vote'] = False
        write_json(raw, result)
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            compare(self.root, ROOT, 'release', 'success', 'managed-node')
        original['join']['stdout_sha256'] = digest(raw)
        write_json(path, original)
        with self.assertRaisesRegex(ValueError, 'join did not verify'):
            compare(self.root, ROOT, 'release', 'success', 'managed-node')

    def test_managed_comparison_requires_recovery_raw_evidence(self):
        for cell in self.cells:
            shutil.rmtree(cell)
        cells = [self.cell(target, link_set='managed-node') for target in sorted(TARGETS)]
        directory = cells[0]
        path = directory / 'node-execution.json'
        original = json.loads(path.read_text())
        changed = copy.deepcopy(original)
        changed.pop('recovery')
        write_json(path, changed)
        with self.assertRaisesRegex(ValueError, 'missing managed recovery evidence'):
            compare(self.root, ROOT, 'release', 'success', 'managed-node')
        write_json(path, original)
        raw = directory / 'node-recovery.stdout.json'
        result = json.loads(raw.read_text())
        result['finality_replay'].pop()
        write_json(raw, result)
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            compare(self.root, ROOT, 'release', 'success', 'managed-node')
        original['recovery']['stdout_sha256'] = digest(raw)
        write_json(path, original)
        with self.assertRaisesRegex(ValueError, 'recovery replay cases missing'):
            compare(self.root, ROOT, 'release', 'success', 'managed-node')

    def test_managed_comparison_requires_authorization_raw_evidence(self):
        for cell in self.cells:
            shutil.rmtree(cell)
        cells = [self.cell(target, link_set='managed-node') for target in sorted(TARGETS)]
        directory = cells[0]
        path = directory / 'node-execution.json'
        original = json.loads(path.read_text())
        changed = copy.deepcopy(original)
        changed.pop('authorization')
        write_json(path, changed)
        with self.assertRaisesRegex(ValueError, 'missing managed authorization evidence'):
            compare(self.root, ROOT, 'release', 'success', 'managed-node')
        write_json(path, original)
        raw = directory / 'node-authorization.stdout.json'
        result = json.loads(raw.read_text())
        result['orphaned_p2_batch_not_replayed'] = False
        write_json(raw, result)
        with self.assertRaisesRegex(ValueError, 'hash mismatch'):
            compare(self.root, ROOT, 'release', 'success', 'managed-node')
        original['authorization']['stdout_sha256'] = digest(raw)
        write_json(path, original)
        with self.assertRaisesRegex(ValueError, 'authorization replay evidence missing'):
            compare(self.root, ROOT, 'release', 'success', 'managed-node')

    def test_managed_comparison_binds_consensus_sources_and_actual_controls(self):
        for cell in self.cells:
            shutil.rmtree(cell)
        cells = [self.cell(target, link_set='managed-node') for target in sorted(TARGETS)]
        self.assertEqual(compare(self.root, ROOT, 'release', 'success', 'managed-node')['status'], 'passed')
        directory = cells[0]
        build_path = directory / 'node-build.json'
        original = json.loads(build_path.read_text())
        for mutation in ('missing', 'substituted', 'adapter', 'interface'):
            build = copy.deepcopy(original)
            if mutation == 'missing':
                build['consensus_graphs'].pop()
            elif mutation == 'substituted':
                build['consensus_graphs'][0] = build['graphs'][0]
            elif mutation == 'adapter':
                build['node']['consensus_adapter_checks']['graph_inputs']['first'] = 'other build'
            else:
                build['node']['consensus_interface_checks']['report_sha256'] = 'other report'
            write_json(build_path, build)
            self.bind(directory)
            with self.subTest(mutation=mutation), self.assertRaises((RuntimeError, ValueError)):
                compare(self.root, ROOT, 'release', 'success', 'managed-node')
        write_json(build_path, original)
        self.bind(directory)
        log = directory / 'node/consensus/node-adapter/test.log'
        log.write_text(log.read_text().replace('0 ignored', '1 ignored'))
        original['node']['consensus_adapter_checks']['test_log_sha256'] = digest(log)
        write_json(build_path, original)
        self.bind(directory)
        with self.assertRaisesRegex(RuntimeError, 'tests missing or failed'):
            compare(self.root, ROOT, 'release', 'success', 'managed-node')

    def test_k4_comparator_rejects_missing_certified_result(self):
        for cell in self.cells:
            shutil.rmtree(cell)
        for target in sorted(TARGETS):
            self.cell(target, link_set='k4-node')
        compare(self.root, ROOT, 'release', 'success', 'k4-node')
        directory = self.cells[0]
        path = directory / 'node-execution.stdout.json'
        observations = json.loads(path.read_text())
        observations.pop('certified_history')
        write_json(path, observations)
        self.bind(directory)
        with self.assertRaisesRegex(RuntimeError, 'certified history evidence'):
            compare(self.root, ROOT, 'release', 'success', 'k4-node')

    def test_retained_link_set_is_explicit_and_validates_both_source_roots(self):
        for cell in self.cells:
            shutil.rmtree(cell)
        for target in sorted(TARGETS):
            self.cell(target, link_set='legacy-qualification')
        result = compare(self.root, ROOT, 'release', 'success', 'legacy-qualification')
        self.assertEqual(result['link_set'], 'legacy-qualification')
        with self.assertRaisesRegex(ValueError, 'link set mismatch'):
            compare(self.root, ROOT, 'release', 'success')
        with self.assertRaisesRegex(ValueError, 'unknown executor link set'):
            compare(self.root, ROOT, 'release', 'success', 'unsupported')
        directory = self.cells[0]
        inventory = json.loads((directory / 'first/source-inputs.json').read_text())
        inventory['build_tools']['build.py'] = 'unrecorded build change'
        write_json(directory / 'first/source-inputs.json', inventory)
        report = json.loads((directory / 'first/build-inputs.json').read_text())
        report['source_inputs_sha256'] = fingerprint(inventory)
        with self.assertRaisesRegex(ValueError, 'current build-tool inventory differs'):
            validate_sources(directory / 'first', report,
                             graph_root(ROOT, executor_graphs('legacy-qualification')['first']),
                             'executor', tool_root=ROOT)

    def test_observer_link_set_cannot_substitute_for_legacy_qualification(self):
        for cell in self.cells:
            shutil.rmtree(cell)
        for target in sorted(TARGETS):
            self.cell(target, link_set='k4-node')
        self.assertEqual(compare(self.root, ROOT, 'release', 'success', 'k4-node')['status'], 'passed')
        with self.assertRaisesRegex(ValueError, 'link set mismatch'):
            compare(self.root, ROOT, 'release', 'success', 'legacy-qualification')

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
                         'node/final-ownership.json', 'node/node-input-ownership.json', 'node/root-objects.json']:
            with self.subTest(relative=relative):
                path = self.cells[0] / relative
                original = path.read_bytes()
                path.write_bytes(original + b'changed')
                with self.assertRaisesRegex(ValueError, 'hash mismatch'):
                    compare(self.root, ROOT, 'release', 'success')
                path.write_bytes(original)

    def test_rehashed_shared_historical_regression_rejects(self):
        for directory in self.cells:
            path = directory / 'node-execution.stdout.json'
            observations = json.loads(path.read_text())
            for graph in observations['executors']:
                graph['observations']['malformed_transaction'] = 'changed error'
            write_json(path, observations)
            self.bind(directory)
        with self.assertRaisesRegex(ValueError, 'historical semantic comparison differs'):
            compare(self.root, ROOT, 'release', 'success')

    def test_rehashed_unrelated_compile_error_is_not_type_isolation(self):
        directory = self.cells[0]
        checks = directory / 'node/type-boundary'
        log = checks / 'wasmtime-engine.log'
        log.write_text(json.dumps({'level': 'error', 'code': {'code': 'E0463'}}))
        report = json.loads((checks / 'result.json').read_text())
        report['controls']['wasmtime-engine']['diagnostics_sha256'] = digest(log)
        write_json(checks / 'result.json', report)
        build = json.loads((directory / 'node-build.json').read_text())
        build['node']['interface_checks']['report_sha256'] = digest(checks / 'result.json')
        write_json(directory / 'node-build.json', build)
        self.bind(directory)
        with self.assertRaisesRegex(RuntimeError, 'interface control failed'):
            compare(self.root, ROOT, 'release', 'success')

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

    def test_rehashed_stale_rust_build_tool_sources_reject(self):
        directory = self.cells[0]
        source = copy.deepcopy(self.sources['node'])
        source['rust_build_tools']['src/compiler_wrapper.rs'] = 'substituted wrapper source'
        write_json(directory / 'node/source-inputs.json', source)
        build = json.loads((directory / 'node-build.json').read_text())
        build['node']['source_inputs_sha256'] = fingerprint(source)
        write_json(directory / 'node-build.json', build)
        self.bind(directory)
        with self.assertRaisesRegex(ValueError, 'Rust build-tool inventory differs'):
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

    def test_node_wrapper_identity_cannot_be_missing_or_substituted(self):
        directory = self.cells[0]
        original = json.loads((directory / 'node-build.json').read_text())
        for field, value in (('wrapper_binary_sha256', ''), ('wrapper_binary_sha256', 'ab' * 32),
                             ('wrapper', '/synthetic/another-wrapper'), ('wrapper_sha256', '00' * 32)):
            build = copy.deepcopy(original)
            build['node'][field] = value
            write_json(directory / 'node-build.json', build)
            self.bind(directory)
            with self.subTest(field=field, value=value), self.assertRaises(ValueError):
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
        build['node']['wrapper'] = '/synthetic/rustc-wrapper-' + fingerprint(spec) + '-' + build['node']['wrapper_binary_sha256']
        write_json(directory / 'node/link-spec.json', spec)
        build['node']['link_spec_sha256'] = digest(directory / 'node/link-spec.json')
        link = json.loads((directory / 'node/linker-record.json').read_text())
        link['spec_sha256'] = build['node']['link_spec_sha256']
        write_json(directory / 'node/linker-record.json', link)
        build['node']['linker_record_sha256'] = digest(directory / 'node/linker-record.json')
        write_json(directory / 'node/root-objects.json', {'spec_sha256': build['node']['link_spec_sha256'],
            'linker_record_sha256': build['node']['linker_record_sha256'],
            'compiler_output': {'path': link['output'], 'sha256': build['node']['executable_sha256']}})
        build['node']['root_codegen_sha256'] = digest(directory / 'node/root-objects.json')
        write_json(directory / 'node-build.json', build)
        self.bind(directory)
        self.assertEqual(compare(self.root, ROOT, 'release', 'success')['status'], 'passed')

    def test_final_output_requires_completed_compiler_capture(self):
        directory = self.cells[0]
        build = json.loads((directory / 'node-build.json').read_text())
        root_path = directory / 'node/root-objects.json'
        original = json.loads(root_path.read_text())
        for capture in (None, {}, {'path': '/another/output', 'sha256': build['node']['executable_sha256']},
                        {'path': '/synthetic/kontor', 'sha256': '00' * 32}):
            changed = dict(original, compiler_output=capture)
            write_json(root_path, changed)
            build['node']['root_codegen_sha256'] = digest(root_path)
            write_json(directory / 'node-build.json', build)
            self.bind(directory)
            with self.subTest(capture=capture), self.assertRaisesRegex((ValueError, RuntimeError), 'compiler output'):
                compare(self.root, ROOT, 'release', 'success')

    def test_post_link_processing_preserves_both_stage_bindings(self):
        directory = self.cells[0]
        build = json.loads((directory / 'node-build.json').read_text())
        link_path = directory / 'node/linker-record.json'
        link = json.loads(link_path.read_text())
        link['output_sha256'] = 'ab' * 32
        write_json(link_path, link)
        build['node']['linker_record_sha256'] = digest(link_path)
        root_path = directory / 'node/root-objects.json'
        root = json.loads(root_path.read_text())
        root['linker_record_sha256'] = digest(link_path)
        write_json(root_path, root)
        build['node']['root_codegen_sha256'] = digest(root_path)
        write_json(directory / 'node-build.json', build)
        self.bind(directory)
        self.assertEqual(compare(self.root, ROOT, 'release', 'success')['status'], 'passed')
        root['linker_record_sha256'] = '00' * 32
        write_json(root_path, root)
        build['node']['root_codegen_sha256'] = digest(root_path)
        write_json(directory / 'node-build.json', build)
        self.bind(directory)
        with self.assertRaisesRegex(ValueError, 'compiler and linker records disagree'):
            compare(self.root, ROOT, 'release', 'success')

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
        shutil.copytree(ROOT / 'core/kontor-build', checkout / 'core/kontor-build',
                        ignore=shutil.ignore_patterns('target'))
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
