import copy
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from build import digest, install_node, node_codegen_objects, node_dependencies, node_executable, node_link_inputs
from linker_record import validate as validate_linker_record
from provenance import node_sources

spec = importlib.util.spec_from_file_location('node_wrapper', Path(__file__).with_name('node-rustc-wrapper.py'))
wrapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wrapper)


class NodeBuild(unittest.TestCase):
    @unittest.skipUnless(shutil.which('rustc') and shutil.which('cc'), 'Rust and C driver required')
    def test_real_compiler_output_includes_post_link_processing(self):
        compiler = shutil.which('rustc')
        self.spec['compiler'] = compiler
        shim = self.root / 'cc'
        shutil.copyfile(Path(__file__).with_name('linker_record.py'), shim)
        shim.chmod(0o755)
        self.spec.update(linker_wrapper=str(shim), linker_wrapper_sha256=digest(shim),
                         linker_record=str(self.root / 'linker.json'),
                         root_objects=str(self.root / 'objects.json'))
        spec_path = self.root / 'link-spec.json'
        spec_path.write_text(json.dumps(self.spec))
        source = self.root / 'main.rs'
        source.write_text('fn main() { println!("compiler output"); }\n')
        result = subprocess.run([
            sys.executable, str(Path(wrapper.__file__)), compiler, str(source),
            '--crate-name', 'kontor', '--crate-type', 'bin', '--out-dir', str(self.root),
            '-C', 'extra-filename=-test', '-C', 'debuginfo=2', '-C', 'strip=debuginfo',
        ], env=dict(os.environ, KONTOR_NODE_LINK_SPEC=str(spec_path), CCACHE_DISABLE='1'),
            capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stderr)
        link = json.loads(Path(self.spec['linker_record']).read_text())
        root = json.loads(Path(self.spec['root_objects']).read_text())
        output = self.root / 'kontor-test'
        self.assertEqual(root['linker_record_sha256'], digest(Path(self.spec['linker_record'])))
        self.assertEqual(root['compiler_output'], {'path': str(output), 'sha256': digest(output)})
        validate_linker_record(link, digest(spec_path), digest(output), root['compiler_output'])
        self.assertEqual(subprocess.check_output([str(output)], text=True), 'compiler output\n')
        if sys.platform == 'darwin':
            self.assertNotEqual(link['output_sha256'], digest(output))
        output.write_bytes(output.read_bytes() + b'changed after compiler')
        with self.assertRaisesRegex(RuntimeError, 'compiler output'):
            validate_linker_record(link, digest(spec_path), digest(output), root['compiler_output'])
        source.write_text('invalid Rust source')
        failed = subprocess.run(result.args,
                                env=dict(os.environ, KONTOR_NODE_LINK_SPEC=str(spec_path)),
                                capture_output=True, text=True, timeout=60)
        self.assertNotEqual(failed.returncode, 0)
        self.assertFalse(Path(self.spec['root_objects']).exists())
        self.assertFalse(Path(self.spec['linker_record']).exists())

    def test_linker_driver_uses_last_rustc_override(self):
        self.assertEqual(wrapper.linker_driver([]), 'cc')
        self.assertEqual(wrapper.linker_driver(['-C', 'linker=/bin/clang']), '/bin/clang')
        self.assertEqual(wrapper.linker_driver(['-Clinker=/bin/cc', '-C', 'linker=/bin/clang']), '/bin/clang')

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.facade = self.root / 'libkontor_executor_first.rlib'
        self.facade.write_bytes(b'compiled retained graph')
        self.spec = {'compiler': '/pinned/rustc', 'graphs': [
            {'graph': 'first', 'facade': str(self.facade), 'facade_sha256': digest(self.facade),
             'link_inputs': str(self.root)}]}

    def test_embedded_attestation_matches_compiler_target_and_linked_inputs(self):
        self.spec['link_set'] = 'managed-node'
        prototype = dict(self.spec['graphs'][0], build_inputs_sha256='a' * 64)
        self.spec['graphs'] = [dict(prototype, role=role, graph=graph) for role, graph in (
            ('executor', 'first'), ('executor', 'observer'),
            ('consensus', 'first'))]
        arguments = ['--target', 'aarch64-unknown-linux-gnu']
        with self.assertRaisesRegex(RuntimeError, 'requires'):
            wrapper.attestation_environment(arguments, self.spec)
        record = {'schema': 1, 'link_set': 'managed-node', 'target': arguments[1],
                  'graphs': [{key: graph[key] for key in
                              ('role', 'graph', 'facade_sha256', 'build_inputs_sha256')}
                             for graph in self.spec['graphs']]}
        self.spec['attestation'] = record
        environment = wrapper.attestation_environment(arguments, self.spec)
        self.assertEqual(json.loads(environment['KONTOR_NODE_ATTESTATION']), record)
        with self.assertRaisesRegex(RuntimeError, 'target'):
            wrapper.attestation_environment(['--target', 'x86_64-unknown-linux-gnu'], self.spec)
        for index in range(3):
            for field in ('role', 'graph', 'facade_sha256', 'build_inputs_sha256'):
                changed = copy.deepcopy(self.spec)
                changed['attestation']['graphs'][index][field] = 'wrong'
                with self.subTest(index=index, field=field), self.assertRaisesRegex(RuntimeError, 'differs'):
                    wrapper.attestation_environment(arguments, changed)

    def test_library_and_binary_receive_retained_search_paths(self):
        for crate in ('indexer', 'kontor'):
            with self.subTest(crate=crate):
                args, capture = wrapper.prepare('/pinned/rustc', [
                    '--crate-name', crate, '--out-dir', str(self.root), '-C', 'extra-filename=-abcd'], self.spec)
                self.assertIn('dependency=' + str(self.root), args)
                self.assertEqual('--extern' in args, crate == 'indexer')
                self.assertEqual(capture is not None, crate == 'kontor')
                if capture:
                    self.assertEqual(capture, (self.root, 'kontor-abcd.*.rcgu.o'))
                    self.assertIn('-Csave-temps', args)
        args = ['--crate-name', 'build_script_build']
        self.assertEqual(wrapper.prepare('/pinned/rustc', args, self.spec), (args, None))
        self.assertEqual(wrapper.prepare('/pinned/rustc', ['-vV'], self.spec), (['-vV'], None))

    def test_external_facade_and_compiler_changes_are_rejected(self):
        with self.assertRaisesRegex(RuntimeError, 'pinned compiler'):
            wrapper.prepare('/another/rustc', [], self.spec)
        self.facade.write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'facade changed'):
            wrapper.prepare('/pinned/rustc', ['--crate-name', 'indexer'], self.spec)

    def test_observer_configuration_requires_its_explicit_library_set(self):
        self.spec['link_set'] = 'k4-node'
        with self.assertRaisesRegex(RuntimeError, 'does not match'):
            wrapper.prepare('/pinned/rustc', ['--crate-name', 'indexer'], self.spec)

        observer = copy.deepcopy(self.spec['graphs'][0])
        observer['graph'] = 'observer'
        self.spec['graphs'].append(observer)
        arguments, _ = wrapper.prepare('/pinned/rustc', ['--crate-name', 'indexer'], self.spec)
        self.assertIn('kontor_observer', arguments)
        self.assertIn('kontor_executor_observer=' + str(self.facade), arguments)
        self.assertNotIn('kontor_executor_second=' + str(self.facade), arguments)
        self.spec['link_set'] = 'legacy-qualification'
        with self.assertRaisesRegex(RuntimeError, 'does not match'):
            wrapper.prepare('/pinned/rustc', ['--crate-name', 'indexer'], self.spec)

    def test_managed_node_requires_two_executors_and_one_runtime(self):
        self.spec['link_set'] = 'managed-node'
        prototype = self.spec['graphs'][0]
        self.spec['graphs'] = [dict(prototype, role=role, graph=graph) for role, graph in (
            ('executor', 'first'), ('executor', 'observer'),
            ('consensus', 'first'))]
        for crate in ('indexer', 'kontor'):
            args, _ = wrapper.prepare('/pinned/rustc', [
                '--crate-name', crate, '--out-dir', str(self.root), '-C', 'extra-filename=-abcd'], self.spec)
            self.assertIn('kontor_managed', args)
            self.assertIn('kontor_observer', args)
            self.assertEqual(args.count('-L'), 3)
            self.assertEqual(args.count('--extern'), 3 if crate == 'indexer' else 0)
            if crate == 'indexer':
                for role, graph in (('executor', 'first'), ('executor', 'observer'),
                                    ('consensus', 'first')):
                    self.assertIn(f'kontor_{role}_{graph}={self.facade}', args)
        extra = copy.deepcopy(self.spec)
        extra['graphs'].append(dict(prototype, role='consensus', graph='second'))
        broken = [extra]
        for index in range(3):
            missing = copy.deepcopy(self.spec)
            del missing['graphs'][index]
            broken.append(missing)
            wrong_role = copy.deepcopy(self.spec)
            wrong_role['graphs'][index]['role'] = 'consensus' if index < 2 else 'executor'
            broken.append(wrong_role)
        for value in broken:
            with self.assertRaisesRegex(RuntimeError, 'does not match'):
                wrapper.prepare('/pinned/rustc', ['--crate-name', 'indexer'], value)

    def test_audit_roles_do_not_relabel_graph_provenance(self):
        base = dict(self.spec['graphs'][0], namespace='independent-executor')
        consensus = dict(base, namespace='independent-consensus', identity={'kind': 'consensus'})
        executors = [base]
        engines = [consensus]
        originals = copy.deepcopy((executors, engines))
        audited, libraries = node_link_inputs(executors, engines)
        self.assertEqual([graph['graph'] for graph in audited], ['executor-first', 'consensus-first'])
        self.assertEqual([graph['namespace'] for graph in audited],
                         ['independent-executor', 'independent-consensus'])
        self.assertEqual([(graph['role'], graph['graph']) for graph in libraries],
                         [('executor', 'first'), ('consensus', 'first')])
        self.assertEqual((executors, engines), originals)
        self.assertEqual(node_link_inputs(executors, [])[0], executors)

    @unittest.skipUnless(os.name == 'posix', 'Cargo pipe jobserver uses POSIX descriptors')
    def test_wrapper_preserves_cargo_jobserver_descriptors(self):
        read_fd, write_fd = os.pipe()
        self.addCleanup(os.close, read_fd)
        self.addCleanup(os.close, write_fd)
        os.write(write_fd, b'+')
        compiler = self.root / 'compiler.py'
        compiler.write_text(
            'import os\n'
            'auth = os.environ["CARGO_MAKEFLAGS"].split("--jobserver-auth=", 1)[1].split()[0]\n'
            'read_fd, write_fd = map(int, auth.split(","))\n'
            'token = os.read(read_fd, 1)\n'
            'assert token == b"+"\n'
            'os.write(write_fd, token)\n'
        )
        spec_path = self.root / 'link-spec.json'
        spec_path.write_text(json.dumps({'compiler': sys.executable, 'graphs': []}))
        result = subprocess.run(
            [sys.executable, str(Path(wrapper.__file__)), sys.executable, str(compiler)],
            env=dict(os.environ, KONTOR_NODE_LINK_SPEC=str(spec_path),
                     CARGO_MAKEFLAGS=f'-j --jobserver-auth={read_fd},{write_fd}'),
            pass_fds=(read_fd, write_fd), capture_output=True, text=True, timeout=10,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(os.read(read_fd, 1), b'+')

    def test_node_graph_rejects_hidden_executor_dependency(self):
        node_dependencies({'packages': [{'name': 'libsql'}]})
        for name in ('wasmtime', 'wasmtime-internal-cranelift', 'kontor-executor-first', 'kontor-consensus-first'):
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, 'retained execution'):
                node_dependencies({'packages': [{'name': name}]})
        with self.assertRaisesRegex(RuntimeError, 'native patch'):
            node_dependencies({'packages': [{'name': 'psm', 'manifest_path': '/registry/psm/Cargo.toml'}]})

    def test_codegen_capture_rejects_stale_spec_or_modified_objects(self):
        path = self.root / 'link-spec.json'
        path.write_text(json.dumps(self.spec))
        obj = self.root / 'kontor-abcd.1.rcgu.o'
        obj.write_bytes(b'node object')
        record = self.root / 'objects.json'
        contents = {'spec_sha256': digest(path), 'objects': [{'path': str(obj), 'sha256': digest(obj)}]}
        record.write_text(json.dumps(contents))
        self.assertEqual(node_codegen_objects(record, path), [obj])
        path.write_text('{}')
        with self.assertRaisesRegex(RuntimeError, 'link specification'):
            node_codegen_objects(record, path)
        contents['spec_sha256'] = digest(path)
        record.write_text(json.dumps(contents))
        obj.write_bytes(b'changed')
        with self.assertRaisesRegex(RuntimeError, 'object changed'):
            node_codegen_objects(record, path)

    def test_executable_must_be_from_current_cargo_messages(self):
        log = self.root / 'build.log'
        log.write_text('unstructured diagnostic\n')
        with self.assertRaisesRegex(RuntimeError, 'current node executable'):
            node_executable(log)
        message = {'reason': 'compiler-artifact', 'target': {'name': 'kontor', 'kind': ['bin']},
                   'executable': str(self.root / 'kontor')}
        log.write_text(json.dumps(message) + '\n')
        self.assertEqual(node_executable(log), self.root / 'kontor')
        other = copy.deepcopy(message)
        other['executable'] += '-stale'
        log.write_text(json.dumps(message) + '\n' + json.dumps(other))
        with self.assertRaisesRegex(RuntimeError, 'ambiguous'):
            node_executable(log)

    def test_node_source_inventory_covers_external_build_inputs(self):
        files = ('core/indexer/src/main.rs', 'core/indexer/src/protocol/coordinator/linked.rs',
                 'core/indexer/src/database/storage_callbacks_v1.rs',
                 'core/indexer/src/database/sql/current_state.sql',
                 'core/indexer/proto/consensus.proto', 'core/indexer/build.rs',
                 'test-contracts/binaries/counter.wasm.br', 'test-contracts/binaries/proxy.wasm.br')
        for relative in files:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text('original')
        original = node_sources(self.root)
        for relative in files:
            with self.subTest(path=relative):
                path = self.root / relative
                path.write_text('changed')
                self.assertNotEqual(original, node_sources(self.root))
                path.write_text('original')
        (self.root / 'core/indexer/proto/consensus.proto').unlink()
        (self.root / 'core/indexer/proto').rmdir()
        with self.assertRaisesRegex(RuntimeError, 'missing node source tree'):
            node_sources(self.root)

    def test_installation_preserves_audited_bytes_and_rejects_changed_binary(self):
        source = self.root / 'built-kontor'
        source.write_bytes(b'audited executable')
        record = {'executable': str(source), 'executable_sha256': digest(source)}
        destination = self.root / 'bin/kontor'
        installed = install_node(record, destination)
        self.assertEqual(installed['sha256'], digest(destination))
        self.assertEqual(destination.stat().st_mode & 0o777, 0o755)
        source.write_bytes(b'changed after audit')
        with self.assertRaisesRegex(RuntimeError, 'changed after'):
            install_node(record, destination)
        self.assertEqual(destination.read_bytes(), b'audited executable')
        self.assertEqual(list(destination.parent.iterdir()), [destination])
        with self.assertRaisesRegex(RuntimeError, 'overwrite the audited'):
            install_node(record, source)


if __name__ == '__main__':
    unittest.main()
