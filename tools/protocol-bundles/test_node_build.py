import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from build import digest, install_node, node_codegen_objects, node_dependencies, node_executable
from provenance import node_sources

spec = importlib.util.spec_from_file_location('node_wrapper', Path(__file__).with_name('node-rustc-wrapper.py'))
wrapper = importlib.util.module_from_spec(spec)
spec.loader.exec_module(wrapper)


class NodeBuild(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.facade = self.root / 'libkontor_executor_first.rlib'
        self.facade.write_bytes(b'compiled retained graph')
        self.spec = {'compiler': '/pinned/rustc', 'graphs': [
            {'graph': 'first', 'facade': str(self.facade), 'facade_sha256': digest(self.facade),
             'link_inputs': str(self.root)}]}

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
        for name in ('wasmtime', 'wasmtime-internal-cranelift', 'kontor-executor-first'):
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
