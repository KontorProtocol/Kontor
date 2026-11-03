import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from build import digest, install_node, node_codegen_objects, node_dependencies, node_executable, node_link_inputs, stage_compiler_wrapper
from linker_record import validate as validate_linker_record
from provenance import node_sources


class NodeBuild(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        temporary = tempfile.TemporaryDirectory()
        cls.addClassCleanup(temporary.cleanup)
        cls.wrapper = stage_compiler_wrapper(Path(temporary.name), dict(os.environ), False, kind="node")

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
            str(self.wrapper), compiler, str(source),
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

    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.facade = self.root / 'libkontor_executor_first.rlib'
        self.facade.write_bytes(b'compiled retained graph')
        self.spec = {'compiler': '/pinned/rustc', 'graphs': [
            {'graph': 'first', 'facade': str(self.facade), 'facade_sha256': digest(self.facade),
             'link_inputs': str(self.root)}]}

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
