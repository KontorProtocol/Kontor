import copy
import json
from pathlib import Path
import tempfile
import unittest

from build import digest, install_node, node_codegen_objects, node_dependencies, node_executable, node_link_inputs
from provenance import node_sources


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
