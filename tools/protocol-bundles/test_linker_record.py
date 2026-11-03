import copy
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

from linker_record import backend, digest, validate


class LinkerRecord(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.shim = self.root / 'cc'
        shutil.copyfile(Path(__file__).with_name('linker_record.py'), self.shim)
        self.shim.chmod(0o755)
        self.record = self.root / 'record.json'
        self.spec = self.root / 'spec.json'
        self.spec.write_text(json.dumps({'linker_record': str(self.record)}))
        self.source = self.root / 'main.c'
        self.source.write_text('int main(void) { return 0; }\n')
        self.output = self.root / 'program'

    def run_link(self, arguments, driver='cc'):
        subprocess.run([str(self.shim), *arguments], check=True, capture_output=True, text=True,
                       env=dict(os.environ, KONTOR_NODE_LINK_SPEC=str(self.spec),
                                KONTOR_REAL_LINKER=driver, CCACHE_DISABLE='1'))
        record = json.loads(self.record.read_text())
        validate(record, digest(self.spec), digest(self.output))
        subprocess.run([str(self.output)], check=True)
        return record

    @unittest.skipUnless(shutil.which('cc'), 'C driver required')
    def test_records_successful_link_and_rejects_other_spec_output_or_incomplete_identity(self):
        record = self.run_link([str(self.source), '-o', str(self.output)])
        self.assertEqual(record['backend']['sha256'], digest(record['backend']['path']))
        for mutation in ('spec_sha256', 'output_sha256', 'backend', 'arguments', 'output'):
            changed = copy.deepcopy(record)
            changed[mutation] = {} if mutation == 'backend' else 'wrong'
            with self.subTest(mutation=mutation), self.assertRaises(RuntimeError):
                validate(changed, digest(self.spec), digest(self.output))

    @unittest.skipUnless(sys.platform.startswith('linux') and shutil.which('cc'), 'GNU driver search case')
    def test_selected_backend_follows_b_search_and_fuse_ld_including_response_file(self):
        actual, _ = backend('cc', [str(self.source), '-o', str(self.output)])
        directory = self.root / 'rust linker search'
        directory.mkdir()
        marker = self.root / 'invoked'
        selected = directory / 'ld.lld'
        selected.write_text('#!' + sys.executable + '\nimport os, sys\n'
                            + 'open(' + repr(str(marker)) + ', "w").write("used")\n'
                            + 'os.execv(' + repr(actual['invocation_path']) + ', ['
                            + repr(actual['invocation_path']) + ', *sys.argv[1:]])\n')
        selected.chmod(0o755)
        response = self.root / 'arguments'
        response.write_text(' '.join(json.dumps(arg) for arg in
                                    ['-B', str(directory), '-fuse-ld=lld', str(self.source), '-o', str(self.output)]))
        record = self.run_link(['@' + str(response)])
        self.assertEqual(marker.read_text(), 'used')
        self.assertEqual(record['backend']['path'], str(selected))
        self.assertEqual(record['backend']['sha256'], digest(selected))
        self.assertEqual(record['arguments'], ['@' + str(response)])
        self.assertIn('-fuse-ld=lld', record['expanded_arguments'])

    @unittest.skipUnless(shutil.which('cc'), 'C driver required')
    def test_completed_compiler_output_is_bound_without_replacing_linker_hash(self):
        record = self.run_link([str(self.source), '-o', str(self.output)])
        self.output.write_bytes(self.output.read_bytes() + b'post-link processing')
        completed = {'path': str(self.output), 'sha256': digest(self.output)}
        self.assertNotEqual(record['output_sha256'], completed['sha256'])
        validate(record, digest(self.spec), digest(self.output), completed)
        with self.assertRaises(RuntimeError):
            validate(record, digest(self.spec), digest(self.output))
        for changed in ({}, [], dict(completed, path='/another/output'),
                        dict(completed, sha256=record['output_sha256'])):
            with self.subTest(changed=changed), self.assertRaises(RuntimeError):
                validate(record, digest(self.spec), digest(self.output), changed)
        for field in ('spec_sha256', 'output_sha256', 'output'):
            changed = dict(record, **{field: 'wrong'})
            with self.subTest(field=field), self.assertRaises(RuntimeError):
                validate(changed, digest(self.spec), digest(self.output), completed)

    @unittest.skipUnless(shutil.which('clang'), 'Clang driver required')
    def test_clang_plan_records_direct_backend(self):
        record = self.run_link([str(self.source), '-o', str(self.output)], 'clang')
        self.assertIsNone(record['selection']['backend_query'])
        self.assertTrue(Path(record['backend']['path']).is_file())

    @unittest.skipUnless(shutil.which('cc'), 'C driver required')
    def test_failed_link_does_not_produce_success_record(self):
        result = subprocess.run([str(self.shim), str(self.root / 'missing.c'), '-o', str(self.output)],
                                env=dict(os.environ, KONTOR_NODE_LINK_SPEC=str(self.spec),
                                         KONTOR_REAL_LINKER='cc', CCACHE_DISABLE='1'),
                                capture_output=True, text=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertFalse(self.record.exists())


if __name__ == '__main__':
    unittest.main()
