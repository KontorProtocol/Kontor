"""Negative controls for the native instruction/data/relocation comparator."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest


TOOL = Path(os.environ.get("KONTOR_OBJECT_REPORT", Path(__file__).parent / "object-report/target/debug/kontor-native-object-report")).resolve()
SOURCE = """
extern int dependency(int);
int state = 17;
int zeros[8];
int operation(int value) { return dependency(value) + state + zeros[0]; }
"""


class ObjectComparison(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="kontor-object-test-")
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.counter = 0

    def compile(self, source, target=None):
        self.counter += 1
        path = self.root / f"fixture-{self.counter}.c"
        path.write_text(source)
        command = ["clang", "-target", target] if target else ["cc"]
        subprocess.run([*command, "-O2", "-g0", "-fno-ident", "-c", str(path), "-o", str(path.with_suffix(".o"))],
                       env=dict(os.environ, CCACHE_DISABLE="1"), check=True, capture_output=True)
        return path.with_suffix(".o")

    def report(self, path, namespace=""):
        return json.loads(subprocess.check_output([str(TOOL), str(path), namespace], text=True))

    def test_symbol_renaming_only_preserves_identity(self):
        original = self.compile(SOURCE)
        renamed = SOURCE
        for name in ("dependency", "operation", "state", "zeros"):
            renamed = renamed.replace(name, "bundle_" + name)
        self.assertEqual(self.report(original), self.report(self.compile(renamed), "bundle"))

    def test_instruction_data_relocation_and_binding_changes_are_rejected(self):
        original = self.report(self.compile(SOURCE))
        mutations = {
            "instruction": SOURCE.replace("dependency(value)", "dependency(value + 1)"),
            "data": SOURCE.replace("state = 17", "state = 18"),
            "bss": SOURCE.replace("zeros[8]", "zeros[9]"),
            "relocation": SOURCE.replace("dependency", "other_dependency"),
            "binding": SOURCE.replace("int state", "__attribute__((weak)) int state"),
            "alignment": SOURCE.replace("int state", "__attribute__((aligned(64))) int state"),
        }
        for label, source in mutations.items():
            with self.subTest(label=label):
                self.assertNotEqual(original, self.report(self.compile(source)))

    def test_literal_bytes_are_never_namespace_normalized(self):
        source = 'const char message[] = "bundle_operation";'
        self.assertNotEqual(self.report(self.compile(source), "bundle"),
                            self.report(self.compile(source.replace('"bundle_operation"', '"operation"'))))

    @unittest.skipUnless(shutil.which("clang"), "cross-format checks require clang")
    def test_macho_and_elf_cross_target_objects(self):
        for target in ("aarch64-unknown-linux-gnu", "x86_64-unknown-linux-gnu", "arm64-apple-macos11", "x86_64-apple-macos11"):
            with self.subTest(target=target):
                original = self.report(self.compile(SOURCE, target))
                renamed = SOURCE
                for name in ("dependency", "operation", "state", "zeros"):
                    renamed = renamed.replace(name, "bundle_" + name)
                self.assertEqual(original, self.report(self.compile(renamed, target), "bundle"))
                self.assertNotEqual(original, self.report(self.compile(SOURCE.replace("state = 17", "state = 19"), target)))

    def test_empty_archive_and_truncated_objects_fail_closed(self):
        for content in (b"!<arch>\n", b"\x7fELF", b""):
            path = self.root / "invalid.o"
            path.write_bytes(content)
            result = subprocess.run([str(TOOL), str(path), ""], capture_output=True)
            self.assertNotEqual(result.returncode, 0)


if __name__ == "__main__":
    unittest.main()
