"""Negative controls for the native instruction/data/relocation comparator."""

import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest

from qualify import undefined_references, validate_references


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

    def compile(self, source, target=None, debug=False):
        self.counter += 1
        path = self.root / f"fixture-{self.counter}.c"
        path.write_text(source)
        command = ["clang", "-target", target] if target else ["cc"]
        subprocess.run([*command, "-O2", "-g" if debug else "-g0", "-fno-ident", "-c", str(path), "-o", str(path.with_suffix(".o"))],
                       env=dict(os.environ, CCACHE_DISABLE="1"), check=True, capture_output=True)
        return path.with_suffix(".o")

    def report(self, path, namespace=""):
        result = json.loads(subprocess.check_output([str(TOOL), str(path), namespace], text=True))
        result.pop("namespace_audit")
        return result

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

    def test_bare_crypto_reference_is_rejected_even_when_default_copy_can_link(self):
        source = 'extern int bundle_blst_keygen(int); int bundle_operation(int x) { return bundle_blst_keygen(x); }'
        good = self.compile(source)
        validate_references(undefined_references(good), "bundle")
        self.report(good, "bundle")
        bad = self.compile(source.replace("bundle_blst_keygen", "blst_keygen"))
        with self.assertRaisesRegex(RuntimeError, "unnamespaced crypto references"):
            validate_references(undefined_references(bad), "bundle")
        result = subprocess.run([str(TOOL), str(bad), "bundle"], text=True, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("unprefixed crypto symbol or reference", result.stderr)
        provider = self.compile('int blst_keygen(int x) { return x + 1; } int bundle_operation(int); int main(void) { return bundle_operation(1) != 2; }')
        executable = self.root / "silent-cross-binding"
        subprocess.run(["cc", str(bad), str(provider), "-o", str(executable)], check=True,
                       env=dict(os.environ, CCACHE_DISABLE="1"))
        subprocess.run([str(executable)], check=True)

    @unittest.skipUnless(shutil.which("clang"), "cross-format checks require clang")
    def test_macho_arm_debug_layout_does_not_change_section_relative_identity(self):
        # ARM's unwind bytes are unchanged in this reproducer. x86 can encode
        # provisional PC-relative values directly in unwind data, which this
        # deliberately strict comparator continues to reject when bytes differ.
        target = "arm64-apple-macos11"
        self.assertEqual(self.report(self.compile(SOURCE, target, debug=True)),
                         self.report(self.compile(SOURCE, target, debug=False)))

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
