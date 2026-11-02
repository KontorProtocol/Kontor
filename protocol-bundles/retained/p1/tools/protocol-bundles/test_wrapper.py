"""Check that graph isolation never changes Cargo's toolchain probes."""

import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

WRAPPER = Path(__file__).with_name("rustc-wrapper.py").resolve()
NAMESPACE = "kontor_first_0123456789abcdef01234567"


class Wrapper(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.addCleanup(self.directory.cleanup)
        self.compiler = Path(self.directory.name) / "rustc"
        self.compiler.write_text('#!/usr/bin/env python3\nimport json,sys\nprint(json.dumps(sys.argv[1:]))\n')
        self.compiler.chmod(0o755)
        self.env = dict(os.environ, RUSTC_WRAPPER=str(WRAPPER), KONTOR_NATIVE_NAMESPACE=NAMESPACE,
                        KONTOR_PINNED_RUSTC=str(self.compiler))
        self.env.pop("RUSTC_WORKSPACE_WRAPPER", None)

    def invoke(self, arguments):
        return subprocess.run([str(WRAPPER), str(self.compiler), *arguments], env=self.env,
                              text=True, capture_output=True)

    def test_cargo_metadata_is_retained_and_graph_metadata_added(self):
        arguments = ["--crate-name", "serde", "-Cmetadata=unit_identity", "lib.rs"]
        result = self.invoke(arguments)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), arguments + ["-Cmetadata=" + NAMESPACE])

    def test_probe_argv_is_unchanged(self):
        for arguments in [["-vV"], ["--print", "sysroot"],
                          ["-", "--crate-name", "___", "--print=file-names", "--print=cfg"]]:
            with self.subTest(arguments=arguments):
                result = self.invoke(arguments)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertEqual(json.loads(result.stdout), arguments)

    def test_nested_workspace_wrapper_is_rejected(self):
        self.env["RUSTC_WORKSPACE_WRAPPER"] = "sccache"
        self.assertNotEqual(self.invoke(["--crate-name", "proof", "lib.rs"]).returncode, 0)

    def test_outer_wrapper_is_rejected(self):
        self.env["RUSTC_WRAPPER"] = "sccache"
        self.assertNotEqual(self.invoke(["--crate-name", "proof", "lib.rs"]).returncode, 0)

    def test_different_compiler_with_same_basename_is_rejected(self):
        self.env["KONTOR_PINNED_RUSTC"] = "/another/toolchain/bin/rustc"
        result = self.invoke(["-vV"])
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("exact pinned rustc", result.stderr)


if __name__ == "__main__":
    unittest.main()
