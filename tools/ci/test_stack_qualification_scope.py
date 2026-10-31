import json
import os
from pathlib import Path
import subprocess
import tempfile
import sys
import unittest

import stack_qualification_scope as scope


class ScopeTests(unittest.TestCase):
    def test_execution_and_build_inputs(self):
        for path in (
            "core/indexer/src/runtime/ownership.rs", "core/indexer/src/runtime/new_module.rs",
            "core/indexer/src/protocol/v2/engine.rs", "core/indexer/src/database/storage.rs",
            "core/indexer/src/reactor/executor.rs", "core/indexer/src/main.rs",
            "core/indexer/proto/consensus/v1/consensus.proto", "core/indexer/proto/imports/shared.proto",
            "core/indexer/src/api/handlers/contracts.rs", "core/indexer/src/api/env.rs",
            "core/macros/src/lib.rs", "core/numerics/src/lib.rs",
            "core/indexer-types/src/lib.rs", "core/testlib/src/lib.rs",
            "native-contracts/binaries/token.wasm.br", "test-contracts/proxy/src/lib.rs",
            "protocol-bundles/p2/src/lib.rs", "tools/protocol-bundles/build.py",
            "core/Cargo.lock", "core/kontor-sdk-native/Cargo.toml",
            "new-executor/Cargo.toml", "new-executor/build.rs",
            "rust-toolchain.toml", "core/.cargo/config.toml",
            "Dockerfile", "tools/build.json", "tools/kontor",
            ".github/workflows/native-stack.yml", "tools/native-stack/qualify.py",
            "tools/ci/stack_qualification_scope.py",
        ):
            with self.subTest(path=path):
                self.assertTrue(scope.relevant(path))

    def test_unrelated_changes_keep_ordinary_ci_only(self):
        for path in (
            "README.md", "docs/design/protocol-upgrades/implementation-plan.md",
            "sdk/src/client.ts", "sdk-native/android/build.gradle",
            "core/kontor-sdk-native/src/lib.rs", "core/kontor-sdk/src/client.rs",
            "core/indexer/src/api/handlers/info.rs", "core/indexer/src/api/handlers/receipt_stream.rs",
            "core/indexer/src/logging.rs", "core/indexer/src/metrics.rs",
            ".github/workflows/mobile.yml", "core/.cargo/audit.toml",
        ):
            with self.subTest(path=path):
                self.assertFalse(scope.relevant(path))

    def test_manual_and_unknown_scope_require_full_run(self):
        self.assertTrue(scope.select("workflow_dispatch", {}, Path.cwd())["required"])
        self.assertTrue(scope.select("unknown", {}, Path.cwd())["required"])
        self.assertTrue(scope.select("pull_request", {}, Path.cwd())["required"])
        self.assertTrue(scope.select("push", {"before": "0" * 40, "after": "a" * 40}, Path.cwd())["required"])


class GitDiffTests(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        self.git("init", "-q")
        self.git("config", "user.name", "Test fixture")
        self.git("config", "user.email", "fixture@example.invalid")
        self.git("config", "commit.gpgsign", "false")
        self.write("README.md", "base")
        self.write("core/indexer/src/runtime/old.rs", "runtime")
        self.base = self.commit()

    def git(self, *args):
        return subprocess.check_output(["git", *args], cwd=self.root, text=True).strip()

    def write(self, path, value):
        target = self.root/path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(value)

    def commit(self):
        self.git("add", "--all")
        self.git("-c", "core.hooksPath=/dev/null", "commit", "-qm", "Fixture")
        return self.git("rev-parse", "HEAD")

    def event(self, head, base=None):
        return {"pull_request": {"base": {"sha": base or self.base}, "head": {"sha": head}}}

    def test_unrelated_pr_and_mixed_large_pr(self):
        for number in range(350):
            self.write(f"docs/{number}.md", "documentation")
        docs = self.commit()
        self.assertFalse(scope.select("pull_request", self.event(docs), self.root)["required"])
        self.write("core/indexer/src/runtime/late.rs", "runtime")
        selected = scope.select("pull_request", self.event(self.commit()), self.root)
        self.assertTrue(selected["required"])
        self.assertIn("core/indexer/src/runtime/late.rs", selected["paths"])

    def test_rename_out_of_sensitive_directory_and_deletion(self):
        self.git("mv", "core/indexer/src/runtime/old.rs", "renamed.rs")
        selected = scope.select("pull_request", self.event(self.commit()), self.root)
        self.assertIn("core/indexer/src/runtime/old.rs", selected["paths"])
        (self.root/"renamed.rs").unlink()
        self.assertTrue(scope.select("pull_request", self.event(self.commit()), self.root)["required"])

    def test_rename_into_sensitive_directory_and_unusual_filename(self):
        self.git("mv", "README.md", "core/indexer/src/runtime/renamed\nfile.rs")
        selected = scope.select("pull_request", self.event(self.commit()), self.root)
        self.assertIn("core/indexer/src/runtime/renamed\nfile.rs", selected["paths"])

    def test_pr_ignores_unrelated_base_advancement_but_push_includes_it(self):
        self.write("README.md", "PR documentation")
        head = self.commit()
        self.git("checkout", "-q", "--detach", self.base)
        self.write("core/indexer/src/runtime/base.rs", "base advancement")
        base = self.commit()
        self.assertFalse(scope.select("pull_request", self.event(head, base), self.root)["required"])
        self.assertTrue(scope.select("push", {"before": self.base, "after": base}, self.root)["required"])

    def test_missing_history_requires_full_run(self):
        selected = scope.select("push", {"before": "a" * 40, "after": self.base}, self.root)
        self.assertTrue(selected["required"])
        self.assertIn("cannot establish", selected["reason"])

    def test_action_entrypoint_emits_boolean_output_and_explanation(self):
        self.write("README.md", "documentation")
        event = self.root/"event.json"
        event.write_text(json.dumps(self.event(self.commit())))
        output = self.root/"github-output"
        result = subprocess.run(
            [sys.executable, str(Path(scope.__file__).resolve())], cwd=self.root,
            env={**os.environ, "GITHUB_EVENT_PATH": str(event), "GITHUB_EVENT_NAME": "pull_request", "GITHUB_OUTPUT": str(output)},
            text=True, capture_output=True, check=True,
        )
        self.assertEqual(output.read_text(), "required=false\n")
        self.assertEqual(json.loads(result.stdout)["reason"], "no stack qualification inputs changed")


if __name__ == "__main__":
    unittest.main()
