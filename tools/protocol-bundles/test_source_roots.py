from dataclasses import replace
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import build
import provenance
from recipes import EXECUTOR_GRAPHS, graph_root, identity, verify_identity


ROOT = Path(__file__).resolve().parents[2]


class SourceRoots(unittest.TestCase):
    def test_provenance_bootstraps_once_per_build_environment(self):
        provenance._tool_path.cache_clear()
        self.addCleanup(provenance._tool_path.cache_clear)
        with patch.object(provenance.subprocess, "check_output", return_value="/built/kontor-build\n") as bootstrap, \
                patch.object(provenance.subprocess, "run") as process:
            process.return_value.returncode = 0
            process.return_value.stdout = '{}'
            env = {"CARGO_NET_OFFLINE": "true"}
            for _ in range(2):
                provenance._request({"operation": "retained_trees"}, env=env)
            self.assertEqual(bootstrap.call_count, 1)
            self.assertEqual(bootstrap.call_args.kwargs["env"], env)
            self.assertEqual(process.call_args.args[0], ["/built/kontor-build", "provenance"])
            provenance._request({"operation": "retained_trees"}, env={"CARGO_NET_OFFLINE": "false"})
            self.assertEqual(bootstrap.call_count, 2)

    def test_provenance_bridge_uses_pinned_tool_and_offline_environment(self):
        env = {"KONTOR_BUILD_TOOL": "/pinned/kontor-build", "CARGO_NET_OFFLINE": "true"}
        data = {"operation": "source_inputs", "data": {"packages": []}}
        with patch.object(provenance.subprocess, "run") as process:
            process.return_value.returncode = 0
            process.return_value.stdout = '{"git": {}, "registry": {}}'
            self.assertEqual(provenance._request(data, env=env), {"git": {}, "registry": {}})
            self.assertEqual(process.call_args.args[0], ["/pinned/kontor-build", "provenance"])
            self.assertEqual(process.call_args.kwargs["env"], env)
            self.assertEqual(json.loads(process.call_args.kwargs["input"]), data)
            process.return_value.returncode = 1
            process.return_value.stderr = "pinned source differs"
            with self.assertRaisesRegex(RuntimeError, "pinned source differs"):
                provenance._request(data, env=env)

    def test_compiler_bootstrap_forwards_offline_policy_without_mutating_environment(self):
        environment = {"CARGO_NET_OFFLINE": "false"}
        with patch.object(build.subprocess, "check_output", return_value="/tmp/wrapper\n") as bootstrap:
            build.stage_compiler_wrapper(Path("output"), environment, True)
            self.assertEqual(bootstrap.call_args.kwargs["env"]["CARGO_NET_OFFLINE"], "true")
            self.assertEqual(environment["CARGO_NET_OFFLINE"], "false")
            self.assertEqual(bootstrap.call_args.args[0][0], str(build.ROOT / "tools/kontor"))
            build.stage_compiler_wrapper(Path("output"), {"KONTOR_BUILD_TOOL": "/tool", "CARGO_NET_OFFLINE": "true"}, False)
            self.assertEqual(bootstrap.call_args.kwargs["env"]["CARGO_NET_OFFLINE"], "true")
            self.assertEqual(bootstrap.call_args.args[0][0], "/tool")


    def test_relocated_recipe_binds_the_selected_root_and_ignores_live_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            recipe = replace(EXECUTOR_GRAPHS["first"], source_root="retained/k3")
            frozen = root / recipe.source_root
            for destination in (root, frozen):
                target = destination / "protocol-bundles" / recipe.directory
                target.mkdir(parents=True)
                for name in ("Cargo.toml", "Cargo.lock"):
                    shutil.copyfile(ROOT / "protocol-bundles" / recipe.directory / name, target / name)
            graphs = {"first": recipe}
            report = {"graph": "first", "identity": identity(root, "first", graphs)}
            live = root / "protocol-bundles" / recipe.directory / "Cargo.toml"
            live.write_text("new observer manifest")
            verify_identity(root, report, graphs)
            with self.assertRaisesRegex(RuntimeError, "attestation"):
                verify_identity(root, report, EXECUTOR_GRAPHS)
            historical = frozen / "protocol-bundles" / recipe.directory / "Cargo.lock"
            historical.write_text("substituted historical dependencies")
            with self.assertRaisesRegex(RuntimeError, "attestation"):
                verify_identity(root, report, graphs)

    def test_source_root_cannot_escape_or_use_ambiguous_spelling(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "outside").symlink_to(root.parent, target_is_directory=True)
            for relative in ("../old", "/tmp", "outside", "foo/../bar", "./foo", "foo//bar"):
                with self.subTest(root=relative), self.assertRaises(RuntimeError):
                    graph_root(root, replace(EXECUTOR_GRAPHS["first"], source_root=relative))


if __name__ == "__main__":
    unittest.main()
