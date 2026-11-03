from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import freeze_sources
import provenance
from freeze_sources import verify_snapshot
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

    def test_freeze_keeps_fixture_and_package_inputs_without_tool_programs(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            data = self.fixture(root)
            for relative in (*freeze_sources.SEMANTIC_TREES, *freeze_sources.SUPPORT_TREES):
                (root / relative).mkdir(parents=True, exist_ok=True)
            tool_root = root / "tools/protocol-bundles"
            tool_root.mkdir(parents=True)
            (tool_root / "build.py").write_text("obsolete build orchestration")
            # Some historical commits predate the optional fixture assets.
            expected_assets = freeze_sources.SUPPORT_FILES[:-1]
            for relative in expected_assets:
                (root / relative).write_text("historical fixture")
            graph = root / "protocol-bundles/executor-first"
            graph.mkdir(parents=True)
            (graph / "Cargo.toml").write_text('[patch.crates-io.helper]\npath = "../../vendor/helper"\n')
            helper = root / "vendor/helper"
            helper.mkdir(parents=True)
            (helper / "lib.rs").write_text("unused path patch still required by Cargo")
            found = {path.relative_to(root).as_posix() for path in freeze_sources.inputs(
                root, [data], ["executor-first"])}
            self.assertNotIn("tools/protocol-bundles/build.py", found)
            self.assertTrue(set(expected_assets).issubset(found))
            self.assertTrue({"core/local/lib.rs", "core/local/Cargo.toml", "core/Cargo.toml",
                             "vendor/helper/lib.rs"}.issubset(found))
            for relative in freeze_sources.COORDINATOR_FILES:
                path = root / relative
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("coordinator identity input")
            coordinator = {path.relative_to(root).as_posix() for path in freeze_sources.inputs(
                root, [data], ["executor-first"], freeze_sources.COORDINATOR_FILES)}
            self.assertTrue(set(freeze_sources.COORDINATOR_FILES).issubset(coordinator))

    def test_frozen_inventory_rejects_mutation_additions_and_substituted_manifest(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "lib.rs"
            source.write_bytes(b"retained code")
            manifest = root / "snapshot.json"
            manifest.write_text(json.dumps({"files": {
                "lib.rs": {"sha256": hashlib.sha256(source.read_bytes()).hexdigest()}}}))
            expected = hashlib.sha256(manifest.read_bytes()).hexdigest()
            verify_snapshot(root, expected)
            source.write_bytes(b"modified code")
            with self.assertRaisesRegex(ValueError, "files differ"):
                verify_snapshot(root, expected)
            source.write_bytes(b"retained code")
            extra = root / "extra.rs"
            extra.write_bytes(b"untracked addition")
            with self.assertRaisesRegex(ValueError, "files differ"):
                verify_snapshot(root, expected)
            extra.unlink()
            manifest.write_text(json.dumps({"files": {}}))
            with self.assertRaisesRegex(ValueError, "inventory changed"):
                verify_snapshot(root, expected)

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


    def fixture(self, root):
        package = root / "core/local"
        package.mkdir(parents=True)
        (package / "Cargo.toml").write_text("local package")
        (package / "lib.rs").write_text("old execution rules")
        (root / "core/Cargo.toml").write_text("frozen inherited properties")
        return {"packages": [{"manifest_path": str(package / "Cargo.toml"),
                               "id": f"path+file://{package}#local", "source": None}]}



if __name__ == "__main__":
    unittest.main()
