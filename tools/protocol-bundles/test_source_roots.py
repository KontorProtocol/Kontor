from dataclasses import replace
import hashlib
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch

import build
import provenance
from freeze_sources import verify_snapshot
from recipes import EXECUTOR_GRAPHS, graph_root, identity, verify_identity


ROOT = Path(__file__).resolve().parents[2]


class SourceRoots(unittest.TestCase):
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

    def test_metadata_runs_from_graph_root(self):
        with patch.object(build.subprocess, "check_output", return_value="{}") as cargo:
            build.metadata(Path("retained/Cargo.toml"), None, {}, True, source_root=Path("retained"))
            self.assertEqual(cargo.call_args.kwargs["cwd"], Path("retained"))

    def fixture(self, root):
        package = root / "core/local"
        package.mkdir(parents=True)
        (package / "Cargo.toml").write_text("local package")
        (package / "lib.rs").write_text("old execution rules")
        (root / "core/Cargo.toml").write_text("frozen inherited properties")
        return {"packages": [{"manifest_path": str(package / "Cargo.toml"),
                               "id": f"path+file://{package}#local", "source": None}]}

    def inputs(self, root, data, tool_root):
        with patch.object(provenance, "verify_sources", return_value={}), \
                patch.object(provenance, "repository_sources", return_value={}):
            return provenance.source_inputs(root, data, kind="executor", tool_root=tool_root)

    def test_explicit_boundary_preserves_frozen_inheritance_and_tracks_current_tools(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            frozen = root / "retained/k3"
            data = self.fixture(frozen)
            (root / "Cargo.toml").write_text("current workspace")
            tools = root / "tools/protocol-bundles"
            tools.mkdir(parents=True)
            wrapper = tools / "wrapper.py"
            wrapper.write_text("current compiler wrapper")
            before = self.inputs(frozen, data, root)
            self.assertIn(str(frozen / "core/Cargo.toml"), before["inherited_manifests_and_configuration"])
            self.assertNotIn(str(root / "Cargo.toml"), before["inherited_manifests_and_configuration"])
            (root / "Cargo.toml").write_text("changed node workspace")
            self.assertEqual(before, self.inputs(frozen, data, root))
            wrapper.write_text("changed compiler wrapper")
            self.assertNotEqual(before, self.inputs(frozen, data, root))

    def test_local_dependency_and_symlink_cannot_read_mutable_node_sources(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            frozen = root / "retained"
            data = self.fixture(frozen)
            outside = root / "node"
            outside.mkdir()
            (outside / "Cargo.toml").write_text("live dependency")
            (outside / "lib.rs").write_text("live execution rules")
            escaped = {"packages": [{**data["packages"][0], "manifest_path": str(outside / "Cargo.toml")}]}
            with self.assertRaisesRegex(RuntimeError, "local package escapes"):
                self.inputs(frozen, escaped, frozen)
            package = frozen / "core/local"
            for target in (outside / "lib.rs", outside, package):
                link = package / "linked"
                link.symlink_to(target)
                with self.subTest(target=target), self.assertRaisesRegex(RuntimeError, "escapes|cyclic"):
                    self.inputs(frozen, data, frozen)
                link.unlink()


if __name__ == "__main__":
    unittest.main()
