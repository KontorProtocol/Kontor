import hashlib
import tempfile
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

import build
from execution_definition import SEMANTIC_TREES, encode, reference, verify_reference
from recipes import EXECUTOR_GRAPHS


class ExecutionDefinitionTests(unittest.TestCase):
    def fixture(self, root):
        for relative in SEMANTIC_TREES:
            (root / relative).mkdir(parents=True, exist_ok=True)
        manifest = root / "protocol-bundles/executor-first/Cargo.toml"
        manifest.parent.mkdir(parents=True)
        manifest.write_text('[package]\nname="executor"\nversion="1.0.0"\n')
        manifest.with_name("Cargo.lock").write_text("locked inputs")
        (root / "core/indexer/src/runtime/semantics.rs").write_text("execution rules")
        package_id = f"path+file://{manifest.parent}#executor@1.0.0"
        metadata = {"packages": [{"id": package_id, "source": None,
            "manifest_path": str(manifest), "name": "executor", "version": "1.0.0"}],
            "resolve": {"nodes": [{"id": package_id, "features": ["z", "a"]}]}}
        return manifest, metadata

    def test_binary_format_matches_rust_golden_reference(self):
        encoded = encode({"core/main.rs": bytes([0x11]) * 32},
            {"core/Cargo.lock": bytes([0x22]) * 32}, ["a", "b"], bytes([0x33]) * 32)
        self.assertEqual(hashlib.sha256(b"kontor/execution-definition/v1\0" + encoded).hexdigest(),
            "042b0f0715621140a44437d8e2dc62dc74ae72cc8ba5e68afdd263e98c70f592")

    def test_paths_and_artifact_outputs_do_not_change_reference(self):
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            first, second = Path(first), Path(second)
            manifest, metadata = self.fixture(first)
            other_manifest, other_metadata = self.fixture(second)
            expected = reference(first, manifest, metadata)
            self.assertEqual(expected, reference(second, other_manifest, other_metadata))
            manifest.with_name("definition.bin").write_bytes(b"previous reference")
            build = manifest.parent / "target"
            build.mkdir()
            (build / "binary").write_bytes(b"platform-dependent build")
            self.assertEqual(expected, reference(first, manifest, metadata))

    def test_semantics_lock_and_features_are_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, metadata = self.fixture(root)
            expected = reference(root, manifest, metadata)
            path = root / "core/indexer/src/runtime/semantics.rs"
            original = path.read_text()
            path.write_text("different execution rules")
            self.assertNotEqual(expected, reference(root, manifest, metadata))
            path.write_text(original)
            metadata["resolve"]["nodes"][0]["features"].append("new")
            self.assertNotEqual(expected, reference(root, manifest, metadata))
            metadata["resolve"]["nodes"][0]["features"].pop()
            manifest.with_name("Cargo.lock").write_text("different dependencies")
            self.assertNotEqual(expected, reference(root, manifest, metadata))

    def test_node_implementation_changes_do_not_redefine_required_storage_contract(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, metadata = self.fixture(root)
            contract = root / "core/indexer/src/protocol/v1/storage-contract.json"
            contract.parent.mkdir(parents=True)
            contract.write_text('{"contract":"storage-v1","reference":"immutable"}')
            expected = reference(root, manifest, metadata)
            for name in ("core/indexer/src/protocol/coordinator/migration.rs",
                         "core/indexer/src/runtime/ownership.rs",
                         "core/indexer/src/runtime/ownership/adapter.rs",
                         "core/indexer/src/runtime/pool.rs",
                         "core/indexer/src/runtime/node.rs",
                         "core/indexer/src/database/storage_callbacks_v1.rs",
                         "core/Cargo.toml", "protocol-bundles/node/Cargo.lock"):
                path = root / name
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_text("changed node implementation or unrelated workspace dependency")
                self.assertEqual(expected, reference(root, manifest, metadata), name)
            contract.write_text('{"contract":"changed-storage-contract"}')
            self.assertNotEqual(expected, reference(root, manifest, metadata))

    def test_effective_inherited_package_properties_remain_bound(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, metadata = self.fixture(root)
            package = metadata["packages"][0]
            package["edition"] = "2021"
            expected = reference(root, manifest, metadata)
            package["edition"] = "2024"
            self.assertNotEqual(expected, reference(root, manifest, metadata))

    def test_symlinked_wit_is_bound_and_outside_or_cyclic_links_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, metadata = self.fixture(root)
            runtime = root / "core/indexer/src/runtime"
            (manifest.parent / "wit").symlink_to(runtime, target_is_directory=True)
            expected = reference(root, manifest, metadata)
            (runtime / "semantics.rs").write_text("changed linked input")
            self.assertNotEqual(expected, reference(root, manifest, metadata))
            (runtime / "cycle").symlink_to(runtime, target_is_directory=True)
            with self.assertRaises(ValueError):
                reference(root, manifest, metadata)
            (runtime / "cycle").unlink()
            (runtime / "outside").symlink_to(root.parent, target_is_directory=True)
            with self.assertRaises(ValueError):
                reference(root, manifest, metadata)

    def test_verification_rejects_stale_or_replaced_reference_without_rewriting_it(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, metadata = self.fixture(root)
            destination = manifest.with_name("definition.bin")
            with self.assertRaises(FileNotFoundError):
                verify_reference(root, manifest, metadata)
            encoded = reference(root, manifest, metadata)
            destination.write_bytes(encoded)
            verified = verify_reference(root, manifest, metadata)
            self.assertEqual(verified["sha256"], hashlib.sha256(encoded).hexdigest())
            semantics = root / "core/indexer/src/runtime/semantics.rs"
            for path, replacement in ((semantics, b"changed rules"),
                                      (manifest.with_name("Cargo.lock"), b"changed lock"),
                                      (destination, b"different reference")):
                with self.subTest(path=path):
                    original = path.read_bytes()
                    path.write_bytes(replacement)
                    with self.assertRaisesRegex(ValueError, "reference differs"):
                        verify_reference(root, manifest, metadata)
                    self.assertEqual(path.read_bytes(), replacement)
                    path.write_bytes(original)
            metadata["resolve"]["nodes"][0]["features"].append("changed")
            with self.assertRaisesRegex(ValueError, "reference differs"):
                verify_reference(root, manifest, metadata)
            self.assertEqual(destination.read_bytes(), encoded)

    def test_bundle_build_rejects_stale_definition_before_compiling(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest, metadata = self.fixture(root)
            manifest.write_text(manifest.read_text() +
                                '[profile.dev]\npanic="unwind"\n[profile.release]\npanic="unwind"\n')
            wrapper = root / "tools/protocol-bundles/rustc-wrapper.py"
            wrapper.parent.mkdir(parents=True)
            wrapper.write_text("compiler wrapper")
            manifest.with_name("definition.bin").write_bytes(b"stale reference")
            args = SimpleNamespace(target="x86_64-unknown-linux-gnu", offline=True)
            with patch.object(build, "ROOT", root), patch.object(build, "identity", return_value={}), \
                    patch.object(build, "metadata", return_value=metadata) as resolve, \
                    patch.object(build, "run") as compile_graph:
                with self.assertRaisesRegex(ValueError, "reference differs"):
                    build.build_graph("first", args, {}, root / "output", EXECUTOR_GRAPHS)
                self.assertEqual([call.args[1] for call in resolve.call_args_list], [args.target, None])
                compile_graph.assert_not_called()

    def test_reference_metadata_is_unfiltered_and_locked(self):
        with patch.object(build.subprocess, "check_output", return_value="{}") as cargo:
            build.metadata(Path("Cargo.toml"), None, {}, True)
            command = cargo.call_args.args[0]
            self.assertNotIn("--filter-platform", command)
            self.assertIn("--locked", command)
            self.assertIn("--offline", command)
            build.metadata(Path("Cargo.toml"), "target", {}, True)
            command = cargo.call_args.args[0]
            self.assertEqual(command[command.index("--filter-platform") + 1], "target")


if __name__ == "__main__":
    unittest.main()
