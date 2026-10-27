"""Negative ownership controls that must fail before link-time dead stripping."""

import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from audit import audit_inputs, audit_final, definitions, owner
from build import digest, verify_staged_inputs
from common_ownership import graph_references, reject_common_shadow, reject_unowned_references
from provenance import fingerprint, source_inputs


class Ownership(unittest.TestCase):
    def setUp(self):
        self.graphs = [
            {"graph": name, "namespace": "kontor_" + name,
             "packages": [{"name": "wasmtime", "version": version}],
             "artifacts": [], "native_artifacts": []}
            for name, version in [("first", "51.0.0-dev"), ("second", "51.0.0-kontor.1")]
        ]

    def collision(self, symbol):
        symbol = ("_" if sys.platform == "darwin" else "") + symbol
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for graph in self.graphs:
                source = root / (graph["graph"] + ".c")
                artifact = source.with_suffix(".o")
                source.write_text('int state __asm__("' + symbol + '") = 1;\n')
                subprocess.run(["cc", "-c", str(source), "-o", str(artifact)], check=True)
                graph["artifacts"] = [{"path": str(artifact)}]
            with self.assertRaisesRegex(RuntimeError, "cross-graph definitions would coalesce"):
                audit_inputs(self.graphs, root)

    def test_rust_shaped_global_cannot_hide_collision(self):
        self.collision("_ZN5probe5STATE17h1234567890abcdefE")

    def test_anonymous_constant_cannot_hide_collision(self):
        self.collision("anon.1234abcd.0")

    def test_unknown_c_symbol_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "unowned native"):
            owner("unregistered_state", self.graphs[0], "51.0.0-dev")

    def test_bundle_allocator_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "process allocator"):
            owner("__rust_alloc", self.graphs[0], "51.0.0-dev")

    def test_wasmtime_copy_cannot_reuse_version(self):
        self.graphs[1]["packages"][0]["version"] = "51.0.0-dev"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "unique versions"):
                audit_inputs(self.graphs, Path(directory))

    def test_normalized_version_collision_is_rejected(self):
        self.graphs[1]["packages"][0]["version"] = "51.0.0+dev"
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaisesRegex(RuntimeError, "unique versions"):
                audit_inputs(self.graphs, Path(directory))

    def test_runtime_reference_is_the_only_shared_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for graph in self.graphs:
                path = root / graph["graph"]
                path.write_bytes(b"fixture")
                graph["artifacts"] = [{"path": str(path)}]
            with patch("audit.definitions", return_value={"DW.ref.rust_eh_personality": {"address": "0", "kind": "V"}}):
                sets, _ = audit_inputs(self.graphs, root)
            self.assertEqual(sets[0] & sets[1], {"DW.ref.rust_eh_personality"})
            self.assertEqual(len(json.loads((root / "input-ownership.json").read_text())), 2)

    def object(self, root, name, source):
        path = root / (name + ".c")
        path.write_text(source)
        output = path.with_suffix(".o")
        subprocess.run(["cc", "-c", str(path), "-o", str(output)], check=True)
        return output

    def test_undefined_foreign_import_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            foreign = self.object(root, "foreign", "int kontor_second_secret(void) { return 1; }")
            importer = self.object(root, "importer", "extern int kontor_second_secret(void); int kontor_first_call(void) { return kontor_second_secret(); }")
            self.graphs[0]["artifacts"] = [{"path": str(importer)}]
            self.graphs[1]["artifacts"] = [{"path": str(foreign)}]
            sets, _ = audit_inputs(self.graphs, root)
            with self.assertRaisesRegex(RuntimeError, "references another graph"):
                graph_references(self.graphs[0], 0, sets)

    def test_weak_rust_shaped_definition_cannot_shadow_common_input(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            symbol = ("_" if sys.platform == "darwin" else "") + "_ZN5probe5STATE17h1234567890abcdefE"
            source = f'int state __asm__("{symbol}") __attribute__((weak)) = 1;'
            common = self.object(root, "common", source)
            bundle = self.object(root, "bundle", source)
            self.graphs[0]["artifacts"] = [{"path": str(bundle)}]
            sets, _ = audit_inputs(self.graphs, root)
            with self.assertRaisesRegex(RuntimeError, "shadows common host/sysroot"):
                reject_common_shadow(self.graphs[0], sets[0], definitions(common))

    def test_only_weak_system_unwind_imports_are_optional(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for weak in (True, False):
                attribute = ("__attribute__((weak_import))" if sys.platform == "darwin"
                             else "__attribute__((weak))") if weak else ""
                source = f"extern void __unw_add_dynamic_fde(void) {attribute}; void kontor_first_call(void) {{ if (__unw_add_dynamic_fde) __unw_add_dynamic_fde(); }}"
                artifact = self.object(root, "optional" if weak else "strong", source)
                self.graphs[0]["artifacts"] = [{"path": str(artifact)}]
                sets, _ = audit_inputs(self.graphs, root)
                refs, optional = graph_references(self.graphs[0], 0, sets)
                if weak:
                    self.assertEqual(optional, {"__unw_add_dynamic_fde"})
                    reject_unowned_references(self.graphs[0], sets[0], refs, {}, {}, optional)
                else:
                    self.assertFalse(optional)
                    with self.assertRaisesRegex(RuntimeError, "no declared owner"):
                        reject_unowned_references(self.graphs[0], sets[0], refs, {}, {}, optional)

    def test_unknown_final_rust_symbol_has_no_automatic_common_exemption(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            symbol = ("_" if sys.platform == "darwin" else "") + "_ZN5probe5STATE17h1234567890abcdefE"
            artifact = self.object(root, "unknown", f'int state __asm__("{symbol}") = 1;')
            with self.assertRaisesRegex(RuntimeError, "unowned final definition"):
                audit_final(artifact, self.graphs, [set(), set()], [], root, {})

    def test_staged_input_mutation_is_detected(self):
        with tempfile.TemporaryDirectory() as directory:
            artifact = Path(directory) / "staged.rlib"
            artifact.write_bytes(b"original")
            graph = {"artifacts": [{"path": str(artifact), "sha256": digest(artifact)}],
                     "native_artifacts": [], "compiler_proc_macros": []}
            verify_staged_inputs(graph)
            artifact.write_bytes(b"changed after staging")
            with self.assertRaisesRegex(RuntimeError, "staged compiler input changed"):
                verify_staged_inputs(graph)

    def test_source_mutation_changes_provenance_even_with_unchanged_lock(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            manifest = root / "Cargo.toml"
            source = root / "lib.rs"
            manifest.write_text('[package]\nname="example"\n')
            source.write_text("pub fn result() -> u8 { 1 }")
            data = {"packages": [{"manifest_path": str(manifest), "id": "example"}]}
            before = fingerprint(source_inputs(root, data))
            source.write_text("pub fn result() -> u8 { 2 }")
            self.assertNotEqual(before, fingerprint(source_inputs(root, data)))

    def test_inherited_workspace_manifest_is_fingerprinted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / ".git").mkdir()
            manifest = root / "Cargo.toml"
            manifest.write_text('[workspace.dependencies]\nitoa="=1.0.14"\n')
            package = root / "crates/example/Cargo.toml"
            package.parent.mkdir(parents=True)
            package.write_text('[package]\nname="example"\n')
            data = {"packages": [{"manifest_path": str(package), "id": "example"}]}
            before = fingerprint(source_inputs(root, data))
            manifest.write_text('[workspace.dependencies]\nitoa="=1.0.15"\n')
            self.assertNotEqual(before, fingerprint(source_inputs(root, data)))


if __name__ == "__main__":
    unittest.main()
