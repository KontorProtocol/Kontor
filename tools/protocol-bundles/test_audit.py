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
from common_ownership import graph_references, linker_owners, reject_common_shadow, reject_unowned_references, runtime_paths
from provenance import fingerprint, source_inputs
from symbol_tool import inspect


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

    def test_bitcode_definitions_still_have_owners_and_collide(self):
        symbol = "_RNvCs123_5probe5STATE"
        native = ("_" if sys.platform == "darwin" else "") + symbol
        with patch("audit.inspect", return_value=f"---------------- T {native}\n"):
            self.assertEqual(definitions(Path("bitcode")), {symbol: {"address": None, "kind": "T"}})
            with tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                for graph in self.graphs:
                    path = root / graph["graph"]
                    path.write_bytes(b"fixture")
                    graph["artifacts"] = [{"path": str(path)}]
                with self.assertRaisesRegex(RuntimeError, "cross-graph definitions would coalesce"):
                    audit_inputs(self.graphs, root)
            with self.assertRaisesRegex(RuntimeError, "shadows common host/sysroot"):
                reject_common_shadow(self.graphs[0], {symbol}, definitions(Path("sysroot")))

    def test_final_bitcode_definition_has_no_linked_address(self):
        with patch("audit.definitions", return_value={"_start": {"address": None, "kind": "T"}}):
            with self.assertRaisesRegex(RuntimeError, "no linked address"):
                audit_final(Path("not-linked"), [], [], [], Path("unused"), {})

    def test_unknown_symbol_output_is_rejected(self):
        with patch("audit.inspect", return_value="plugin failed to decode object\n"):
            with self.assertRaisesRegex(RuntimeError, "unknown defined-symbol output"):
                definitions(Path("unreadable"))

    def test_failed_symbol_reader_never_accepts_partial_output(self):
        result = subprocess.CompletedProcess([], 1, "00000000 T partial\n", "incompatible bitcode")
        with patch("symbol_tool.executable", return_value=Path("pinned-llvm-nm")):
            with patch("symbol_tool.subprocess.run", return_value=result):
                with self.assertRaisesRegex(RuntimeError, "incompatible bitcode"):
                    inspect(["-g", Path("bad.rlib")])

    def test_unknown_c_symbol_is_rejected(self):
        with self.assertRaisesRegex(RuntimeError, "unowned native"):
            owner("unregistered_state", self.graphs[0], "51.0.0-dev")

    def test_darwin_platform_libraries_require_exact_system_paths(self):
        paths = ["/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/SystemConfiguration",
                 "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
                 "/usr/lib/libiconv.2.dylib", "/usr/lib/libSystem.B.dylib"]
        def listing(libraries):
            return "fixture:\n" + "".join(f"\t{path} (compatibility version 1.0.0, current version 1.0.0)\n"
                                         for path in libraries)
        with patch("common_ownership.sys.platform", "darwin"):
            with patch("common_ownership.subprocess.check_output", return_value=listing(paths)):
                self.assertEqual(runtime_paths(Path("fixture")), paths)
            for unexpected in ("/opt/homebrew/lib/libiconv.2.dylib", "@rpath/libiconv.2.dylib",
                               "/usr/lib/libiconv.3.dylib", "/usr/lib/libunregistered.dylib"):
                with self.subTest(unexpected=unexpected):
                    with patch("common_ownership.subprocess.check_output", return_value=listing(paths + [unexpected])):
                        with self.assertRaisesRegex(RuntimeError, "undeclared shared platform libraries"):
                            runtime_paths(Path("fixture"))

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
                    linker = {}
                    if sys.platform == "linux":
                        executable = root / "linked-weak"
                        subprocess.run(["cc", "-nostdlib", "-pie", "-Wl,-e,kontor_first_call",
                                        str(artifact), "-o", str(executable)], check=True)
                        linker = linker_owners(executable)
                    self.assertEqual(optional, {"__unw_add_dynamic_fde"})
                    reject_unowned_references(self.graphs[0], sets[0], refs, {}, {}, optional, linker)
                else:
                    self.assertFalse(optional)
                    with self.assertRaisesRegex(RuntimeError, "no declared owner"):
                        reject_unowned_references(self.graphs[0], sets[0], refs, {}, {}, optional, linker)

    def test_linker_got_requires_local_final_definition(self):
        got = {"_GLOBAL_OFFSET_TABLE_": {"kind": "d", "address": "1234"}}
        with patch("common_ownership.sys.platform", "linux"):
            with patch("common_ownership.definitions", return_value=got) as inventory:
                self.assertEqual(linker_owners(Path("fixture")), got)
                inventory.assert_called_once_with(Path("fixture"), globals_only=False)
            absolute = {"_GLOBAL_OFFSET_TABLE_": {"kind": "a", "address": "1234"}}
            with patch("common_ownership.definitions", return_value=absolute):
                self.assertEqual(linker_owners(Path("fixture")), absolute)
            with patch("common_ownership.definitions", return_value={}):
                self.assertEqual(linker_owners(Path("fixture")), {})
            for kind in ("D", "U", "w", "t"):
                with patch("common_ownership.definitions", return_value={"_GLOBAL_OFFSET_TABLE_": {"kind": kind}}):
                    with self.assertRaisesRegex(RuntimeError, "not local linker data"):
                        linker_owners(Path("fixture"))
        with patch("common_ownership.sys.platform", "darwin"):
            with patch("common_ownership.definitions", return_value=got) as inventory:
                self.assertEqual(linker_owners(Path("fixture")), {})
                inventory.assert_not_called()

    def test_linker_got_does_not_allow_other_imports_or_bundle_definitions(self):
        graph = self.graphs[0]
        got = {"_GLOBAL_OFFSET_TABLE_": {"kind": "d", "address": "1234"}}
        reject_unowned_references(graph, set(), set(got), {}, {}, set(), got)
        for refs, linker in ((set(got), {}), ({"unknown_import"}, got)):
            with self.assertRaisesRegex(RuntimeError, "no declared owner"):
                reject_unowned_references(graph, set(), refs, {}, {}, set(), linker)
        with self.assertRaisesRegex(RuntimeError, "unowned native"):
            owner("_GLOBAL_OFFSET_TABLE_", graph, "51.0.0-dev")

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
            engine = root / "core/indexer/src/runtime/mod.rs"
            engine.parent.mkdir(parents=True)
            engine.write_text("node engine configuration")
            manifest = root / "Cargo.toml"
            source = root / "lib.rs"
            manifest.write_text('[package]\nname="example"\n')
            (root / "Cargo.lock").write_text('version=4\npackage=[]\n')
            source.write_text("pub fn result() -> u8 { 1 }")
            data = {"workspace_root": str(root), "packages": [{"manifest_path": str(manifest), "id": "example"}]}
            before = fingerprint(source_inputs(root, data))
            source.write_text("pub fn result() -> u8 { 2 }")
            self.assertNotEqual(before, fingerprint(source_inputs(root, data)))

    def test_inherited_workspace_manifest_is_fingerprinted(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            engine = root / "core/indexer/src/runtime/mod.rs"
            engine.parent.mkdir(parents=True)
            engine.write_text("node engine configuration")
            (root / ".git").mkdir()
            manifest = root / "Cargo.toml"
            manifest.write_text('[workspace.dependencies]\nitoa="=1.0.14"\n')
            (root / "Cargo.lock").write_text('version=4\npackage=[]\n')
            package = root / "crates/example/Cargo.toml"
            package.parent.mkdir(parents=True)
            package.write_text('[package]\nname="example"\n')
            data = {"workspace_root": str(root), "packages": [{"manifest_path": str(package), "id": "example"}]}
            before = fingerprint(source_inputs(root, data))
            manifest.write_text('[workspace.dependencies]\nitoa="=1.0.15"\n')
            self.assertNotEqual(before, fingerprint(source_inputs(root, data)))
            before = fingerprint(source_inputs(root, data))
            engine.write_text("changed node engine configuration")
            self.assertNotEqual(before, fingerprint(source_inputs(root, data)))


if __name__ == "__main__":
    unittest.main()
