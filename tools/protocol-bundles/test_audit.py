"""Negative ownership controls that must fail before link-time dead stripping."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import Mock, patch

from audit import GDB_SCRIPT, audit_inputs, audit_final, compiler_debug_metadata, definitions, owner, private_local_inputs
from build import digest, verify_staged_inputs
from common_ownership import graph_references, linker_owners, platform_owners, reject_common_shadow, reject_unowned_references, runtime_paths, verify
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

    def test_executor_final_audit_accepts_linked_native_subset_without_ring(self):
        first = "kontor_first_blst_keygen"
        second = "kontor_second_rustsecp256k1_v0_10_0_default_illegal_callback_fn"
        local = {first: {"address": "1000", "kind": "t"},
                 second: {"address": "2000", "kind": "t"}}
        sets = [{first}, {second}]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("audit.private_local_inputs", return_value=([set(), set()], [])):
                with patch("audit.definitions", side_effect=lambda _path, globals_only=True:
                           {} if globals_only else local):
                    result = audit_final(Path("linked-node"), self.graphs, sets,
                                         ["51.0.0-dev", "51.0.0-kontor.1"], root, {}, kind="executor")
            self.assertEqual(result["wasmtime"], {})
            self.assertEqual(set(result["native"]), {first, second})
            self.assertEqual(set(result["crypto"]), {first, second})
            inventory = json.loads((root / "final-ownership.json").read_text())
            self.assertEqual(inventory[first]["owner"], "first")
            self.assertEqual(inventory[second]["owner"], "second")
            with patch("audit.private_local_inputs", return_value=([set(), set()], [])):
                with patch("audit.definitions", side_effect=lambda _path, globals_only=True:
                           {"unowned_final": {"address": "3000", "kind": "T"}} if globals_only else local):
                    with self.assertRaisesRegex(RuntimeError, "ambiguous or unowned final definition"):
                        audit_final(Path("linked-node"), self.graphs, sets,
                                    ["51.0.0-dev", "51.0.0-kontor.1"], root, {}, kind="executor")
            with patch("audit.definitions", side_effect=lambda _path, globals_only=True:
                       {} if globals_only else local):
                with self.assertRaisesRegex(RuntimeError, "missing graph-private Wasmtime native helper"):
                    audit_final(Path("linked-proof"), self.graphs, sets,
                                ["51.0.0-dev", "51.0.0-kontor.1"], root, {})

    def test_executor_final_audit_rejects_unowned_or_aliased_private_symbols(self):
        first = "kontor_first_blst_keygen"
        second = "kontor_second_blst_keygen"
        sets = [{first}, {second}]
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for local, message in (
                ({first: {"address": "1000", "kind": "t"},
                  second: {"address": "1000", "kind": "t"}}, "alias one address"),
                ({"kontor_first_unowned": {"address": "1000", "kind": "t"}}, "unowned graph-private"),
            ):
                with self.subTest(message=message):
                    with patch("audit.private_local_inputs", return_value=([set(), set()], [])):
                        with patch("audit.definitions", side_effect=lambda _path, globals_only=True:
                                   {} if globals_only else local):
                            with self.assertRaisesRegex(RuntimeError, message):
                                audit_final(Path("linked-node"), self.graphs, sets,
                                            ["51.0.0-dev", "51.0.0-kontor.1"], root, {},
                                            kind="executor")

    def test_executor_final_node_owner_requires_concrete_input(self):
        symbol = "blst_keygen"
        linked = {symbol: {"address": "1000", "kind": "T"}}
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with patch("audit.private_local_inputs", return_value=([set(), set()], [])):
                with patch("audit.definitions", side_effect=lambda _path, globals_only=True:
                           linked if globals_only else {}):
                    with self.assertRaisesRegex(RuntimeError, "unowned final definition"):
                        audit_final(Path("linked-node"), self.graphs, [set(), set()],
                                    ["51.0.0-dev", "51.0.0-kontor.1"], root, {}, kind="executor")
                    audit_final(Path("linked-node"), self.graphs, [set(), set()],
                                ["51.0.0-dev", "51.0.0-kontor.1"], root, {}, kind="executor",
                                node={symbol: ["node/libblst.a"]})
            final = json.loads((root / "final-ownership.json").read_text())
            self.assertEqual(final[symbol]["owner"], {"node_inputs": ["node/libblst.a"]})

    def test_private_local_input_inventory_keeps_globals_separate(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            local_names = []
            global_names = []
            for graph in self.graphs:
                local = graph["namespace"] + "_native_static"
                public = graph["namespace"] + "_call"
                source = f"static int {local}(void) {{ return 1; }} int {public}(void) {{ return {local}(); }}"
                artifact = self.object(root, graph["graph"], source)
                if graph["graph"] == "first":
                    graph["artifacts"] = [{"path": str(artifact), "sha256": digest(artifact)}]
                else:
                    archive = root / "libnative.a"
                    subprocess.run(["ar", "crs", str(archive), str(artifact)], check=True)
                    graph["native_artifacts"] = [{"path": str(archive), "sha256": digest(archive)}]
                local_names.append(local)
                global_names.append(public)
            sets, _ = audit_inputs(self.graphs, root)
            private_sets, inventory = private_local_inputs(self.graphs)
            for index in range(2):
                self.assertIn(global_names[index], sets[index])
                self.assertNotIn(local_names[index], sets[index])
                self.assertIn(local_names[index], private_sets[index])
                self.assertNotIn(global_names[index], private_sets[index])
                self.assertTrue(inventory[index]["inputs"][0]["sha256"])
            linked = {name: {"address": str(index + 1), "kind": "t"}
                      for index, name in enumerate(local_names)}
            actual_definitions = definitions
            def linked_definitions(path, globals_only=True):
                if Path(path) == Path("linked-node"):
                    return {} if globals_only else linked
                return actual_definitions(path, globals_only=globals_only)
            with patch("audit.definitions", side_effect=linked_definitions):
                result = audit_final(Path("linked-node"), self.graphs, sets,
                                     ["51.0.0-dev", "51.0.0-kontor.1"], root, {},
                                     kind="executor")
            self.assertEqual(set(result["native"]), set(local_names))
            def falsely_global(path, globals_only=True):
                if Path(path) == Path("linked-node") and globals_only:
                    return {local_names[0]: linked[local_names[0]]}
                return linked_definitions(path, globals_only=globals_only)
            with patch("audit.definitions", side_effect=falsely_global):
                with self.assertRaisesRegex(RuntimeError, "ambiguous or unowned final definition"):
                    audit_final(Path("linked-node"), self.graphs, sets,
                                ["51.0.0-dev", "51.0.0-kontor.1"], root, {},
                                kind="executor")
            first_input = Path(self.graphs[0]["artifacts"][0]["path"])
            first_input.write_bytes(first_input.read_bytes() + b"changed")
            with self.assertRaisesRegex(RuntimeError, "staged graph input changed"):
                private_local_inputs(self.graphs)

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
            cpp = "/usr/lib/libc++.1.dylib"
            with patch("common_ownership.subprocess.check_output", return_value=listing(paths + [cpp])):
                self.assertEqual(runtime_paths(Path("fixture"), kind="executor"), paths + [cpp])
                with self.assertRaisesRegex(RuntimeError, "undeclared shared platform libraries"):
                    runtime_paths(Path("fixture"))
            with patch("common_ownership.subprocess.check_output",
                       return_value=listing(paths + ["/opt/homebrew/lib/libc++.1.dylib"])):
                with self.assertRaisesRegex(RuntimeError, "undeclared shared platform libraries"):
                    runtime_paths(Path("fixture"), kind="executor")

    def test_linux_node_cpp_runtime_is_explicit_and_unknown_libraries_stay_rejected(self):
        def listing(paths):
            return "".join(f"{Path(path).name} => {path} (0x1234)\n" for path in paths)
        paths = ["/lib64/libc.so.6", "/lib64/libstdc++.so.6"]
        with patch("common_ownership.sys.platform", "linux"):
            with patch("common_ownership.subprocess.check_output", return_value=listing(paths)):
                self.assertEqual(runtime_paths(Path("fixture"), kind="executor"), paths)
                with self.assertRaisesRegex(RuntimeError, "undeclared shared platform libraries"):
                    runtime_paths(Path("fixture"))
            with patch("common_ownership.subprocess.check_output",
                       return_value=listing(paths + ["/opt/lib/libunregistered.so"])):
                with self.assertRaisesRegex(RuntimeError, "undeclared shared platform libraries"):
                    runtime_paths(Path("fixture"), kind="executor")
            with self.assertRaisesRegex(RuntimeError, "unknown runtime audit kind"):
                runtime_paths(Path("fixture"), kind="other")

    def test_node_runtime_still_hashes_actual_library_and_resolves_its_exports(self):
        with tempfile.TemporaryDirectory() as directory:
            library = Path(directory) / "libstdc++.so.6"
            library.write_bytes(b"fixture-cpp-runtime")
            with patch("common_ownership.runtime_paths", return_value=[str(library)]) as paths:
                with patch("common_ownership.ctypes.CDLL", return_value=Mock(spec=["owned_export"])):
                    owners, libraries = platform_owners(Path("fixture"), {"owned_export", "absent_export"},
                                                         kind="executor")
            paths.assert_called_once_with(Path("fixture"), kind="executor")
            self.assertEqual(owners, {"owned_export": [str(library)]})
            self.assertEqual(libraries[0]["path"], str(library))
            self.assertEqual(libraries[0]["sha256"], digest(library))
            self.assertEqual(libraries[0]["symbols_resolved_in_library_scope"], ["owned_export"])

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

    def debug_object(self, root, name, section=".debug_gdb_scripts", payload="gdb_load_rust_pretty_printers.py", weak=True):
        source = root / (name + ".S")
        source.write_text(f'.section {section},"aMS",%progbits,1\n'
                          + (".weak " if weak else ".globl ") + GDB_SCRIPT + "\n"
                          + f'.type {GDB_SCRIPT}, %object\n{GDB_SCRIPT}:\n.byte 1\n'
                          + f'.asciz "{payload}"\n.size {GDB_SCRIPT}, .-{GDB_SCRIPT}\n')
        output = source.with_suffix(".o")
        subprocess.run(["cc", "-c", str(source), "-o", str(output)], check=True)
        return output

    @unittest.skipUnless(sys.platform == "linux", "exact compiler metadata shape is ELF-specific")
    def test_compiler_debug_metadata_requires_exact_object_shape(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            first = self.debug_object(root, "first")
            second = self.debug_object(root, "second")
            self.graphs[0]["artifacts"] = [{"path": str(first)}]
            self.graphs[1]["artifacts"] = [{"path": str(second)}]
            sets, _ = audit_inputs(self.graphs, root)
            self.assertEqual(sets[0] & sets[1], {GDB_SCRIPT})
            self.assertEqual(compiler_debug_metadata(first), 1)
            linked = root / "metadata.so"
            subprocess.run(["cc", "-nostdlib", "-shared", str(first), "-o", str(linked)], check=True)
            self.assertEqual(compiler_debug_metadata(linked, linked=True), 1)
            with self.assertRaisesRegex(RuntimeError, "unverified compiler GDB metadata"):
                owner(GDB_SCRIPT, self.graphs[0], "51.0.0-dev")
            for name, kwargs in (("wrong_payload", {"payload": "gdb_load_rust_pretty_printers.pz"}),
                                 ("wrong_section", {"section": ".rodata.fake_gdb_scripts"}),
                                 ("strong", {"weak": False})):
                with self.subTest(name=name):
                    forged = self.debug_object(root, name, **kwargs)
                    self.graphs[0]["artifacts"] = [{"path": str(forged)}]
                    with self.assertRaisesRegex(RuntimeError, "compiler GDB metadata"):
                        audit_inputs(self.graphs, root)

    @unittest.skipUnless(sys.platform == "linux", "compiler metadata reference check is ELF-specific")
    def test_compiler_debug_metadata_cannot_be_a_code_reference(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            importer = self.object(root, "importer",
                                   f'extern char {GDB_SCRIPT}; char *kontor_first_pointer = &{GDB_SCRIPT};')
            self.graphs[0]["artifacts"] = [{"path": str(importer)}]
            sets, _ = audit_inputs(self.graphs, root)
            with self.assertRaisesRegex(RuntimeError, "references compiler debug metadata as code"):
                graph_references(self.graphs[0], 0, sets)

    def test_unprefixed_native_helpers_are_rejected_even_from_known_packages(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("rust_psm_on_stack", "rust_psm_replace_stack",
                         "rust_psm_stack_direction", "rust_psm_stack_pointer",
                         "cabi_realloc_wit_bindgen_0_63_0"):
                with self.subTest(name=name):
                    package = "psm" if name.startswith("rust_psm_") else "wit-bindgen"
                    version = "0.1.32" if package == "psm" else "0.63.0"
                    crate = package.replace("-", "_")
                    artifact = root / f"lib{crate}-1234567890abcdef.rlib"
                    obj = self.object(root, name, f"int {name}(void) {{ return 1; }}")
                    artifact.unlink(missing_ok=True)
                    subprocess.run(["ar", "crs", str(artifact), str(obj)], check=True)
                    self.graphs[0]["packages"].append({"name": package, "version": version})
                    self.graphs[0]["artifacts"] = [{"path": str(artifact),
                                                    "source_path": str(root / "target/debug/deps" / artifact.name)}]
                    with self.assertRaisesRegex(RuntimeError, "unowned native input definition"):
                        audit_inputs(self.graphs, root)
                    self.graphs[0]["packages"].pop()

    def test_namespaced_native_helpers_and_references_remain_graph_private(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for graph in self.graphs:
                prefix = graph["namespace"] + "_"
                names = [prefix + name for name in ("rust_psm_on_stack", "rust_psm_replace_stack",
                                                    "rust_psm_stack_direction", "rust_psm_stack_pointer",
                                                    "cabi_realloc_wit_bindgen_0_63_0")]
                source = "".join(f"int {name}(void) {{ return 1; }}\n" for name in names)
                artifact = self.object(root, graph["graph"] + "_symbols", source)
                caller = self.object(root, graph["graph"] + "_caller",
                                     f"extern int {names[0]}(void); int {prefix}call(void) {{ return {names[0]}(); }}")
                graph["artifacts"] = [{"path": str(artifact)}, {"path": str(caller)}]
            sets, _ = audit_inputs(self.graphs, root)
            self.assertFalse(sets[0] & sets[1])
            for index, graph in enumerate(self.graphs):
                references, _ = graph_references(graph, index, sets)
                self.assertEqual(references, {graph["namespace"] + "_rust_psm_on_stack"})

    def test_duplicate_psm_native_archive_must_match_embedded_object(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            objects = []
            for index in (1, 2):
                source_dir = root / str(index)
                source_dir.mkdir()
                objects.append(self.object(
                    source_dir, "psm_native",
                    f"int kontor_first_rust_psm_on_stack(void) {{ return {index}; }}"))
            rlib = root / "libpsm-1234567890abcdef.rlib"
            native = root / "libpsm_s.a"
            subprocess.run(["ar", "crs", str(rlib), str(objects[0])], check=True)
            subprocess.run(["ar", "crs", str(native), str(objects[0])], check=True)
            self.graphs[0]["artifacts"] = [{"path": str(rlib)}]
            self.graphs[0]["native_artifacts"] = [{"path": str(native)}]
            audit_inputs(self.graphs, root)
            native.unlink()
            subprocess.run(["ar", "crs", str(native), str(objects[1])], check=True)
            with self.assertRaisesRegex(RuntimeError, "psm native archive copies differ"):
                audit_inputs(self.graphs, root)

    def object(self, root, name, source):
        path = root / (name + ".c")
        path.write_text(source)
        output = path.with_suffix(".o")
        subprocess.run(["cc", "-c", str(path), "-o", str(output)], check=True)
        return output

    def test_executor_node_native_definition_cannot_own_retained_import(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            node_native = self.object(root, "node_native", "int blst_keygen(void) { return 1; }")
            root_codegen = self.object(root, "root_codegen", "int kontor_node_root(void) { return 1; }")
            importer = self.object(root, "retained", "extern int blst_keygen(void); int kontor_first_call(void) { return blst_keygen(); }")
            executable = root / "node"
            subprocess.run(["cc", "-x", "c", "-", "-o", str(executable)],
                           input="int main(void) { return 0; }", text=True, check=True)
            self.graphs[0]["artifacts"] = [{"path": str(importer)}]
            sets, _ = audit_inputs(self.graphs, root)
            env = dict(os.environ, RUSTC="rustc")
            with self.assertRaisesRegex(RuntimeError, "imports have no declared owner.*blst_keygen"):
                verify(self.graphs, sets, [], executable, env, root, kind="executor",
                       node_objects=[node_native, root_codegen], compiler_objects=[root_codegen])

            platform_importer = self.object(root, "platform_importer",
                                            'extern int puts(const char *); int kontor_first_call(void) { return puts("ok"); }')
            self.graphs[0]["artifacts"] = [{"path": str(platform_importer)}]
            sets, _ = audit_inputs(self.graphs, root)
            common, node = verify(self.graphs, sets, [], executable, env, root, kind="executor",
                                  node_objects=[node_native, root_codegen], compiler_objects=[root_codegen])
            self.assertIn("blst_keygen", node)
            self.assertNotIn("blst_keygen", common)
            report = json.loads((root / "common-reference-ownership.json").read_text())
            self.assertIn("puts", report["references"][0]["platform"])
            self.assertNotIn(str(node_native), [item["path"] for item in report["common_inputs"]])
            node_report = json.loads((root / "node-input-ownership.json").read_text())
            self.assertEqual([item["path"] for item in node_report["node_inputs"]],
                             sorted([str(node_native), str(root_codegen)]))
            node_collision = self.object(root, "node_collision",
                                         "int kontor_first_call(void) { return 1; }")
            with self.assertRaisesRegex(RuntimeError, "shadows node input definitions"):
                verify(self.graphs, sets, [], executable, env, root, kind="executor",
                       node_objects=[node_collision, root_codegen], compiler_objects=[root_codegen])

    def test_executor_compiler_allocator_requires_root_codegen_owner(self):
        symbol = "_RNvCs1234_7___rustc12___rust_alloc"
        native = ("_" if sys.platform == "darwin" else "") + symbol
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            allocator = self.object(root, "allocator",
                                    f'int shim(void) __asm__("{native}"); int shim(void) {{ return 1; }}')
            root_codegen = self.object(root, "root_codegen", "int kontor_node_root(void) { return 1; }")
            importer = self.object(root, "retained",
                                   f'extern int shim(void) __asm__("{native}"); int kontor_first_call(void) {{ return shim(); }}')
            executable = root / "node"
            subprocess.run(["cc", "-x", "c", "-", "-o", str(executable)],
                           input="int main(void) { return 0; }", text=True, check=True)
            self.graphs[0]["artifacts"] = [{"path": str(importer)}]
            sets, _ = audit_inputs(self.graphs, root)
            env = dict(os.environ, RUSTC="rustc")
            with self.assertRaisesRegex(RuntimeError, "imports have no declared owner"):
                verify(self.graphs, sets, [], executable, env, root, kind="executor",
                       node_objects=[allocator, root_codegen], compiler_objects=[root_codegen])
            common, node = verify(self.graphs, sets, [], executable, env, root, kind="executor",
                                  node_objects=[allocator, root_codegen], compiler_objects=[allocator])
            self.assertNotIn(symbol, common)
            self.assertIn(symbol, node)
            report = json.loads((root / "common-reference-ownership.json").read_text())
            self.assertEqual(report["references"][0]["compiler_runtime"], [symbol])
            node_report = json.loads((root / "node-input-ownership.json").read_text())
            self.assertEqual(node_report["compiler_runtime"][symbol], [str(allocator)])
            duplicate = self.object(root, "duplicate_allocator",
                                    f'int shim(void) __asm__("{native}"); int shim(void) {{ return 2; }}')
            with self.assertRaisesRegex(RuntimeError, "duplicates root compiler runtime"):
                verify(self.graphs, sets, [], executable, env, root, kind="executor",
                       node_objects=[allocator, duplicate], compiler_objects=[allocator])

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
            retained = root / "core/indexer/src/protocol/v1"
            retained.mkdir(parents=True)
            for name in ("engine", "resources", "gas", "native", "errors", "fuel", "fees", "deposit"):
                (retained / f"{name}.rs").write_text(f"retained {name} policy")
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
            retained = root / "core/indexer/src/protocol/v1"
            retained.mkdir(parents=True)
            for name in ("engine", "resources", "gas", "native", "errors", "fuel", "fees", "deposit"):
                (retained / f"{name}.rs").write_text(f"retained {name} policy")
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
            for name in ("engine", "resources", "gas", "native", "errors", "fuel", "fees", "deposit"):
                before = fingerprint(source_inputs(root, data))
                (retained / f"{name}.rs").write_text(f"changed retained {name} policy")
                self.assertNotEqual(before, fingerprint(source_inputs(root, data)))


if __name__ == "__main__":
    unittest.main()
