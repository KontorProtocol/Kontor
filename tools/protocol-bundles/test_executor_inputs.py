import copy
from pathlib import Path
import tempfile
import unittest

from build import ROOT, identities
from provenance import RETAINED_TREES, fingerprint, retained_sources
from recipes import EXECUTOR_GRAPHS, GRAPHS
from source_policy import check


class ExecutorDependencies(unittest.TestCase):
    def metadata(self):
        recipe = EXECUTOR_GRAPHS["first"]
        packages = [
            {"id": "root", "name": "kontor-executor-first", "version": "0.1.0", "source": None},
            {"id": "vm", "name": "wasmtime", "version": recipe.version,
             "source": "git+https://github.com/wilfreddenton/wasmtime#" + recipe.revision},
            *({"id": name, "name": name, "version": "0.0.0", "source": None,
               "manifest_path": str(ROOT / "core/vendor" / name / "Cargo.toml")}
              for name in recipe.native_patches),
        ]
        nodes = [{"id": p["id"], "features": [], "deps": []} for p in packages]
        nodes[0]["deps"] = [{"pkg": p["id"]} for p in packages[1:]]
        return {"packages": packages, "resolve": {"root": "root", "nodes": nodes}}

    def test_executor_does_not_require_unused_proof_dependencies(self):
        data = self.metadata()
        selected = identities("first", data, EXECUTOR_GRAPHS)
        self.assertEqual({p["name"] for p in selected},
                         {"kontor-executor-first", "wasmtime", "blst", "secp256k1-sys"})
        with self.assertRaisesRegex(RuntimeError, "expected one arc-malachitebft-app-channel"):
            identities("first", data, GRAPHS)

    def test_executor_still_requires_native_patches_and_pinned_vm(self):
        original = self.metadata()
        for name in EXECUTOR_GRAPHS["first"].native_patches:
            data = copy.deepcopy(original)
            package = next(p for p in data["packages"] if p["name"] == name)
            package["manifest_path"] = str(ROOT / "unpatched" / name / "Cargo.toml")
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "missing native patch"):
                identities("first", data, EXECUTOR_GRAPHS)
        data = copy.deepcopy(original)
        data["packages"][1]["source"] = "git+different#" + "0" * 40
        with self.assertRaisesRegex(RuntimeError, "immutable Wasmtime identity"):
            identities("first", data, EXECUTOR_GRAPHS)
        data = copy.deepcopy(original)
        data["resolve"]["nodes"][1]["features"] = ["profiling"]
        with self.assertRaisesRegex(RuntimeError, "forbidden Wasmtime feature"):
            identities("first", data, EXECUTOR_GRAPHS)

    def test_node_services_cannot_enter_executor_closure(self):
        for name in ("libsql", "arc-malachitebft-app-channel", "if-watch", "ring"):
            data = self.metadata()
            data["packages"].append({"id": "extra", "name": name, "version": "0.0.0",
                                     "source": None, "manifest_path": "/unpatched/Cargo.toml"})
            data["resolve"]["nodes"].append({"id": "extra", "features": [], "deps": []})
            data["resolve"]["nodes"][0]["deps"].append({"pkg": "extra"})
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "node-owned|native patch"):
                identities("first", data, EXECUTOR_GRAPHS)


class ExecutorSources(unittest.TestCase):
    def setUp(self):
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.root = Path(temporary.name)
        for relative in RETAINED_TREES:
            (self.root / relative).mkdir(parents=True)
        self.files = (
            "protocol-bundles/executor/lib.rs",
            "protocol-bundles/executor/build.rs",
            "core/indexer/src/runtime/call.rs",
            "core/indexer/src/runtime/wit/deps/built-in/context.wit",
            "core/indexer/src/protocol/v1/native/token.wasm.br",
            "core/indexer/src/bls/mod.rs",
            "native-contracts/token/wit/deps/built-in/types.wit",
        )
        for relative in self.files:
            path = self.root / relative
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text("original")

    def test_external_rust_wit_and_artifact_edits_invalidate_evidence(self):
        original = retained_sources(self.root)
        for relative in self.files:
            path = self.root / relative
            for mutation in ("change", "remove"):
                with self.subTest(path=relative, mutation=mutation):
                    if mutation == "change":
                        path.write_text("changed")
                    else:
                        path.unlink()
                    self.assertNotEqual(fingerprint(original), fingerprint(retained_sources(self.root)))
                    path.write_text("original")
        added = self.root / "core/indexer/src/runtime/new_module.rs"
        added.write_text("new")
        self.assertNotEqual(fingerprint(original), fingerprint(retained_sources(self.root)))

    def test_missing_external_tree_is_an_error(self):
        (self.root / "native-contracts/nft/wit").rmdir()
        with self.assertRaisesRegex(RuntimeError, "missing retained source tree"):
            retained_sources(self.root)

    def test_process_control_is_checked_in_actual_executor_sources(self):
        (self.root / "core/indexer/src/runtime/mod.rs").write_text(
            "#[cfg(not(kontor_retained))]\npub mod ownership;\n"
            "#[cfg(not(kontor_retained))]\npub mod pool;\n")
        (self.root / "core/indexer/src/protocol/mod.rs").write_text(
            "#[cfg(not(kontor_retained))]\npub(crate) mod coordinator;\n")
        ownership = self.root / "core/indexer/src/runtime/ownership.rs"
        ownership.write_text("std::process::abort();")
        call = self.root / "core/indexer/src/runtime/call.rs"
        call.write_text("#[cfg(test)]\nmod tests;\n")
        test = call.parent / "call/tests/process.rs"
        test.parent.mkdir(parents=True)
        test.write_text('Command::new("fixture");')
        report = check(self.root, {"packages": []}, kind="executor")
        self.assertEqual([x["path"] for x in report["test_only_sources"]], [str(test)])
        self.assertEqual([x["path"] for x in report["node_only_sources"]], [str(ownership)])
        production = self.root / "core/indexer/src/runtime/process.rs"
        production.write_text(test.read_text())
        with self.assertRaisesRegex(RuntimeError, "process-ownership review"):
            check(self.root, {"packages": []}, kind="executor")
        production.unlink()
        call.write_text("mod tests;\n")
        with self.assertRaisesRegex(RuntimeError, "exclusion guard changed"):
            check(self.root, {"packages": []}, kind="executor")
        call.write_text("#[cfg(test)]\nmod tests;\n")
        (self.root / "core/indexer/src/runtime/mod.rs").write_text("pub mod ownership;\n")
        with self.assertRaisesRegex(RuntimeError, "exclusion guard changed"):
            check(self.root, {"packages": []}, kind="executor")


if __name__ == "__main__":
    unittest.main()
