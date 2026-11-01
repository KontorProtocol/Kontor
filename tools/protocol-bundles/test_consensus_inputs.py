import copy
from pathlib import Path
import re
import shutil
import tempfile
import unittest
from unittest.mock import patch

from audit import audit_final, audit_inputs, owner
from build import ROOT, identities
from provenance import consensus_sources, fingerprint, repository_sources
from recipes import CONSENSUS_GRAPHS, MALACHITE_REVISION, MALACHITE_VERSION, identity, verify_identity, verify_reservations
from source_policy import CONTROL, check


class ConsensusInputs(unittest.TestCase):
    def metadata(self):
        packages = [{"id": "root", "name": "kontor-consensus-first", "version": "0.1.0", "source": None}]
        for name in ("arc-malachitebft-app-channel", "arc-malachitebft-signing", "if-watch"):
            packages.append({"id": name, "name": name, "version": "3.2.2" if name == "if-watch" else MALACHITE_VERSION,
                             "source": "git+https://github.com/KontorProtocol/malachite#" + MALACHITE_REVISION})
        for name in CONSENSUS_GRAPHS["first"].native_patches:
            packages.append({"id": name, "name": name, "version": "0.0.0", "source": None,
                             "manifest_path": str(ROOT / "core/vendor" / name / "Cargo.toml")})
        nodes = [{"id": p["id"], "features": [], "deps": []} for p in packages]
        nodes[0]["deps"] = [{"pkg": p["id"]} for p in packages[1:]]
        return {"packages": packages, "resolve": {"root": "root", "nodes": nodes}}

    def test_production_recipes_bind_consensus_without_vm_settings(self):
        verify_reservations(ROOT, CONSENSUS_GRAPHS)
        for label in CONSENSUS_GRAPHS:
            record = identity(ROOT, label, CONSENSUS_GRAPHS)
            self.assertEqual(record["kind"], "consensus")
            self.assertNotIn("wasmtime_version", record)
            self.assertNotIn("execution", record)
            verify_identity(ROOT, {"graph": label, "identity": record}, CONSENSUS_GRAPHS)
        self.assertNotEqual(identity(ROOT, "first", CONSENSUS_GRAPHS), identity(ROOT, "second", CONSENSUS_GRAPHS))

    def test_malachite_manifest_changes_are_rejected(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for name in ("first", "second", "consensus-first", "consensus-second"):
                target = root / "protocol-bundles" / name
                target.mkdir(parents=True)
                for file in ("Cargo.toml", "Cargo.lock"):
                    shutil.copyfile(ROOT / "protocol-bundles" / name / file, target / file)
            manifest = root / "protocol-bundles/consensus-first/Cargo.toml"
            manifest.write_text(manifest.read_text().replace(MALACHITE_REVISION, "0" * 40))
            with self.assertRaisesRegex(RuntimeError, "wrong immutable identity"):
                verify_reservations(root, CONSENSUS_GRAPHS)

    def test_resolved_sources_and_native_patches_are_required(self):
        original = self.metadata()
        self.assertNotIn("wasmtime", {p["name"] for p in identities("first", original, CONSENSUS_GRAPHS)})
        for name in ("arc-malachitebft-app-channel", "arc-malachitebft-signing", "if-watch", "ring", "secp256k1-sys"):
            data = copy.deepcopy(original)
            package = next(p for p in data["packages"] if p["name"] == name)
            package.update(source="git+substituted#" + "0" * 40, manifest_path="/unpatched/Cargo.toml")
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "unqualified|native patch"):
                identities("first", data, CONSENSUS_GRAPHS)

    def test_execution_and_storage_dependencies_are_rejected(self):
        for name in ("wasmtime", "libsql"):
            data = self.metadata()
            data["packages"].append({"id": name, "name": name, "source": None, "version": "0"})
            data["resolve"]["nodes"].append({"id": name, "features": [], "deps": []})
            data["resolve"]["nodes"][0]["deps"].append({"pkg": name})
            with self.subTest(name=name), self.assertRaisesRegex(RuntimeError, "execution or storage"):
                identities("first", data, CONSENSUS_GRAPHS)

    def test_shared_crate_protobuf_and_imported_sources_are_bound(self):
        inventory = consensus_sources(ROOT)
        for source in (ROOT / "protocol-bundles/consensus").rglob("*.rs"):
            self.assertIn(str(source.relative_to(ROOT)), inventory)
            for relative in re.findall(r'#\[path\s*=\s*"([^"]+)"\]', source.read_text()):
                self.assertIn(str((source.parent / relative).resolve().relative_to(ROOT)), inventory)
        self.assertIn("core/indexer/proto/consensus/v1/consensus.proto", inventory)
        self.assertNotIn("core/indexer/src/protocol/v1/engine.rs", repository_sources(ROOT, "consensus"))

    def test_external_source_edits_invalidate_inventory(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            for relative in consensus_sources(ROOT):
                destination = root / relative
                destination.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ROOT / relative, destination)
            before = fingerprint(consensus_sources(root))
            for relative in ("protocol-bundles/consensus/owner.rs", "core/indexer/src/consensus/value.rs",
                             "core/indexer/src/protocol/coordinator/certified_input.rs",
                             "core/indexer/proto/consensus/v1/sync.proto"):
                path = root / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\n")
                self.assertNotEqual(before, fingerprint(consensus_sources(root)), relative)
                path.write_bytes(original)
            owner_source = root / "protocol-bundles/consensus/owner.rs"
            owner_source.write_text("std::process::exit(1);")
            with self.assertRaisesRegex(RuntimeError, "process-ownership review"):
                check(root, {"packages": []}, kind="consensus")

    def test_actual_maintained_consensus_sources_pass_process_tripwire(self):
        result = check(ROOT, {"packages": []}, kind="consensus")
        paths = {item["path"] for item in result["maintained_sources"]}
        self.assertIn(str(ROOT / "protocol-bundles/consensus/owner.rs"), paths)
        self.assertIn(str(ROOT / "core/indexer/src/consensus/codec.rs"), paths)

    def test_process_tripwire_distinguishes_enum_variants_and_read_only_pid(self):
        for source in ("Command::Block { height }", "Command :: Batch { anchor }", "std::process:: id()"):
            self.assertIsNone(CONTROL.search(source), source)
        for source in ('Command::new("child")', "std::process::exit(1)", "tokio::process::Command",
                       "tokio::signal::ctrl_c()", "waitpid(pid)"):
            self.assertIsNotNone(CONTROL.search(source), source)


class ConsensusOwnership(unittest.TestCase):
    def graphs(self):
        return [{"graph": label, "namespace": "kontor_" + label, "identity": {"kind": "consensus"},
                 "packages": [], "artifacts": [], "native_artifacts": []} for label in ("first", "second")]

    def test_vm_absence_requires_explicit_consensus_role(self):
        with tempfile.TemporaryDirectory() as directory:
            graphs = self.graphs()
            sets, versions = audit_inputs(graphs, Path(directory))
            self.assertEqual(versions, [None, None])
            self.assertEqual(sets, [set(), set()])
            del graphs[0]["identity"]
            with self.assertRaisesRegex(RuntimeError, "role does not match"):
                audit_inputs(graphs, Path(directory))

    def test_consensus_cannot_claim_vm_native_helpers(self):
        with self.assertRaisesRegex(RuntimeError, "unowned native"):
            owner("wasmtime_libunwind_51_0_0", self.graphs()[0], None)
        with self.assertRaisesRegex(RuntimeError, "process allocator"):
            owner("__rust_alloc", self.graphs()[0], None)

    def test_consensus_still_rejects_native_collisions_and_shared_namespaces(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            graphs = self.graphs()
            for graph in graphs:
                path = root / graph["graph"]
                path.write_bytes(b"fixture")
                graph["artifacts"] = [{"path": str(path)}]
            with patch("audit.definitions", return_value={"_RNvCs123_5probe5STATE": {"kind": "T", "address": "0"}}):
                with self.assertRaisesRegex(RuntimeError, "would coalesce"):
                    audit_inputs(graphs, root)
            graphs[1]["namespace"] = graphs[0]["namespace"]
            with self.assertRaisesRegex(RuntimeError, "unique names and namespaces"):
                audit_inputs(graphs, root)

    def test_mixed_final_ownership_keeps_vm_helper_with_its_actual_graph(self):
        graphs = self.graphs()
        graphs[1]["identity"] = {}
        helper = "wasmtime_libunwind_51_0_0"
        symbols = {helper: {"address": "1000", "kind": "T"}}
        with tempfile.TemporaryDirectory() as directory:
            with patch("audit.definitions", return_value=symbols), patch(
                    "audit.private_local_inputs", return_value=([set(), set()], [])):
                result = audit_final(Path("node"), graphs, [set(), {helper}], [None, "51.0.0"],
                                     Path(directory), {}, kind="executor")
        self.assertEqual(result["wasmtime"][helper]["owner"], "second")


if __name__ == "__main__":
    unittest.main()
