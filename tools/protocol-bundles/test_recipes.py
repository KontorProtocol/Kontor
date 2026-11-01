import copy
from dataclasses import replace
import json
from pathlib import Path
import shutil
import tempfile
import unittest

from capabilities import DISABLED, settings, verify
from recipes import EXECUTION, EXECUTOR_GRAPHS, GRAPHS, identity, verify_engine_observations, verify_identity, verify_reservations


ROOT = Path(__file__).resolve().parents[2]


class Recipes(unittest.TestCase):
    def copy_manifests(self, root):
        for directory in ("first", "second", "pulley-first", "pulley-second"):
            target = root / "protocol-bundles" / directory
            target.mkdir(parents=True)
            for name in ("Cargo.toml", "Cargo.lock"):
                shutil.copyfile(ROOT / "protocol-bundles" / directory / name, target / name)

    def test_active_manifest_identity_is_checked(self):
        for label, graph in GRAPHS.items():
            for old, new in ((graph.revision, "0" * 40), (graph.version, "51.0.0-kontor.99")):
                with self.subTest(graph=label, field=old), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    self.copy_manifests(root)
                    manifest = root / "protocol-bundles" / graph.directory / "Cargo.toml"
                    manifest.write_text(manifest.read_text().replace(old, new))
                    with self.assertRaisesRegex(RuntimeError, "wrong immutable identity"):
                        verify_reservations(root)

    def test_modified_historical_inputs_are_rejected(self):
        for label in ("first", "second"):
            for name in ("Cargo.toml", "Cargo.lock"):
                with self.subTest(graph=label, file=name), tempfile.TemporaryDirectory() as directory:
                    root = Path(directory)
                    self.copy_manifests(root)
                    path = root / "protocol-bundles" / label / name
                    path.write_text(path.read_text() + "\n# changed historical input\n")
                    with self.assertRaisesRegex(RuntimeError, "historical proof inputs changed"):
                        verify_reservations(root)

    def test_current_inputs_and_capability_parity(self):
        verify_reservations(ROOT)
        verify(ROOT)
        for label in GRAPHS:
            verify_identity(ROOT, {"graph": label, "identity": identity(ROOT, label)})

    def test_executor_and_proof_are_distinct_link_sets(self):
        verify_reservations(ROOT, EXECUTOR_GRAPHS)
        report = {"graph": "first", "identity": identity(ROOT, "first", EXECUTOR_GRAPHS)}
        verify_identity(ROOT, report, EXECUTOR_GRAPHS)
        with self.assertRaisesRegex(RuntimeError, "attestation"):
            verify_identity(ROOT, report)
        with self.assertRaisesRegex(RuntimeError, "reserved Wasmtime"):
            verify_reservations(ROOT, dict(GRAPHS, executor=EXECUTOR_GRAPHS["first"]))

    def test_reserved_historical_and_active_versions(self):
        for version in ("51.0.0-dev", "51.0.0+dev", "51.0.0-kontor.1",
                        "51.0.0-kontor.2", "51.0.0+kontor.2"):
            with self.subTest(version=version):
                graphs = dict(GRAPHS, second=replace(GRAPHS["second"], version=version))
                with self.assertRaisesRegex(RuntimeError, "reserved Wasmtime"):
                    verify_reservations(ROOT, graphs)

    def test_relabelled_or_incomplete_identity_is_rejected(self):
        original = {"graph": "first", "identity": identity(ROOT, "first")}
        for field, value in (("directory", "first"), ("wasmtime_revision", "0" * 40),
                             ("wasmtime_version", "51.0.0-dev"),
                             ("manifest_sha256", "0" * 64), ("lock_sha256", "0" * 64)):
            report = copy.deepcopy(original)
            report["identity"][field] = value
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, "attestation"):
                verify_identity(ROOT, report)
        for field in EXECUTION:
            report = copy.deepcopy(original)
            del report["identity"]["execution"][field]
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, "attestation"):
                verify_identity(ROOT, report)

    def test_actual_observations_are_required_for_each_graph(self):
        values = [{"graph": label, **EXECUTION, "lift_rate": graph.lift_rate}
                  for label, graph in GRAPHS.items()]
        def log(items):
            return "\n".join("KONTOR_VM_ATTESTATION " + json.dumps(item) for item in items)
        self.assertEqual(verify_engine_observations(log(values)), values)
        with self.assertRaisesRegex(RuntimeError, "missing"):
            verify_engine_observations(log(values[:1]))
        for field in EXECUTION:
            changed = copy.deepcopy(values)
            del changed[1][field]
            with self.subTest(field=field), self.assertRaisesRegex(RuntimeError, "differs"):
                verify_engine_observations(log(changed))
        changed = copy.deepcopy(values)
        changed[1]["target"] = "aarch64-unknown-linux-gnu"
        with self.assertRaisesRegex(RuntimeError, "differs"):
            verify_engine_observations(log(changed))

    def test_retained_engine_and_facade_are_both_checked(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            paths = ("core/indexer/src/runtime/mod.rs",
                     "core/indexer/src/protocol/v1/engine.rs",
                     "protocol-bundles/proof/vm.rs")
            for relative in paths:
                target = root / relative
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_bytes((ROOT / relative).read_bytes())
            verify(root)
            retained = root / paths[1]
            original = retained.read_text()
            retained.write_text(original.replace("config.wasm_threads(false)",
                                                 "config.wasm_threads(true)"))
            with self.assertRaisesRegex(RuntimeError, "synchronous baseline"):
                verify(root)
            retained.write_text(original)
            facade = root / paths[0]
            facade.write_text(facade.read_text().replace("engine::new_engine()",
                                                        "other::new_engine()"))
            with self.assertRaisesRegex(RuntimeError, "delegate"):
                verify(root)

    def test_capability_enable_or_omission_is_rejected(self):
        calls = [f"config.{name}(false);" for name in sorted(DISABLED)]
        settings("\n".join(calls))
        for index in range(len(calls)):
            changed = calls.copy()
            changed[index] = changed[index].replace("false", "true")
            with self.assertRaisesRegex(RuntimeError, "synchronous baseline"):
                settings("\n".join(changed))
            with self.assertRaisesRegex(RuntimeError, "synchronous baseline"):
                settings("\n".join(calls[:index] + calls[index + 1:]))


if __name__ == "__main__":
    unittest.main()
