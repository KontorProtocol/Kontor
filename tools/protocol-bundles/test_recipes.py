import copy
from dataclasses import replace
import json
from pathlib import Path
import unittest

from capabilities import DISABLED, settings, verify
from recipes import EXECUTION, GRAPHS, identity, verify_engine_observations, verify_identity, verify_reservations


ROOT = Path(__file__).resolve().parents[2]


class Recipes(unittest.TestCase):
    def test_current_inputs_and_capability_parity(self):
        verify_reservations(ROOT)
        verify(ROOT)
        for label in GRAPHS:
            verify_identity(ROOT, {"graph": label, "identity": identity(ROOT, label)})

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
