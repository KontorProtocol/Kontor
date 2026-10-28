import importlib.util
import hashlib
import json
import tempfile
import unittest
from pathlib import Path


SPEC = importlib.util.spec_from_file_location("native_stack_compare", Path(__file__).with_name("compare.py"))
compare = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(compare)


def observation(kind, depth, outcome, target_os, target_arch, log):
    return {
        "kind": kind,
        "depth": depth,
        "outcome": outcome,
        "value": str(32640 if kind == "paid_huge" else 496 * depth if kind.endswith("_wide") else depth) if outcome == "ok" else None,
        "receipt": None if kind.startswith(("view_", "system_")) else {
            "status": {"ok": "Ok", "stack_overflow": "Trap", "invocation_limit": "Other"}[outcome],
            "gas": 10,
        },
        "last_depth": (1 if kind == "paid_huge" else depth) if outcome == "ok" and not kind.startswith(("view_", "system_")) else 0,
        "child_markers": (list(range(depth - 1, -1, -1)) if outcome == "ok" else [0] * depth) if kind == "paid_reenter" else [],
        "rolled_back": outcome != "ok",
        "fuel": {"user": 100, "system": 0, "deposit": 0},
        "gas_limit": 100000,
        "paid_fuel_limit": 100000000,
        "view_gas_limit": 100000,
        "view_fuel_limit": 100000000,
        "system_fuel_ceiling": 9223372036854775807,
        "gas_to_fuel_multiplier": 1000,
        "max_wasm_stack": 524288,
        "async_stack_size": 2097152,
        "engine_target": "pulley64-unknown-unknown-elf",
        "component_sha256": "d" * 64,
        "target_os": target_os,
        "target_arch": target_arch,
        "log": log,
    }


def chain_report(mode, stores, target_os, target_arch):
    trials = []
    for outcome in (["invocation_limit"] * 3 if stores == 65 else ["ok", "trap", "ok"]):
        changed_state = mode != "view" and outcome == "ok"
        trials.append({
            "outcome": outcome, "value": "42" if outcome == "ok" else None,
            "fuel": {"user": 100 if mode == "paid" else 0, "system": 0 if mode == "paid" else 100, "deposit": 0},
            "receipt": None if mode == "view" else {"status": "Ok" if outcome == "ok" else "Other", "gas": 10},
            "receipt_count": 0 if mode == "view" else stores if outcome == "ok" else 1,
            "storage_state": "[2, 0, 0, 0]" if changed_state else "[0, 0, 0, 0]",
            "rolled_back": True, "resource_count": 0, "baseline_resource_count": 0,
            "stack_empty": True, "savepoint_restored": True, "rollback_clean": True,
            "host_io_suspended": stores != 65, "leaf_callback_seen": stores != 65,
            "balances": {
                "before": "100", "after": "98.75" if mode == "paid" else "100", "restored": "100",
                "burned_before": "5", "burned_after": "6.25" if mode == "paid" else "5",
                "supply_before": "1000", "supply_after": "998.75" if mode == "paid" else "1000",
                "floor_before": "10", "floor_after": "9" if mode == "core" and outcome == "ok" else "10",
                "floor_restored": "10",
            },
        })
    return {
        "mode": mode, "stores": stores, "trials": trials,
        "component_sha256": {"error_test": "e" * 64, "proxy": "f" * 64},
        "engine_target": "pulley64-unknown-unknown-elf", "max_wasm_stack": 524288,
        "async_stack_size": 2097152, "target_os": target_os, "target_arch": target_arch,
    }


def write_evidence(directory, report):
    logs = {}
    for case in report["cases"]:
        for observation in case["observations"]:
            path = directory / observation["log"]
            raw = {field: value for field, value in observation.items() if field != "log"}
            path.write_text("KONTOR_STACK_REPORT:" + json.dumps(raw) + "\n")
            logs[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    path = directory / report["chain_log"]
    path.write_text("".join("CHAIN_PROBE_REPORT:" + json.dumps(chain) + "\n" for chain in report["chains"]))
    logs[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
    report["log_sha256"] = logs
    (directory / "qualification.json").write_text(json.dumps(report))


class CompareTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for artifact, (cell, target_os, target_arch) in compare.CELLS.items():
            directory = self.root / artifact
            directory.mkdir()
            cases = []
            for kind in sorted(compare.CASES):
                if kind == "paid_huge":
                    samples = [(0, "ok")]
                    boundary = "bounded"
                    last_success = first_failure = first_failure_outcome = None
                elif kind == "paid_reenter":
                    samples = [(62, "ok")] * 3 + [(63, "ok")] * 3 + [(64, "invocation_limit")] * 3
                    boundary = "first_failure"
                    last_success, first_failure, first_failure_outcome = 63, 64, "invocation_limit"
                else:
                    samples = [(3, "ok")] * 3 + [(4, "stack_overflow")] * 3
                    boundary = "first_failure"
                    last_success, first_failure, first_failure_outcome = 3, 4, "stack_overflow"
                observations = []
                for index, (depth, outcome) in enumerate(samples):
                    log = f"{kind}-{depth}-{index}.log"
                    (directory / log).write_text(outcome)
                    observations.append(observation(kind, depth, outcome, target_os, target_arch, log))
                cases.append({
                    "kind": kind,
                    "boundary": boundary,
                    "last_success": last_success,
                    "first_failure": first_failure,
                    "first_failure_outcome": first_failure_outcome,
                    "observations": observations,
                })
            report = {
                "schema_version": 3,
                "cell": cell,
                "source_sha": "a" * 40,
                "lockfile_sha256": "b" * 64,
                "wasmtime_revision": compare.FORK_REVISION,
                "binary": f"core/target/{'release' if cell.endswith('/release') else 'debug'}/deps/indexer-test",
                "binary_sha256": "c" * 64,
                "rustc_version_verbose": "rustc 1.99.1\n",
                "host": "test host",
                "cases": cases,
                "chains": [chain_report(mode, stores, target_os, target_arch) for mode, stores in sorted(compare.CHAIN_KEYS)],
                "chain_log": "chain-matrix.log",
            }
            write_evidence(directory, report)

    def report(self, artifact="native-stack-ubuntu-24.04-dev"):
        path = self.root / artifact / "qualification.json"
        return path, json.loads(path.read_text())

    def mutate(self, change):
        path, report = self.report()
        change(report)
        path.write_text(json.dumps(report))

    def rejected(self):
        with self.assertRaises(ValueError):
            compare.compare(self.root, "success")

    def test_complete_matrix_passes(self):
        result = compare.compare(self.root, "success")
        self.assertEqual(len(result["cells"]), 6)

    def test_missing_or_duplicate_cell_rejected(self):
        (self.root / "native-stack-ubuntu-24.04-dev" / "qualification.json").unlink()
        self.rejected()
        self.setUp()
        self.mutate(lambda report: report.__setitem__("cell", "Linux-ARM64/dev"))
        self.rejected()

    def test_missing_case_or_field_rejected(self):
        self.mutate(lambda report: report["cases"].pop())
        self.rejected()
        self.setUp()
        self.mutate(lambda report: report["cases"].__setitem__(1, report["cases"][0]))
        self.rejected()
        self.setUp()
        self.mutate(lambda report: report["cases"][0]["observations"][0].pop("fuel"))
        self.rejected()

    def test_bad_target_or_stack_settings_rejected(self):
        self.mutate(lambda report: report["cases"][0]["observations"][0].__setitem__("target_arch", "aarch64"))
        self.rejected()
        self.setUp()
        self.mutate(lambda report: report["cases"][0]["observations"][0].__setitem__("max_wasm_stack", 1))
        self.rejected()

    def test_shifted_boundary_or_process_signal_rejected(self):
        self.mutate(lambda report: report["cases"][0].__setitem__("first_failure", 5))
        self.rejected()
        self.setUp()
        self.mutate(lambda report: report["cases"][0]["observations"][0].__setitem__("outcome", "process_signal"))
        self.rejected()

    def test_stale_source_and_failed_upstream_rejected(self):
        self.mutate(lambda report: report.__setitem__("source_sha", "e" * 40))
        self.rejected()
        self.setUp()
        with self.assertRaises(ValueError):
            compare.compare(self.root, "success", "e" * 40, "b" * 64)
        with self.assertRaises(ValueError):
            compare.compare(self.root, "success", "a" * 40, "e" * 64)
        with self.assertRaises(ValueError):
            compare.compare(self.root, "failure")

    def mutate_all_with_matching_logs(self, change):
        for path in self.root.glob("*/qualification.json"):
            report = json.loads(path.read_text())
            change(report)
            write_evidence(path.parent, report)

    def test_63_store_failure_rejected_even_when_all_cells_agree(self):
        def change(report):
            case = next(case for case in report["cases"] if case["kind"] == "paid_reenter")
            for value in case["observations"]:
                if value["depth"] == 62:
                    value.update(outcome="stack_overflow", value=None, last_depth=0,
                                 child_markers=[0] * 62, rolled_back=True, receipt={"status": "Trap", "gas": 10})
        self.mutate_all_with_matching_logs(change)
        self.rejected()

    def test_wrong_success_value_and_state_rejected_with_matching_logs(self):
        def change(report):
            value = next(case for case in report["cases"] if case["kind"] == "paid_huge")["observations"][0]
            value.update(value="0", last_depth=0)
        self.mutate_all_with_matching_logs(change)
        self.rejected()

    def test_duplicate_sample_logs_rejected(self):
        def change(report):
            case = next(case for case in report["cases"] if case["kind"] == "paid_reenter")
            samples = {value["depth"]: value for value in case["observations"]}
            case["observations"] = [samples[depth] for depth in (62, 63, 64) for _ in range(3)]
        self.mutate_all_with_matching_logs(change)
        self.rejected()

    def test_truncated_or_mismatched_raw_log_rejected(self):
        path, report = self.report()
        log = path.parent / report["cases"][0]["observations"][0]["log"]
        log.write_text("truncated\n")
        self.rejected()
        self.setUp()
        path, report = self.report()
        report["cases"][0]["observations"][0]["fuel"]["user"] += 1
        path.write_text(json.dumps(report))
        self.rejected()

    def test_raw_log_digest_mismatch_rejected(self):
        path, report = self.report()
        log = path.parent / report["cases"][0]["observations"][0]["log"]
        with log.open("a") as file:
            file.write("trailing diagnostic changed\n")
        self.rejected()

    def test_missing_duplicate_and_wrong_chain_outcome_rejected(self):
        self.mutate_all_with_matching_logs(lambda report: report["chains"].pop())
        self.rejected()
        self.setUp()
        self.mutate_all_with_matching_logs(lambda report: report["chains"].__setitem__(1, report["chains"][0]))
        self.rejected()
        self.setUp()
        self.mutate_all_with_matching_logs(lambda report: report["chains"][0]["trials"][0].__setitem__("outcome", "invocation_limit"))
        self.rejected()

    def test_chain_accounting_and_cleanup_rejected(self):
        self.mutate_all_with_matching_logs(lambda report: report["chains"][0]["trials"][0]["balances"].__setitem__("burned_after", "7"))
        self.rejected()
        self.setUp()
        self.mutate_all_with_matching_logs(lambda report: report["chains"][0]["trials"][0].__setitem__("rollback_clean", False))
        self.rejected()

    def test_cross_platform_chain_fuel_difference_rejected(self):
        path, report = self.report()
        report["chains"][0]["trials"][0]["fuel"]["system"] += 1
        write_evidence(path.parent, report)
        self.rejected()

    def test_matching_stale_component_hashes_rejected(self):
        with self.assertRaisesRegex(ValueError, "stack probe differs"):
            compare.compare(self.root, "success", component_hashes={"stack_probe": "0" * 64})
        with self.assertRaisesRegex(ValueError, "chain probes differ"):
            compare.compare(self.root, "success", component_hashes={
                "stack_probe": "d" * 64, "error_test": "0" * 64, "proxy": "f" * 64,
            })


if __name__ == "__main__":
    unittest.main()
