import importlib.util
from copy import deepcopy
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
        "child_markers": (list(range(depth - 1, -1, -1)) + [0] * (64 - depth) if outcome == "ok" else [0] * 64) if kind == "paid_reenter" else [],
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


def add_sweep_fields(samples, kind, role, boundaries):
    for index, sample in enumerate(samples):
        sample.update(
            role=role, sample_index=index, sample_id=f"{role}:{kind}:{index:04}",
            cache_mode="warm_compiled_cache", fixture_contracts=65 if kind == "paid_reenter" else 1,
            call_hook_installed=False,
            log=f"{kind}-{role}-{index:04}.log",
            reset={
                "pre": {"live_invocations": 0, "stack_empty": True, "savepoint_intact": True,
                        "resource_count": 0, "baseline_resource_count": 0,
                        "failure_rolled_back": None if sample["outcome"] == "ok" else True},
                "post": {"persistent_digest_sha256": "1" * 64, "baseline_digest_sha256": "1" * 64,
                         "digest_matches": True, "live_invocations": 0, "stack_empty": True,
                         "savepoint_restored": True, "resource_count": 0, "balances_restored": True,
                         "floor_restored": True, "supply_restored": True},
            },
        )
    return {
        "role": role, "kind": kind, "cache_mode": "warm_compiled_cache",
        "fixture_contracts": 65 if kind == "paid_reenter" else 1,
        "boundaries": boundaries,
        "ordered_sample_indices": list(range(len(samples))),
        "ordered_sample_ids": [sample["sample_id"] for sample in samples],
        "baseline_digest_sha256": "1" * 64,
    }


def transcript(samples, summary):
    return "".join("KONTOR_STACK_REPORT:" + json.dumps({key: value for key, value in sample.items() if key != "log"}) + "\n" for sample in samples) + "KONTOR_STACK_SWEEP_SUMMARY:" + json.dumps(summary) + "\ntest result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 0 filtered out; finished in 1s\n"


def chain_report(mode, stores, target_os, target_arch):
    trials = []
    for repeat_index, outcome in enumerate(["invocation_limit"] * 3 if stores == 65 else ["ok", "trap", "ok"]):
        changed_state = mode != "view" and outcome == "ok"
        trials.append({
            "outcome": outcome, "value": "42" if outcome == "ok" else None,
            "fuel": {"user": 100 if mode == "paid" else 0, "system": 0 if mode == "paid" else 100, "deposit": 0},
            "receipt": None if mode == "view" else {"contract_id": stores + 5, "status": "Ok" if outcome == "ok" else "Other", "gas": 10, "value": "42" if outcome == "ok" else None},
            "repeat_index": repeat_index,
            "state_before_sha256": "1" * 64, "state_after_sha256": "1" * 64,
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
        "mode": mode, "stores": stores, "trials": trials, "call_hook_installed": False,
        "component_sha256": {"error_test": "e" * 64, "proxy": "f" * 64},
        "engine_target": "pulley64-unknown-unknown-elf", "max_wasm_stack": 524288,
        "async_stack_size": 2097152, "target_os": target_os, "target_arch": target_arch,
    }


def write_evidence(directory, report):
    logs = {}
    for graph, name in report["feature_logs"].items():
        path = directory / name
        path.write_text(",".join(report["wasmtime_features"][graph]) + "\n")
        logs[name] = hashlib.sha256(path.read_bytes()).hexdigest()
    cargo = directory / report["cargo_log"]
    cargo.write_text(json.dumps({
        "reason": "compiler-artifact", "target": {"name": "indexer", "kind": ["lib"]},
        "profile": {"test": True}, "executable": report["binary"],
    }) + "\n" + json.dumps({
        "reason": "compiler-artifact", "target": {"name": "wasmtime", "kind": ["lib"]},
        "package_id": f"git+https://github.com/wilfreddenton/wasmtime?rev={compare.FORK_REVISION}#wasmtime@51.0.0-kontor.2",
        "features": report["wasmtime_features"]["qualification"],
    }) + "\n" + json.dumps({"reason": "build-finished", "success": True}) + "\n")
    logs[cargo.name] = hashlib.sha256(cargo.read_bytes()).hexdigest()
    for case in report["cases"]:
        for observation in case["observations"] + case["control_observations"]:
            path = directory / observation["log"]
            raw = {field: value for field, value in observation.items() if field != "log"}
            path.write_text("KONTOR_STACK_REPORT:" + json.dumps(raw) + "\n")
            logs[path.name] = hashlib.sha256(path.read_bytes()).hexdigest()
        for role, samples in (("worker", case["observations"]), ("control", case["control_observations"])):
            path = directory / case[f"{role}_log"]
            path.write_text(transcript(samples, case[f"{role}_summary"]))
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
                    samples = [(depth, "invocation_limit" if depth == 64 else "ok") for depth in (62, 63, 64, 64, 63, 62, 62, 63, 64)]
                    boundary = "first_failure"
                    last_success, first_failure, first_failure_outcome = 63, 64, "invocation_limit"
                else:
                    samples = [(depth, "stack_overflow" if depth == 4 else "ok") for depth in (0, 3, 4, 3, 4, 4, 3, 3, 4)]
                    boundary = "first_failure"
                    last_success, first_failure, first_failure_outcome = 3, 4, "stack_overflow"
                observations = []
                for index, (depth, outcome) in enumerate(samples):
                    log = f"{kind}-{depth}-{index}.log"
                    (directory / log).write_text(outcome)
                    observations.append(observation(kind, depth, outcome, target_os, target_arch, log))
                boundaries = {"bounded_depth": 0} if kind == "paid_huge" else {
                    "last_success": last_success, "first_failure": first_failure,
                    "first_failure_outcome": first_failure_outcome,
                }
                control_depths = [0] if kind == "paid_huge" else [last_success, first_failure]
                controls = [deepcopy(next(sample for sample in observations if sample["depth"] == depth)) for depth in control_depths]
                worker_summary = add_sweep_fields(observations, kind, "worker", boundaries)
                control_summary = add_sweep_fields(controls, kind, "control", boundaries)
                cases.append({
                    "kind": kind,
                    "boundary": boundary,
                    "last_success": last_success,
                    "first_failure": first_failure,
                    "first_failure_outcome": first_failure_outcome,
                    "observations": observations,
                    "control_observations": controls,
                    "worker_summary": worker_summary, "control_summary": control_summary,
                    "worker_log": f"{kind}-worker.log", "control_log": f"{kind}-control.log",
                })
            report = {
                "schema_version": 5,
                "cell": cell,
                "source_sha": "a" * 40,
                "lockfile_sha256": "b" * 64,
                "wasmtime_revision": compare.FORK_REVISION,
                "wasmtime_features": {
                    "production": sorted(compare.PRODUCTION_FEATURES),
                    "qualification": sorted(compare.QUALIFICATION_FEATURES),
                },
                "feature_logs": compare.FEATURE_LOGS,
                "cargo_log": "cargo.json",
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

    def test_chain_receipt_fields_and_repeat_index_rejected(self):
        for field, value in (("contract_id", True), ("value", "wrong")):
            with self.subTest(field=field):
                chains = [chain_report(mode, stores, "linux", "x86_64") for mode, stores in sorted(compare.CHAIN_KEYS)]
                chains[0]["trials"][0]["receipt"][field] = value
                with self.assertRaisesRegex(ValueError, "chain receipt"):
                    compare.validate_chains(chains, "linux", "x86_64")
        self.mutate_all_with_matching_logs(lambda report: report["chains"][0]["trials"][1].__setitem__("repeat_index", 0))
        self.rejected()

    def test_chain_state_must_restore_and_match_across_cells(self):
        self.mutate_all_with_matching_logs(lambda report: report["chains"][0]["trials"][0].__setitem__("state_after_sha256", "2" * 64))
        self.rejected()
        self.setUp()
        path, report = self.report()
        trial = report["chains"][0]["trials"][0]
        trial["state_before_sha256"] = trial["state_after_sha256"] = "2" * 64
        write_evidence(path.parent, report)
        with self.assertRaisesRegex(ValueError, "cross-cell observations differ"):
            compare.compare(self.root, "success")

    def test_cross_platform_sweep_fuel_difference_rejected(self):
        path, report = self.report()
        case = report["cases"][0]
        for sample in case["observations"] + case["control_observations"]:
            sample["fuel"]["user"] += 1
        write_evidence(path.parent, report)
        with self.assertRaisesRegex(ValueError, "cross-cell observations differ"):
            compare.compare(self.root, "success")

    def test_extra_qualification_feature_and_chain_hook_rejected(self):
        self.mutate_all_with_matching_logs(lambda report: report["wasmtime_features"]["qualification"].append("coredump"))
        self.rejected()
        self.setUp()
        self.mutate_all_with_matching_logs(lambda report: report["chains"][0].__setitem__("call_hook_installed", True))
        self.rejected()

    def test_matching_stale_component_hashes_rejected(self):
        with self.assertRaisesRegex(ValueError, "stack probe differs"):
            compare.compare(self.root, "success", component_hashes={"stack_probe": "0" * 64})
        with self.assertRaisesRegex(ValueError, "chain probes differ"):
            compare.compare(self.root, "success", component_hashes={
                "stack_probe": "d" * 64, "error_test": "0" * 64, "proxy": "f" * 64,
            })

    def test_actual_compiled_features_must_match_resolution(self):
        path, report = self.report()
        cargo = path.parent / report["cargo_log"]
        lines = [json.loads(line) for line in cargo.read_text().splitlines()]
        lines[1]["features"].append("profiling")
        cargo.write_text("".join(json.dumps(line) + "\n" for line in lines))
        report["log_sha256"][cargo.name] = hashlib.sha256(cargo.read_bytes()).hexdigest()
        path.write_text(json.dumps(report))
        self.rejected()

    def test_forbidden_missing_or_unexpected_wasmtime_features_rejected(self):
        self.mutate_all_with_matching_logs(
            lambda report: report["wasmtime_features"]["production"].append("cache")
        )
        self.rejected()
        self.setUp()
        self.mutate_all_with_matching_logs(
            lambda report: report["wasmtime_features"]["production"].remove("pulley")
        )
        self.rejected()
        self.setUp()
        self.mutate_all_with_matching_logs(
            lambda report: report["wasmtime_features"]["qualification"].remove("call-hook")
        )
        self.rejected()

    def test_missing_duplicate_or_wrong_compiled_wasmtime_rejected(self):
        for mutation in ("missing", "duplicate", "identity"):
            with self.subTest(mutation=mutation):
                self.setUp()
                path, report = self.report()
                cargo = path.parent / report["cargo_log"]
                entries = [json.loads(line) for line in cargo.read_text().splitlines()]
                if mutation == "missing":
                    entries.pop(1)
                elif mutation == "duplicate":
                    entries.insert(2, entries[1].copy())
                else:
                    entries[1]["package_id"] = entries[1]["package_id"].replace("kontor.2", "kontor.3")
                cargo.write_text("".join(json.dumps(entry) + "\n" for entry in entries))
                report["log_sha256"][cargo.name] = hashlib.sha256(cargo.read_bytes()).hexdigest()
                path.write_text(json.dumps(report))
                self.rejected()

    def test_incomplete_or_failed_cargo_build_log_rejected(self):
        for mutation in ("missing", "failed", "duplicate"):
            with self.subTest(mutation=mutation):
                self.setUp()
                path, report = self.report()
                cargo = path.parent / report["cargo_log"]
                entries = [json.loads(line) for line in cargo.read_text().splitlines()]
                if mutation == "missing":
                    entries.pop()
                elif mutation == "failed":
                    entries[-1]["success"] = False
                else:
                    entries.append(entries[-1].copy())
                cargo.write_text("".join(json.dumps(entry) + "\n" for entry in entries))
                report["log_sha256"][cargo.name] = hashlib.sha256(cargo.read_bytes()).hexdigest()
                path.write_text(json.dumps(report))
                self.rejected()

    def test_missing_or_mismatched_build_provenance_rejected(self):
        path, report = self.report()
        (path.parent / "cargo.json").unlink()
        self.rejected()
        self.setUp()
        path, report = self.report()
        cargo = path.parent / "cargo.json"
        entries = [json.loads(line) for line in cargo.read_text().splitlines()]
        entries[0]["executable"] = "core/target/debug/deps/indexer-other"
        cargo.write_text("".join(json.dumps(entry) + "\n" for entry in entries))
        report["log_sha256"]["cargo.json"] = hashlib.sha256(cargo.read_bytes()).hexdigest()
        path.write_text(json.dumps(report))
        self.rejected()
        self.setUp()
        path, report = self.report()
        feature_log = path.parent / compare.FEATURE_LOGS["production"]
        feature_log.write_text("cache\n")
        report["log_sha256"][feature_log.name] = hashlib.sha256(feature_log.read_bytes()).hexdigest()
        path.write_text(json.dumps(report))
        self.rejected()


if __name__ == "__main__":
    unittest.main()
