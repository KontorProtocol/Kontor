import json
import tempfile
import unittest
from pathlib import Path

import resource_evidence
import resource_manifest


def raw_log(directory, name, text):
    path = directory / name
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text)
    return {"path": name, "sha256": resource_evidence.sha256(path)}


def thread(category, name, size, requested, pid):
    index = {"worker-1": 1, "worker-2": 2, "blocking": 3, "caller": 4}[name]
    base = index * 4_194_304
    return {
        "thread_category": category, "thread_id": name, "requested_bytes": requested,
        "process_id": pid, "os_thread_id": pid * 10 + index,
        "identity_api": "linux_gettid", "page_size_bytes": 4096,
        "mapped_bytes": size, "guard_bytes": 4096, "usable_bytes": size - 4096,
        "guard_start": base, "guard_end": base + 4096,
        "guard_verification": "linux_maps_prot_none",
        "mapped_start": base, "mapped_end": base + size,
        "usable_start": base + 4096, "usable_end": base + size,
        "measurement_api": "synthetic pthread observation",
        "guard_treatment": "guard excluded from usable interval",
        "guard_verified": True,
    }


def guard_control(directory, manifest, binary_path, binary_sha256, source_sha):
    parent_pid = 103
    lines = ["running 1 test"]
    for mode, pid, tid in (("reduced", 104, 204), ("production", 105, 205)):
        target = {
            "mode": mode, "process_id": pid, "os_thread_id": tid,
            "page_size_bytes": 4096, "guard_start": pid * 4_194_304,
            "guard_end": pid * 4_194_304 + 4096,
            "guard_verification": "guard protected below pthread stack range",
            "address": pid * 4_194_304 + 2048,
        }
        child = {
            "mode": mode, "signal": 6, "target": target,
            "child_binary": binary_path,
            "child_stdout": "running 1 test\nKONTOR_RESOURCE_GUARD_TARGET=" +
                            json.dumps(target) + "\n",
            "child_stderr": f"thread 'tokio-rt-worker' ({tid}) has overflowed its stack\n"
                            "fatal runtime error: stack overflow, aborting\n",
        }
        lines.append("KONTOR_RESOURCE_GUARD_CONTROL=" + json.dumps(child))
    lines.append("KONTOR_RESOURCE_GUARD_TERMINAL=" + json.dumps({
        "pid": parent_pid, "binary_path": binary_path,
        "binary_sha256": binary_sha256, "embedded_source_sha": source_sha,
        "modes": ["reduced", "production"], "complete": True,
    }))
    lines.append("test runtime::call::tests::native_stack_resource::linux_worker_guard_fault_control ... ok")
    lines.append("test result: ok. 1 passed; 0 failed; 0 ignored; 0 measured; 690 filtered out; finished in 0.14s")
    return {
        "process": {"pid": parent_pid,
                    "command": [binary_path, "--exact",
                                manifest["guard_control_runner"]["test_name"],
                                "--ignored", "--nocapture"],
                    "started_unix_ns": 103_000, "ended_unix_ns": 103_001,
                    "exit_code": 0, "signal": None, "timed_out": False,
                    "complete": True, "test_harness_passed": True},
        "raw_log": raw_log(directory, "guard-control.txt", "\n".join(lines) + "\n"),
    }


def guard_report(directory):
    manifest = resource_manifest.build_manifest()
    binary_path = str(directory / "indexer-synthetic")
    report = {
        "host": {"os": "linux"},
        "binary_path": binary_path,
        "binary_sha256": "0" * 64,
        "source_sha": "1" * 40,
        "configurations": {
            mode: {"engine": {"page_size_bytes": 4096},
                   "process_log": {"path": f"{mode}.log"}}
            for mode in ("production", "reduced")
        },
    }
    report["guard_control"] = guard_control(
        directory, manifest, binary_path, report["binary_sha256"], report["source_sha"])
    return manifest, report


class ResourceGuardControls(unittest.TestCase):
    def test_raw_evidence_rejects_substitution_and_escaping_paths(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary) / "archive"
            directory.mkdir()
            entry = raw_log(directory, "raw.json", '{"nested":{"field":1}}')
            resource_evidence.file_evidence(directory, entry)
            self.assertEqual(resource_evidence.load_json_strict(directory / entry["path"]),
                             {"nested": {"field": 1}})
            for text in ('{"nested":{"field":1,"field":2}}', '{"field":NaN}'):
                (directory / entry["path"]).write_text(text)
                with self.assertRaises(ValueError):
                    resource_evidence.load_json_strict(directory / entry["path"])
            with self.assertRaisesRegex(ValueError, "hash mismatch"):
                resource_evidence.file_evidence(directory, entry)
            outside = Path(temporary) / "outside.json"
            outside.write_text("{}")
            (directory / "link.json").symlink_to(outside)
            for path in (str(outside), "../outside.json", "link.json"):
                with self.subTest(path=path), self.assertRaises(ValueError):
                    resource_evidence.file_evidence(directory, {
                        "path": path, "sha256": resource_evidence.sha256(outside)})

    def test_macos_worker_capacity_requires_guard_below_mapped_stack(self):
        pid = 401
        records = [
            thread("tokio_worker", "worker-1", 1_019_904, 1_015_808, pid),
            thread("tokio_worker", "worker-2", 1_019_904, 1_015_808, pid),
            thread("blocking_pool", "blocking", 8_388_608, None, pid),
            thread("block_on_caller", "caller", 8_388_608, None, pid),
        ]
        for record in records:
            record["identity_api"] = "macos_pthread_threadid_np"
            record["guard_verification"] = "macos_mach_vm_region_prot_none"
            record["mapped_start"] = record["usable_start"]
            record["mapped_bytes"] = record["usable_bytes"]
            record["guard_treatment"] = "guard protected below pthread stack range"
        runtime = {
            "flavor": "multi_thread", "worker_count": 2,
            "worker_requested_bytes": 1_015_808,
            "thread_observations": records,
            "blocking_pool_observed": True, "block_on_caller_observed": True,
        }
        resource_evidence.thread_capacities(runtime, "reduced", 4096, "macos", pid)
        records[0]["guard_end"] += 4096
        with self.assertRaisesRegex(ValueError, "thread guard interval"):
            resource_evidence.thread_capacities(runtime, "reduced", 4096, "macos", pid)

    def test_macos_pthread_offset_is_counted_in_worker_capacity(self):
        def measured(mode, pid):
            requested = 1_015_808 if mode == "reduced" else None
            worker_bytes = (requested or 2_097_152) + 12_288
            records = [
                thread("tokio_worker", "worker-1", worker_bytes + 16_384, requested, pid),
                thread("tokio_worker", "worker-2", worker_bytes + 16_384, requested, pid),
                thread("blocking_pool", "blocking", 2_125_824, None, pid),
                thread("block_on_caller", "caller", 2_125_824, None, pid),
            ]
            for record in records:
                low = record["mapped_start"] + 16_384
                high = record["mapped_end"]
                record.update({
                    "identity_api": "macos_pthread_threadid_np",
                    "page_size_bytes": 16_384,
                    "guard_bytes": 16_384,
                    "guard_end": low,
                    "guard_verification": "macos_mach_vm_region_prot_none",
                    "mapped_start": low,
                    "mapped_bytes": high - low,
                    "usable_start": low,
                    "usable_end": high,
                    "usable_bytes": high - low,
                    "guard_treatment": "guard protected below pthread stack range",
                })
            runtime = {
                "flavor": "multi_thread", "worker_count": 2,
                "worker_requested_bytes": requested,
                "thread_observations": records,
                "blocking_pool_observed": True, "block_on_caller_observed": True,
            }
            workers = resource_evidence.thread_capacities(
                runtime, mode, 16_384, "macos", pid)["tokio_worker"]
            return runtime, workers

        reduced, reduced_workers = measured("reduced", 402)
        _, production_workers = measured("production", 403)
        self.assertGreaterEqual(
            min(item["usable_bytes"] for item in production_workers),
            2 * max(item["usable_bytes"] for item in reduced_workers))
        reduced_workers[0]["usable_end"] -= 12_288
        reduced_workers[0]["usable_bytes"] -= 12_288
        with self.assertRaisesRegex(ValueError, "pthread stack offset or layout"):
            resource_evidence.thread_capacities(reduced, "reduced", 16_384, "macos", 402)
        reduced_workers[0]["usable_end"] += 12_288
        reduced_workers[0]["usable_bytes"] += 12_288
        reduced_workers[0]["mapped_end"] += 4096
        reduced_workers[0]["mapped_bytes"] += 4096
        reduced_workers[0]["usable_end"] += 4096
        reduced_workers[0]["usable_bytes"] += 4096
        with self.assertRaisesRegex(ValueError, "pthread stack offset or layout"):
            resource_evidence.thread_capacities(reduced, "reduced", 16_384, "macos", 402)

    def test_macos_guard_control_accepts_faulted_children_only(self):
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest, report = guard_report(directory)
            report["host"]["os"] = "macos"
            control = report["guard_control"]
            control["process"]["command"][2] = manifest["guard_control_runner"]["macos_test_name"]
            path = directory / control["raw_log"]["path"]
            lines = path.read_text().splitlines()
            for index in (1, 2):
                child = json.loads(lines[index].split("=", 1)[1])
                child["target"]["guard_verification"] = "macos_mach_vm_region_prot_none"
                child["child_stdout"] = (
                    "running 1 test\nKONTOR_RESOURCE_GUARD_TARGET=" +
                    json.dumps(child["target"]) + "\n")
                lines[index] = "KONTOR_RESOURCE_GUARD_CONTROL=" + json.dumps(child)
            lines[4] = lines[4].replace("linux_worker_guard_fault_control",
                                        "macos_worker_guard_fault_control")
            path.write_text("\n".join(lines) + "\n")
            control["raw_log"]["sha256"] = resource_evidence.sha256(path)
            resource_evidence.check_guard_control(report, manifest, directory)
            for mutation, expected in (
                    ("sigbus", "guard child signal"),
                    ("sigsegv", "guard child signal"),
                    ("unrelated_abort", "raw output does not corroborate"),
                    ("missing_fatal_diagnostic", "raw output does not corroborate"),
                    ("wrong_worker_identity", "raw output does not corroborate")):
                with self.subTest(mutation=mutation):
                    changed = lines.copy()
                    child = json.loads(changed[1].split("=", 1)[1])
                    if mutation == "sigbus":
                        child["signal"] = 10
                    elif mutation == "sigsegv":
                        child["signal"] = 11
                    elif mutation == "unrelated_abort":
                        child["child_stderr"] = "fatal runtime error: unrelated abort\n"
                    elif mutation == "missing_fatal_diagnostic":
                        child["child_stderr"] = child["child_stderr"].splitlines()[0] + "\n"
                    else:
                        child["target"]["os_thread_id"] += 1
                        child["child_stdout"] = (
                            "running 1 test\nKONTOR_RESOURCE_GUARD_TARGET=" +
                            json.dumps(child["target"]) + "\n")
                    changed[1] = "KONTOR_RESOURCE_GUARD_CONTROL=" + json.dumps(child)
                    path.write_text("\n".join(changed) + "\n")
                    control["raw_log"]["sha256"] = resource_evidence.sha256(path)
                    with self.assertRaisesRegex(ValueError, expected):
                        resource_evidence.check_guard_control(report, manifest, directory)

    def test_guard_control_transcript_mutations(self):
        for mutation, expected in (
                ("missing_child", "lacks exact two children and terminal"),
                ("duplicate_mode", "mode is missing or duplicated"),
                ("misattributed_tid", "raw output does not corroborate its fault"),
                ("wrong_terminal_source", "terminal differs from source or binary closure"),
                ("failed_parent", "process failed or transcript is incomplete")):
            with self.subTest(mutation=mutation), tempfile.TemporaryDirectory() as temporary:
                directory = Path(temporary)
                manifest, report = guard_report(directory)
                control = report["guard_control"]
                path = directory / control["raw_log"]["path"]
                lines = path.read_text().splitlines()
                if mutation == "missing_child":
                    lines.pop(2)
                elif mutation == "duplicate_mode":
                    lines[2] = lines[1]
                elif mutation == "misattributed_tid":
                    child = json.loads(lines[2].split("=", 1)[1])
                    child["target"]["os_thread_id"] = 999
                    child["child_stdout"] = (
                        "running 1 test\nKONTOR_RESOURCE_GUARD_TARGET=" +
                        json.dumps(child["target"]) + "\n")
                    lines[2] = "KONTOR_RESOURCE_GUARD_CONTROL=" + json.dumps(child)
                elif mutation == "wrong_terminal_source":
                    terminal = json.loads(lines[3].split("=", 1)[1])
                    terminal["embedded_source_sha"] = "0" * 40
                    lines[3] = "KONTOR_RESOURCE_GUARD_TERMINAL=" + json.dumps(terminal)
                else:
                    control["process"]["exit_code"] = 1
                if mutation != "failed_parent":
                    path.write_text("\n".join(lines) + "\n")
                    control["raw_log"]["sha256"] = resource_evidence.sha256(path)
                with self.assertRaisesRegex(ValueError, expected):
                    resource_evidence.check_guard_control(report, manifest, directory)


if __name__ == "__main__":
    unittest.main()
