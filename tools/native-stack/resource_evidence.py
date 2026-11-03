"""Shared strict input, thread-capacity and guard checks for S2 case captures."""

import hashlib
import json
import re
import signal
from decimal import Decimal, InvalidOperation
from pathlib import Path

from resource_manifest import THREAD_CATEGORIES


def canonical_decimal_amount(value, label):
    require(isinstance(value, str) and 0 < len(value) <= 128,
            f"{label}: invalid balance amount")
    try:
        amount = Decimal(value)
    except InvalidOperation as error:
        raise ValueError(f"{label}: invalid balance amount") from error
    require(amount.is_finite() and abs(amount.as_tuple().exponent) <= 128,
            f"{label}: invalid balance amount")
    if amount.is_zero():
        return "0"
    encoded = format(amount, "f")
    return encoded.rstrip("0").rstrip(".") if "." in encoded else encoded


def no_duplicate_keys(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def no_nonfinite_constants(value):
    raise ValueError(f"non-finite JSON constant: {value}")


def load_json_strict(path):
    return json.loads(path.read_text(), object_pairs_hook=no_duplicate_keys,
                      parse_constant=no_nonfinite_constants)


def require(condition, message):
    if not condition:
        raise ValueError(message)


def sha256(path):
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for chunk in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def file_evidence(directory, entry):
    require(set(entry) == {"path", "sha256"}, "raw log identity is incomplete")
    relative = Path(entry["path"])
    require(not relative.is_absolute() and ".." not in relative.parts, "raw log escapes evidence directory")
    path = directory / relative
    require(path.resolve().is_relative_to(directory.resolve()),
            "raw log resolves outside evidence directory")
    require(path.is_file(), f"missing raw log {relative}")
    require(sha256(path) == entry["sha256"], f"raw log hash mismatch: {relative}")


def thread_capacities(runtime, mode, page_size, os_name, process_id):
    require(runtime["flavor"] == "multi_thread", f"{mode}: runtime is not multithreaded")
    require(type(runtime["worker_count"]) is int and runtime["worker_count"] >= 2,
            f"{mode}: invalid worker count")
    if mode == "reduced":
        require(runtime["worker_requested_bytes"] == 1_015_808,
                "reduced workers did not request 992 KiB")
    observations = runtime["thread_observations"]
    require(isinstance(observations, list), f"{mode}: missing thread observations")
    by_category = {category: [] for category in THREAD_CATEGORIES}
    for thread in observations:
        require(set(thread) == {"thread_category", "thread_id", "process_id",
                                "os_thread_id", "identity_api", "page_size_bytes",
                                "requested_bytes", "mapped_bytes", "guard_bytes",
                                "guard_start", "guard_end", "guard_verification", "usable_bytes",
                                "mapped_start", "mapped_end", "usable_start", "usable_end",
                                "measurement_api", "guard_treatment", "guard_verified"},
                f"{mode}: thread capacity record is incomplete")
        category = thread["thread_category"]
        require(category in by_category, f"{mode}: unknown thread category")
        require(isinstance(thread["thread_id"], str) and thread["thread_id"]
                and type(thread["process_id"]) is int and thread["process_id"] == process_id
                and type(thread["os_thread_id"]) is int and thread["os_thread_id"] > 0
                and thread["identity_api"] == ("linux_gettid" if os_name == "linux"
                                               else "macos_pthread_threadid_np")
                and thread["page_size_bytes"] == page_size,
                f"{mode}: thread identity or page size is unverified")
        require(type(thread["mapped_bytes"]) is int and thread["mapped_bytes"] > 0,
                f"{mode}: invalid mapped stack")
        require(type(thread["guard_bytes"]) is int and thread["guard_bytes"] >= 0,
                f"{mode}: invalid guard")
        require(type(thread["usable_bytes"]) is int and
                0 < thread["usable_bytes"] <= thread["mapped_bytes"],
                f"{mode}: usable stack capacity is unverified")
        require(all(type(thread[key]) is int and thread[key] >= 0 for key in
                    ("mapped_start", "mapped_end", "usable_start", "usable_end"))
                and thread["mapped_end"] - thread["mapped_start"] == thread["mapped_bytes"]
                and thread["usable_end"] - thread["usable_start"] == thread["usable_bytes"]
                and thread["mapped_start"] <= thread["usable_start"]
                and thread["usable_end"] <= thread["mapped_end"],
                f"{mode}: actual usable worker range is unverified")
        if os_name == "macos" and category == "tokio_worker":
            page = thread["page_size_bytes"]
            # The arm64 pthread offset is writable stack space, so excluding it
            # from usable_bytes would misstate the measured capacity ratio.
            require(page > 0 and thread["mapped_start"] % page == 0
                    and thread["usable_start"] == thread["mapped_start"]
                    and thread["usable_end"] == thread["mapped_end"],
                    f"{mode}: unexpected macOS pthread stack offset or layout")
            if mode == "reduced":
                requested = thread["requested_bytes"]
                require(type(requested) is int and requested % page == 0
                        and thread["mapped_bytes"] - requested ==
                            thread["mapped_end"] % page,
                        f"{mode}: unexpected macOS pthread stack offset or layout")
        require(isinstance(thread["measurement_api"], str) and thread["measurement_api"],
                f"{mode}: missing stack measurement API")
        require(isinstance(thread["guard_treatment"], str) and
                thread["guard_treatment"] not in {"", "unknown"}
                and thread["guard_verified"] is True,
                f"{mode}: unresolved thread guard treatment")
        guard = thread["guard_bytes"]
        guard_start = thread["guard_start"]
        guard_end = thread["guard_end"]
        verification = thread["guard_verification"]
        if guard == 0:
            require(category != "tokio_worker" and guard_start == guard_end == 0
                    and verification == "pthread_reports_none",
                    f"{mode}: worker guard is absent or guard range is inconsistent")
        else:
            methods = ({"linux_maps_prot_none", "linux_proc_self_mem_eio"}
                       if os_name == "linux" else {"macos_mach_vm_region_prot_none"})
            require(verification in methods and
                    all(type(value) is int and value >= 0 for value in
                        (guard_start, guard_end)) and
                    guard_end - guard_start >= guard and
                    guard_start % page_size == guard_end % page_size == 0 and
                    ((guard_start == thread["mapped_start"] and
                      guard_end == thread["usable_start"]) or
                     guard_end == thread["mapped_start"]),
                    f"{mode}: thread guard interval is unverified")
        by_category[category].append(thread)
    require(len({item["thread_id"] for item in by_category["tokio_worker"]})
            >= runtime["worker_count"], f"{mode}: not all workers measured")
    require(len({item["thread_id"] for item in observations}) == len(observations),
            f"{mode}: duplicate thread capacity record")
    require(len({item["os_thread_id"] for item in observations}) == len(observations),
            f"{mode}: duplicate kernel thread identity")
    require(all(item["requested_bytes"] == runtime["worker_requested_bytes"]
                for item in by_category["tokio_worker"]),
            f"{mode}: worker request differs from runtime settings")
    require(by_category["blocking_pool"] and runtime["blocking_pool_observed"],
            f"{mode}: blocking pool not observed")
    require(by_category["block_on_caller"] and runtime["block_on_caller_observed"],
            f"{mode}: block_on caller not observed")
    return by_category


def check_guard_control(report, manifest, directory):
    os_name = report["host"]["os"]
    require(os_name in {"linux", "macos"}, "unsupported guard control host")
    test_name = (manifest["guard_control_runner"]["test_name"] if os_name == "linux"
                 else manifest["guard_control_runner"]["macos_test_name"])
    control = report["guard_control"]
    require(set(control) == {"process", "raw_log"}, "guard control evidence is incomplete")
    process = control["process"]
    require(set(process) == {"pid", "command", "started_unix_ns", "ended_unix_ns",
                             "exit_code", "signal", "timed_out", "complete",
                             "test_harness_passed"}
            and type(process["pid"]) is int and process["pid"] > 0
            and type(process["started_unix_ns"]) is int
            and type(process["ended_unix_ns"]) is int
            and 0 < process["started_unix_ns"] < process["ended_unix_ns"]
            and process["exit_code"] == 0 and process["signal"] is None
            and process["timed_out"] is False and process["complete"] is True
            and process["test_harness_passed"] is True,
            "guard control process failed or transcript is incomplete")
    require(process["command"] == [
        report["binary_path"], "--exact", test_name,
        "--ignored", "--nocapture",
    ], "guard control command differs from compiled test")
    require(manifest["guard_control_runner"]["source_sha256"] ==
            manifest["artifacts"]["resource_worker_diagnostic"]["sha256"],
            "guard control source differs from frozen worker")
    file_evidence(directory, control["raw_log"])
    require(control["raw_log"]["path"] not in {
        item["process_log"]["path"] for item in report["configurations"].values()
    }, "guard control reuses a workload process transcript")
    lines = (directory / control["raw_log"]["path"]).read_text().splitlines()
    require(sum(line.strip() == "running 1 test" for line in lines) == 1,
            "guard control transcript lacks one selected test")
    harness = [line for line in lines if line.startswith("test result:")]
    require(len(harness) == 1 and re.fullmatch(
        r"test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in [0-9.]+s",
        harness[0]) is not None, "guard control test harness did not pass")
    markers = [line.split("KONTOR_RESOURCE_GUARD_CONTROL=", 1)[1]
               for line in lines if "KONTOR_RESOURCE_GUARD_CONTROL=" in line]
    terminals = [line.split("KONTOR_RESOURCE_GUARD_TERMINAL=", 1)[1]
                 for line in lines if "KONTOR_RESOURCE_GUARD_TERMINAL=" in line]
    require(len(markers) == 2 and len(terminals) == 1,
            "guard control transcript lacks exact two children and terminal")
    marker_positions = [index for index, line in enumerate(lines)
                        if "KONTOR_RESOURCE_GUARD_CONTROL=" in line]
    terminal_position = next(index for index, line in enumerate(lines)
                             if "KONTOR_RESOURCE_GUARD_TERMINAL=" in line)
    harness_position = next(index for index, line in enumerate(lines)
                            if line.startswith("test result:"))
    require(max(marker_positions) < terminal_position < harness_position,
            "guard control terminal or harness result is out of order")
    terminal = json.loads(terminals[0], object_pairs_hook=no_duplicate_keys,
                          parse_constant=no_nonfinite_constants)
    require(isinstance(terminal, dict) and set(terminal) == {
        "pid", "binary_path", "binary_sha256", "embedded_source_sha", "modes", "complete"
    } and type(terminal["pid"]) is int and terminal["pid"] == process["pid"]
            and terminal["binary_path"] == report["binary_path"]
            and terminal["binary_sha256"] == report["binary_sha256"]
            and terminal["embedded_source_sha"] == report["source_sha"]
            and terminal["modes"] == ["reduced", "production"]
            and terminal["complete"] is True,
            "guard control terminal differs from source or binary closure")
    seen = {}
    child_pids = set()
    child_tids = set()
    for marker in markers:
        child = json.loads(marker, object_pairs_hook=no_duplicate_keys,
                           parse_constant=no_nonfinite_constants)
        require(isinstance(child, dict) and set(child) == {
            "mode", "signal", "target", "child_binary", "child_stdout", "child_stderr"
        }, "guard child record is incomplete")
        mode = child["mode"]
        require(mode in ("reduced", "production") and mode not in seen,
                "guard control mode is missing or duplicated")
        seen[mode] = child
        target = child["target"]
        require(isinstance(target, dict) and set(target) == {
            "mode", "process_id", "os_thread_id", "page_size_bytes", "guard_start",
            "guard_end", "guard_verification", "address"
        } and target["mode"] == mode,
                "guard child target is incomplete or misattributed")
        pid = target["process_id"]
        tid = target["os_thread_id"]
        page = report["configurations"][mode]["engine"]["page_size_bytes"]
        require(type(pid) is int and pid > 0 and pid != process["pid"]
                and pid not in child_pids and type(tid) is int and tid > 0
                and tid not in child_tids and type(page) is int and page > 0
                and type(target["page_size_bytes"]) is int
                and target["page_size_bytes"] == page
                and type(target["guard_start"]) is int
                and type(target["guard_end"]) is int
                and type(target["address"]) is int
                and target["guard_start"] >= 0
                and target["guard_end"] - target["guard_start"] >= page
                and target["guard_start"] <= target["address"] < target["guard_end"]
                and target["guard_verification"] in (
                    {"guard protected inside pthread stack range",
                     "guard protected below pthread stack range",
                     "inaccessible interval verified below pthread stack range by /proc/self/mem EIO"}
                    if os_name == "linux" else {"macos_mach_vm_region_prot_none"}),
                "guard child PID, TID, or target is unverified")
        child_pids.add(pid)
        child_tids.add(tid)
        stdout = child["child_stdout"]
        stderr = child["child_stderr"]
        require(type(child["signal"]) is int and child["signal"] == signal.SIGABRT
                and child["child_binary"] == report["binary_path"]
                and isinstance(stdout, str) and isinstance(stderr, str),
                "guard child signal or binary differs from compiled control")
        nested = [line.split("KONTOR_RESOURCE_GUARD_TARGET=", 1)[1]
                  for line in stdout.splitlines()
                  if "KONTOR_RESOURCE_GUARD_TARGET=" in line]
        require(len(nested) == 1 and json.loads(
            nested[0], object_pairs_hook=no_duplicate_keys,
            parse_constant=no_nonfinite_constants) == target
                and stdout.count("running 1 test") == 1
                and "test result:" not in stdout
                and f"({tid}) has overflowed its stack" in stderr
                and "fatal runtime error: stack overflow, aborting" in stderr,
                "guard child raw output does not corroborate its fault")
    require(list(seen) == ["reduced", "production"],
            "guard control lacks one distinct child per configuration")
