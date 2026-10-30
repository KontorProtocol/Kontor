"""Validate complete stack-probe worker and control transcripts."""

import json
import re


REPORT_PREFIX = "KONTOR_STACK_REPORT:"
SUMMARY_PREFIX = "KONTOR_STACK_SWEEP_SUMMARY:"
CACHE_MODE = "warm_compiled_cache"
HEX_64 = re.compile(r"[0-9a-f]{64}\Z")
IDENTITY_FIELDS = {"role", "sample_index", "sample_id"}
SWEEP_FIELDS = IDENTITY_FIELDS | {"cache_mode", "fixture_contracts", "reset", "call_hook_installed"}


def check(condition, message):
    if not condition:
        raise ValueError(message)


def validate_reset(sample, baseline):
    reset = sample.get("reset")
    check(isinstance(reset, dict) and set(reset) == {"pre", "post"}, "missing sweep reset evidence")
    pre, post = reset["pre"], reset["post"]
    check(isinstance(pre, dict) and isinstance(post, dict), "invalid sweep reset evidence")
    check(type(pre.get("baseline_resource_count")) is int and pre["baseline_resource_count"] >= 0, "invalid baseline resources")
    for stage in (pre, post):
        check(type(stage.get("live_invocations")) is int and stage["live_invocations"] == 0, "sweep leaked invocation leases")
        check(stage.get("stack_empty") is True, "sweep leaked call frames")
        check(type(stage.get("resource_count")) is int and stage["resource_count"] == pre["baseline_resource_count"], "sweep leaked resources")
    check(pre.get("savepoint_intact") is True, "call changed the harness savepoint")
    expected_rollback = None if sample.get("outcome") == "ok" else True
    check("failure_rolled_back" in pre and pre["failure_rolled_back"] is expected_rollback, "call rollback was not established before reset")
    for field in ("digest_matches", "savepoint_restored", "balances_restored", "floor_restored", "supply_restored"):
        check(post.get(field) is True, f"sweep reset failed: {field}")
    check(post.get("persistent_digest_sha256") == post.get("baseline_digest_sha256") == baseline, "sweep persistent state was not restored")


def parse_transcript(raw, kind, role):
    observations = []
    summary = None
    terminal_success = False
    for line in raw.splitlines():
        if line.startswith(REPORT_PREFIX):
            check(summary is None, "sample appeared after sweep summary")
            observations.append(json.loads(line.split(REPORT_PREFIX, 1)[1]))
        if line.startswith(SUMMARY_PREFIX):
            check(summary is None, "duplicate sweep summary")
            summary = json.loads(line.split(SUMMARY_PREFIX, 1)[1])
        if line.startswith("test result:"):
            check(summary is not None and not terminal_success, "unexpected sweep test completion")
            check(line.startswith("test result: ok. 1 passed; 0 failed;"), "sweep test did not succeed")
            terminal_success = True
    check(isinstance(summary, dict) and terminal_success, "incomplete sweep transcript")
    check(0 < len(observations) <= 128, "invalid sweep sample count")
    fixture_contracts = 65 if kind == "paid_reenter" else 1
    for field, expected in (("role", role), ("kind", kind), ("cache_mode", CACHE_MODE), ("fixture_contracts", fixture_contracts)):
        check(summary.get(field) == expected, f"sweep summary has wrong {field}")
        check(all(isinstance(sample, dict) and sample.get(field) == expected for sample in observations), f"sweep sample has wrong {field}")
    baseline = summary.get("baseline_digest_sha256")
    check(isinstance(baseline, str) and HEX_64.fullmatch(baseline), "invalid sweep baseline digest")
    indices = list(range(len(observations)))
    ids = [f"{role}:{kind}:{index:04}" for index in indices]
    check(summary.get("ordered_sample_indices") == indices, "sweep index sequence mismatch")
    check(summary.get("ordered_sample_ids") == ids, "sweep sample ID sequence mismatch")
    for index, sample in enumerate(observations):
        check(type(sample.get("sample_index")) is int and sample["sample_index"] == index, "duplicate or out-of-order sweep sample")
        check(sample.get("sample_id") == ids[index], "invalid sweep sample identity")
        check(type(sample.get("depth")) is int and sample["depth"] >= 0, "invalid sweep depth")
        check(sample.get("outcome") in {"ok", "stack_overflow", "invocation_limit"}, "sweep process or execution failed")
        check(sample.get("call_hook_installed") is False, "sweep enabled a test-only call hook")
        validate_reset(sample, baseline)
    boundaries = summary.get("boundaries")
    check(isinstance(boundaries, dict), "missing sweep boundaries")
    depths = [sample["depth"] for sample in observations]
    if kind == "paid_huge":
        check(boundaries == {"bounded_depth": 0} and depths == [0], "invalid bounded sweep")
    else:
        success, failure = boundaries.get("last_success"), boundaries.get("first_failure")
        expected = "invocation_limit" if kind == "paid_reenter" else "stack_overflow"
        check(type(success) is int and success >= 0 and type(failure) is int and failure == success + 1, "invalid sweep boundary")
        check(boundaries.get("first_failure_outcome") == expected, "invalid sweep boundary outcome")
        if role == "control":
            check(depths == [success, failure], "control must exercise both boundary depths in order")
        elif kind == "paid_reenter":
            check((success, failure) == (63, 64), "invalid reentry boundary")
            check(depths == [62, 63, 64, 64, 63, 62, 62, 63, 64], "invalid reentry sweep order")
        else:
            check(depths[0] == 0, "recursion discovery must start at zero")
            check(depths[-6:] == [success, failure, failure, success, success, failure], "missing forward/reverse boundary repeats")
        for sample in observations:
            check(sample["outcome"] == ("ok" if sample["depth"] <= success else expected), "sweep sample contradicts its boundary")
    return observations, summary


def validate_pair(worker, worker_summary, control, control_summary):
    for field in ("boundaries", "baseline_digest_sha256", "cache_mode", "fixture_contracts", "kind"):
        check(worker_summary[field] == control_summary[field], f"fresh control differs: {field}")
    ignored = IDENTITY_FIELDS | {"log", "target_os", "target_arch", "error"}
    for sample in control:
        semantics = {key: value for key, value in sample.items() if key not in ignored}
        check(any(semantics == {key: value for key, value in candidate.items() if key not in ignored} for candidate in worker), "fresh control execution differs")
