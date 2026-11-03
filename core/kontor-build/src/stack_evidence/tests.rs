use serde_json::{Value, json};

use super::{CACHE_MODE, REPORT_PREFIX, SUMMARY_PREFIX, parse_sweep, validate_pair};

pub(super) fn fixture(kind: &str, role: &str) -> (Vec<Value>, Value) {
    let depths: Vec<u64> = match (kind, role) {
        ("paid_huge", _) => vec![0],
        ("paid_reenter", "control") => vec![63, 64],
        ("paid_reenter", _) => vec![62, 63, 64, 64, 63, 62, 62, 63, 64],
        (_, "control") => vec![3, 4],
        _ => vec![0, 3, 4, 3, 4, 4, 3, 3, 4],
    };
    let contracts = if kind == "paid_reenter" { 65 } else { 1 };
    let failure = if kind == "paid_reenter" { 64 } else { 4 };
    let expected = if kind == "paid_reenter" {
        "invocation_limit"
    } else {
        "stack_overflow"
    };
    let samples = depths.iter().enumerate().map(|(index, depth)| {
        let outcome = if *depth < failure { "ok" } else { expected };
        json!({
            "kind": kind, "role": role, "sample_index": index,
            "sample_id": format!("{role}:{kind}:{index:04}"), "depth": depth,
            "cache_mode": CACHE_MODE, "fixture_contracts": contracts,
            "call_hook_installed": false, "outcome": outcome,
            "value": if outcome == "ok" { json!(depth.to_string()) } else { Value::Null },
            "fuel": {"user": 100, "system": 0, "deposit": 0},
            "reset": {
                "pre": {"live_invocations": 0, "stack_empty": true, "savepoint_intact": true,
                    "resource_count": 0, "baseline_resource_count": 0,
                    "failure_rolled_back": if outcome == "ok" { Value::Null } else { json!(true) }},
                "post": {"persistent_digest_sha256": "1".repeat(64), "baseline_digest_sha256": "1".repeat(64),
                    "digest_matches": true, "live_invocations": 0, "stack_empty": true,
                    "savepoint_restored": true, "resource_count": 0, "balances_restored": true,
                    "floor_restored": true, "supply_restored": true}
            }
        })
    }).collect::<Vec<_>>();
    let summary = json!({
        "role": role, "kind": kind, "cache_mode": CACHE_MODE, "fixture_contracts": contracts,
        "baseline_digest_sha256": "1".repeat(64),
        "ordered_sample_indices": (0..samples.len()).collect::<Vec<_>>(),
        "ordered_sample_ids": samples.iter().map(|sample| sample["sample_id"].clone()).collect::<Vec<_>>(),
        "boundaries": if kind == "paid_huge" { json!({"bounded_depth": 0}) } else {
            json!({"last_success": failure - 1, "first_failure": failure, "first_failure_outcome": expected}) }
    });
    (samples, summary)
}

pub(super) fn transcript(samples: &[Value], summary: &Value) -> String {
    let mut raw = String::new();
    for sample in samples {
        raw.push_str(&format!("{REPORT_PREFIX}{sample}\n"));
    }
    raw.push_str(&format!(
        "{SUMMARY_PREFIX}{summary}\ntest result: ok. 1 passed; 0 failed; 0 ignored;\n"
    ));
    raw
}

fn rejects(samples: &[Value], summary: &Value) {
    assert!(parse_sweep(&transcript(samples, summary), "paid_reenter", "worker").is_err());
}

#[test]
fn worker_and_fresh_control_preserve_all_case_records() {
    for kind in [
        "paid_recurse",
        "paid_wide",
        "view_recurse",
        "view_wide",
        "system_recurse",
        "system_wide",
        "core_recurse",
        "core_wide",
        "paid_reenter",
        "paid_huge",
    ] {
        let (worker, ws) = fixture(kind, "worker");
        let (mut control, cs) = fixture(kind, "control");
        for (samples, summary) in [(&worker, &ws), (&control, &cs)] {
            assert_eq!(
                parse_sweep(
                    &transcript(samples, summary),
                    kind,
                    summary["role"].as_str().unwrap()
                )
                .unwrap(),
                (samples.clone(), summary.clone())
            );
        }
        control[0]["log"] = json!("other.log");
        control[0]["target_os"] = json!("macos");
        control[0]["target_arch"] = json!("aarch64");
        control[0]["error"] = json!("diagnostic text");
        validate_pair(&worker, &ws, &control, &cs).unwrap();
        control[0]["fuel"]["user"] = json!(101);
        assert!(validate_pair(&worker, &ws, &control, &cs).is_err());
    }
}

#[test]
fn reset_failures_cannot_be_hidden_by_successful_summary() {
    for (stage, field, value) in [
        ("pre", "live_invocations", json!(1)),
        ("pre", "stack_empty", json!(false)),
        ("pre", "savepoint_intact", json!(false)),
        ("pre", "resource_count", json!(1)),
        ("pre", "failure_rolled_back", json!(false)),
        ("post", "live_invocations", json!(1)),
        ("post", "stack_empty", json!(false)),
        ("post", "savepoint_restored", json!(false)),
        ("post", "resource_count", json!(1)),
        ("post", "balances_restored", json!(false)),
        ("post", "floor_restored", json!(false)),
        ("post", "supply_restored", json!(false)),
        ("post", "digest_matches", json!(false)),
        ("post", "persistent_digest_sha256", json!("2".repeat(64))),
        ("post", "baseline_digest_sha256", json!("2".repeat(64))),
        ("pre", "baseline_resource_count", json!(-1)),
        ("pre", "baseline_resource_count", json!(0.0)),
        ("post", "live_invocations", json!(false)),
    ] {
        let (mut samples, summary) = fixture("paid_reenter", "worker");
        samples[2]["reset"][stage][field] = value;
        rejects(&samples, &summary);
    }
    let (mut samples, summary) = fixture("paid_reenter", "worker");
    samples[0]["reset"]["pre"]
        .as_object_mut()
        .unwrap()
        .remove("failure_rolled_back");
    rejects(&samples, &summary);
    for value in [
        Value::Null,
        json!([]),
        json!({"pre": {}, "post": {}, "extra": {}}),
    ] {
        samples[0]["reset"] = value;
        rejects(&samples, &summary);
    }
}

#[test]
fn missing_duplicate_reordered_and_malformed_observations_fail() {
    let (samples, summary) = fixture("paid_reenter", "worker");
    let mut missing = samples.clone();
    missing.pop();
    rejects(&missing, &summary);
    let mut duplicate = samples.clone();
    duplicate[1] = duplicate[0].clone();
    rejects(&duplicate, &summary);
    let mut reordered = samples.clone();
    reordered.swap(0, 1);
    rejects(&reordered, &summary);
    for (field, value) in [
        ("role", json!("control")),
        ("fixture_contracts", json!(64)),
        ("fixture_contracts", json!(65.0)),
        ("sample_index", json!(false)),
        ("sample_index", json!(0.0)),
        ("sample_id", json!("wrong")),
        ("depth", json!(-1)),
        ("depth", json!(1.0)),
        ("outcome", json!("panic")),
        ("call_hook_installed", json!(true)),
        ("call_hook_installed", Value::Null),
    ] {
        let mut changed = samples.clone();
        changed[0][field] = value;
        rejects(&changed, &summary);
    }
    for value in [Value::Null, json!(1), json!([]), json!(false)] {
        let mut changed = samples.clone();
        changed[0] = value;
        rejects(&changed, &summary);
    }
    rejects(&[], &summary);
    rejects(&vec![samples[0].clone(); 129], &summary);
}

#[test]
fn terminal_order_and_complete_line_markers_are_required() {
    let (samples, summary) = fixture("paid_reenter", "worker");
    let raw = transcript(&samples, &summary);
    parse_sweep(
        &format!("diagnostic: {REPORT_PREFIX}not JSON\n{raw}"),
        "paid_reenter",
        "worker",
    )
    .unwrap();
    for bad in [
        raw.split(SUMMARY_PREFIX).next().unwrap().to_owned(),
        raw.split("test result:").next().unwrap().to_owned(),
        raw.replace("test result: ok.", "test result: FAILED."),
        format!("{raw}{SUMMARY_PREFIX}{summary}\n"),
        format!("{raw}{REPORT_PREFIX}{}\n", samples[0]),
        format!("{raw}test result: ok. 1 passed; 0 failed;\n"),
        format!("test result: ok. 1 passed; 0 failed;\n{raw}"),
        raw.replacen(REPORT_PREFIX, &format!("diagnostic: {REPORT_PREFIX}"), 1),
        format!("{REPORT_PREFIX}not JSON\n{raw}"),
    ] {
        assert!(parse_sweep(&bad, "paid_reenter", "worker").is_err());
    }
}

#[test]
fn frozen_boundaries_and_forward_reverse_repeats_are_required() {
    let (samples, summary) = fixture("paid_reenter", "worker");
    for (field, value) in [
        ("last_success", json!(62)),
        ("first_failure", json!(65)),
        ("first_failure_outcome", json!("stack_overflow")),
        ("last_success", json!(u64::MAX)),
    ] {
        let mut changed = summary.clone();
        changed["boundaries"][field] = value;
        rejects(&samples, &changed);
    }
    let mut sorted = samples.clone();
    sorted.sort_by_key(|sample| sample["depth"].as_u64().unwrap());
    for (i, sample) in sorted.iter_mut().enumerate() {
        sample["sample_index"] = json!(i);
        sample["sample_id"] = summary["ordered_sample_ids"][i].clone();
    }
    rejects(&sorted, &summary);
    let (mut samples, summary) = fixture("paid_wide", "worker");
    samples[0]["depth"] = json!(1);
    assert!(parse_sweep(&transcript(&samples, &summary), "paid_wide", "worker").is_err());
    samples[0]["depth"] = json!(0);
    samples[8]["depth"] = json!(3);
    assert!(parse_sweep(&transcript(&samples, &summary), "paid_wide", "worker").is_err());
    let (mut samples, summary) = fixture("paid_huge", "worker");
    samples[0]["depth"] = json!(1);
    assert!(parse_sweep(&transcript(&samples, &summary), "paid_huge", "worker").is_err());
    let (mut samples, summary) = fixture("paid_reenter", "control");
    samples[0]["depth"] = json!(62);
    assert!(parse_sweep(&transcript(&samples, &summary), "paid_reenter", "control").is_err());
}

#[test]
fn summary_and_pair_identity_fail_closed() {
    let (worker, ws) = fixture("paid_reenter", "worker");
    let (control, cs) = fixture("paid_reenter", "control");
    for field in [
        "boundaries",
        "baseline_digest_sha256",
        "cache_mode",
        "fixture_contracts",
        "kind",
    ] {
        let mut changed = cs.clone();
        changed[field] = Value::Null;
        assert!(validate_pair(&worker, &ws, &control, &changed).is_err());
        let mut missing = ws.clone();
        missing.as_object_mut().unwrap().remove(field);
        assert!(validate_pair(&worker, &missing, &control, &cs).is_err());
    }
    for (field, value) in [
        (
            "ordered_sample_indices",
            json!([false, 1, 2, 3, 4, 5, 6, 7, 8]),
        ),
        ("ordered_sample_ids", json!([])),
        ("baseline_digest_sha256", json!("A".repeat(64))),
        ("baseline_digest_sha256", json!("1".repeat(63))),
        ("kind", json!("paid_wide")),
    ] {
        let mut changed = ws.clone();
        changed[field] = value;
        rejects(&worker, &changed);
    }
    assert!(validate_pair(&[Value::Null], &ws, &control, &cs).is_err());
    assert!(validate_pair(&worker, &ws, &[Value::Null], &cs).is_err());
}
