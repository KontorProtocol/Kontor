use std::collections::BTreeMap;
use std::fs;
use std::iter::repeat_n;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use super::build::{artifact_file, hex_digest};
use super::{IDENTITY_FIELDS, REPORT_PREFIX, SWEEP_FIELDS, parse_sweep};

pub(super) const CASES: &[&str] = &[
    "core_recurse",
    "core_wide",
    "paid_huge",
    "paid_recurse",
    "paid_reenter",
    "paid_wide",
    "system_recurse",
    "system_wide",
    "view_recurse",
    "view_wide",
];
pub(super) const SEMANTICS: &[&str] = &[
    "kind",
    "depth",
    "outcome",
    "value",
    "receipt",
    "last_depth",
    "child_markers",
    "rolled_back",
    "fuel",
    "reset",
    "fixture_contracts",
    "call_hook_installed",
    "gas_limit",
    "paid_fuel_limit",
    "view_gas_limit",
    "view_fuel_limit",
    "system_fuel_ceiling",
    "gas_to_fuel_multiplier",
    "max_wasm_stack",
    "async_stack_size",
    "engine_target",
    "component_sha256",
];
const OBSERVATION_FIELDS: &[&str] = &[
    "kind",
    "depth",
    "outcome",
    "value",
    "receipt",
    "last_depth",
    "child_markers",
    "rolled_back",
    "fuel",
    "gas_limit",
    "paid_fuel_limit",
    "view_gas_limit",
    "view_fuel_limit",
    "system_fuel_ceiling",
    "gas_to_fuel_multiplier",
    "max_wasm_stack",
    "async_stack_size",
    "engine_target",
    "component_sha256",
    "target_os",
    "target_arch",
    "log",
];

pub(super) fn fields(value: &Value, names: &[&str]) -> Result<()> {
    let object = value.as_object().context("expected evidence object")?;
    ensure!(
        names.iter().all(|name| object.contains_key(*name)),
        "missing evidence fields"
    );
    Ok(())
}
pub(super) fn number(value: &Value) -> Result<u64> {
    value
        .as_u64()
        .context("invalid nonnegative evidence integer")
}
pub(super) fn string(value: &Value) -> Result<&str> {
    value.as_str().context("invalid evidence string")
}
pub(super) fn select(value: &Value, fields: &[&str]) -> Value {
    fields
        .iter()
        .map(|key| ((*key).to_owned(), value[*key].clone()))
        .collect()
}
fn without_log(value: &Value) -> Value {
    value
        .as_object()
        .unwrap()
        .iter()
        .filter(|(key, _)| key.as_str() != "log")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}
fn signature(value: &Value) -> Value {
    OBSERVATION_FIELDS
        .iter()
        .chain(SWEEP_FIELDS)
        .filter(|field| {
            !["target_os", "target_arch", "log"].contains(field) && !IDENTITY_FIELDS.contains(field)
        })
        .map(|key| ((*key).to_owned(), value[*key].clone()))
        .collect()
}
pub(super) fn reports(directory: &Path, name: &Value, prefix: &str) -> Result<Vec<Value>> {
    fs::read_to_string(artifact_file(directory, string(name)?)?)?
        .lines()
        .filter_map(|line| line.strip_prefix(prefix))
        .map(|line| serde_json::from_str(line).context("invalid raw probe report"))
        .collect()
}

fn observation(value: &Value, kind: &str, os: &str, arch: &str, directory: &Path) -> Result<()> {
    fields(value, OBSERVATION_FIELDS)?;
    fields(value, SWEEP_FIELDS)?;
    ensure!(value["kind"] == kind, "mismatched observation kind");
    let depth = number(&value["depth"])?;
    let outcome = string(&value["outcome"])?;
    ensure!(
        ["ok", "stack_overflow", "invocation_limit"].contains(&outcome),
        "invalid outcome"
    );
    ensure!(
        value["target_os"] == os && value["target_arch"] == arch,
        "target mismatch"
    );
    ensure!(
        value["engine_target"] == "pulley64-unknown-unknown-elf",
        "wrong engine"
    );
    ensure!(
        value["max_wasm_stack"].as_u64() == Some(524288)
            && value["async_stack_size"].as_u64() == Some(2097152),
        "wrong stack settings"
    );
    ensure!(
        hex_digest(&value["component_sha256"], 64),
        "invalid component hash"
    );
    number(&value["last_depth"])?;
    let children = value["child_markers"]
        .as_array()
        .context("invalid child markers")?;
    for child in children {
        number(child)?;
    }
    ensure!(value["rolled_back"].is_boolean(), "invalid rollback flag");
    fields(&value["fuel"], &["user", "system", "deposit"])?;
    ensure!(
        value["fuel"].as_object().unwrap().len() == 3,
        "invalid fuel"
    );
    for fuel in value["fuel"].as_object().unwrap().values() {
        number(fuel)?;
    }
    for field in [
        "gas_limit",
        "paid_fuel_limit",
        "view_gas_limit",
        "view_fuel_limit",
        "system_fuel_ceiling",
        "gas_to_fuel_multiplier",
    ] {
        number(&value[field])?;
    }
    let receipt = &value["receipt"];
    if !receipt.is_null() {
        fields(receipt, &["status", "gas"])?;
        ensure!(receipt.as_object().unwrap().len() == 2, "invalid receipt");
        string(&receipt["status"])?;
        number(&receipt["gas"])?;
    }
    let view = kind.starts_with("view_") || kind.starts_with("system_");
    if view {
        ensure!(receipt.is_null(), "view call persisted a receipt");
    } else {
        let status = match outcome {
            "ok" => "Ok",
            "stack_overflow" => "Trap",
            _ => "Other",
        };
        ensure!(
            receipt["status"] == status && number(&receipt["gas"])? > 0,
            "wrong receipt"
        );
    }
    ensure!(
        value["value"].is_null() || value["value"].is_string(),
        "invalid returned value"
    );
    ensure!(
        reports(directory, &value["log"], REPORT_PREFIX)? == vec![without_log(value)],
        "raw log disagrees with observation"
    );
    if outcome != "ok" {
        ensure!(
            value["value"].is_null() && value["rolled_back"] == true,
            "failed call did not roll back"
        );
        ensure!(
            value["last_depth"].as_u64() == Some(0)
                && children.iter().all(|c| c.as_u64() == Some(0)),
            "failed call retained state"
        );
        ensure!(
            children.len() == if kind == "paid_reenter" { 64 } else { 0 },
            "missing child state"
        );
    } else {
        let expected = if kind == "paid_huge" {
            32640
        } else if kind.ends_with("_wide") {
            depth.checked_mul(496).context("wide result overflow")?
        } else {
            depth
        };
        let expected_value = expected.to_string();
        ensure!(
            value["value"].as_str() == Some(expected_value.as_str()),
            "incorrect successful value"
        );
        let marker = if view {
            0
        } else if kind == "paid_huge" {
            1
        } else {
            depth
        };
        ensure!(
            value["last_depth"].as_u64() == Some(marker) && value["rolled_back"] == false,
            "incorrect successful state"
        );
        let expected_children: Vec<Value> = if kind == "paid_reenter" {
            ensure!(depth <= 63, "successful reentry exceeds capacity");
            (0..depth)
                .rev()
                .chain(repeat_n(0, (64 - depth) as usize))
                .map(Value::from)
                .collect()
        } else {
            vec![]
        };
        ensure!(*children == expected_children, "incorrect child state");
    }
    Ok(())
}

pub(super) fn validate_case(case: &Value, os: &str, arch: &str, directory: &Path) -> Result<Value> {
    fields(case, &["kind", "boundary", "observations"])?;
    let kind = string(&case["kind"])?;
    ensure!(CASES.contains(&kind), "unexpected case");
    let worker = case["observations"].as_array().context("no observations")?;
    let control = case["control_observations"]
        .as_array()
        .context("missing fresh-process control")?;
    ensure!(!worker.is_empty() && !control.is_empty(), "empty sweep");
    let mut summaries = Vec::new();
    for (role, samples) in [("worker", worker), ("control", control)] {
        let raw = fs::read_to_string(artifact_file(
            directory,
            string(&case[format!("{role}_log")])?,
        )?)?;
        let (parsed, summary) = parse_sweep(&raw, kind, role)?;
        ensure!(
            summary == case[format!("{role}_summary")],
            "summary disagrees with raw log"
        );
        for sample in samples {
            ensure!(sample.is_object(), "invalid sweep sample");
        }
        ensure!(
            parsed == samples.iter().map(without_log).collect::<Vec<_>>(),
            "samples disagree with raw transcript"
        );
        summaries.push(summary);
    }
    ensure!(
        summaries[0]["boundaries"] == summaries[1]["boundaries"],
        "fresh control boundary differs"
    );
    ensure!(
        summaries[0]["baseline_digest_sha256"] == summaries[1]["baseline_digest_sha256"],
        "fresh control baseline differs"
    );
    let expected = if kind == "paid_huge" {
        json!({"bounded_depth":0})
    } else {
        select(
            case,
            &["last_success", "first_failure", "first_failure_outcome"],
        )
    };
    ensure!(
        summaries[0]["boundaries"] == expected,
        "summary boundary differs from report"
    );
    let mut depths: BTreeMap<u64, Vec<&Value>> = BTreeMap::new();
    for sample in worker {
        observation(sample, kind, os, arch, directory)?;
        depths
            .entry(number(&sample["depth"])?)
            .or_default()
            .push(sample);
    }
    for sample in control {
        observation(sample, kind, os, arch, directory)?;
        ensure!(
            depths
                .get(&number(&sample["depth"])?)
                .is_some_and(|values| values.iter().any(|v| signature(v) == signature(sample))),
            "fresh control observation differs"
        );
    }
    for samples in depths.values() {
        ensure!(
            samples
                .iter()
                .all(|s| signature(s) == signature(samples[0])),
            "repeat mismatch"
        );
    }
    if kind == "paid_huge" {
        ensure!(
            case["boundary"] == "bounded"
                && worker.len() == 1
                && worker[0]["depth"].as_u64() == Some(0)
                && worker[0]["outcome"] == "ok",
            "invalid bounded case"
        );
    } else {
        let success = number(&case["last_success"])?;
        let failure = number(&case["first_failure"])?;
        let outcome = if kind == "paid_reenter" {
            "invocation_limit"
        } else {
            "stack_overflow"
        };
        ensure!(
            case["boundary"] == "first_failure" && success.checked_add(1) == Some(failure),
            "nonadjacent boundary"
        );
        ensure!(
            case["first_failure_outcome"] == outcome,
            "wrong boundary class"
        );
        for (depth, outcome) in [(success, "ok"), (failure, outcome)] {
            ensure!(
                depths
                    .get(&depth)
                    .is_some_and(|s| s.len() >= 3 && s.iter().all(|v| v["outcome"] == outcome)),
                "boundary lacks consistent repeats"
            );
        }
        if kind == "paid_reenter" {
            ensure!(
                (success, failure) == (63, 64),
                "reentry must admit 64 Stores and reject 65"
            );
            ensure!(
                depths
                    .get(&62)
                    .is_some_and(|s| s.len() >= 3 && s.iter().all(|v| v["outcome"] == "ok")),
                "63 Store samples must succeed"
            );
        }
    }
    let mut result = select(
        case,
        &[
            "boundary",
            "last_success",
            "first_failure",
            "first_failure_outcome",
        ],
    );
    result["observations"] = worker.iter().map(signature).collect();
    result["control_observations"] = control.iter().map(signature).collect();
    Ok(result)
}

pub(super) fn validate_owned(case: &Value, directory: &Path) -> Result<Value> {
    let kind = string(&case["kind"])?;
    let depths = if kind == "paid_huge" {
        vec![0]
    } else {
        vec![
            number(&case["last_success"])?,
            number(&case["first_failure"])?,
        ]
    };
    let samples = case["owned_observations"]
        .as_array()
        .context("missing owned stack samples")?;
    ensure!(samples.len() == depths.len(), "missing owned stack samples");
    let outcomes: Vec<_> = samples.iter().map(|s| s["outcome"].clone()).collect();
    ensure!(
        case["owned_summary"]
            == json!({"kind":kind,"depths":depths,"outcomes":outcomes,"owned":true}),
        "invalid owned stack summary"
    );
    ensure!(
        reports(directory, &case["owned_log"], "KONTOR_OWNED_STACK_REPORT:")? == *samples,
        "raw owned stack evidence differs"
    );
    let controls = case["control_observations"]
        .as_array()
        .context("missing owned oracle")?;
    let mut normalized = Vec::new();
    for (index, (depth, sample)) in depths.iter().zip(samples).enumerate() {
        fields(sample, SEMANTICS)?;
        ensure!(
            sample["role"] == "owned"
                && sample["sample_index"].as_u64() == Some(index as u64)
                && sample["sample_id"] == format!("owned:{kind}:{index:04}"),
            "wrong owned sample identity"
        );
        ensure!(
            sample["kind"] == kind && sample["depth"].as_u64() == Some(*depth),
            "wrong owned stack boundary"
        );
        let owner = &sample["ownership"];
        fields(owner, &["kind", "fuel_yield_interval", "registered_peak"])?;
        ensure!(
            owner.as_object().unwrap().len() == 3,
            "invalid owner evidence"
        );
        let api = kind.starts_with("view_");
        ensure!(
            owner["kind"] == if api { "api" } else { "canonical" },
            "wrong owner policy"
        );
        ensure!(
            owner["fuel_yield_interval"] == if api { json!(100000) } else { Value::Null },
            "wrong owner yield policy"
        );
        let peak = number(&owner["registered_peak"])?;
        ensure!((1..=64).contains(&peak), "no registered guest Store");
        if kind == "paid_reenter" {
            ensure!(
                peak == depth.saturating_add(1).min(64),
                "descendant Stores were not registered"
            );
        }
        let oracle = controls
            .iter()
            .find(|s| s["depth"].as_u64() == Some(*depth))
            .context("missing owned oracle boundary")?;
        ensure!(
            sample["cache_mode"]
                == if api {
                    "fresh_api_pool_cache"
                } else {
                    "warm_compiled_cache"
                },
            "wrong owned cache provenance"
        );
        ensure!(
            sample["target_os"] == oracle["target_os"]
                && sample["target_arch"] == oracle["target_arch"],
            "owned target differs"
        );
        if api {
            ensure!(
                sample["state_after_sha256"] == sample["reset"]["post"]["persistent_digest_sha256"],
                "owned API state digest differs"
            );
        }
        ensure!(
            select(sample, SEMANTICS) == select(oracle, SEMANTICS),
            "owned output, receipt, fuel, or rollback differs from unowned control"
        );
        normalized.push(json!({"semantics":select(sample,SEMANTICS),"ownership":owner}));
    }
    Ok(json!(normalized))
}
