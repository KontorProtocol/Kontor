use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use num_bigint::{BigInt, Sign};
use num_rational::BigRational;
use serde_json::{Value, json};

use super::build::hex_digest;

const CHAIN_FIELDS: &[&str] = &[
    "mode",
    "stores",
    "trials",
    "component_sha256",
    "engine_target",
    "max_wasm_stack",
    "async_stack_size",
    "target_os",
    "target_arch",
    "call_hook_installed",
];
const TRIAL_FIELDS: &[&str] = &[
    "outcome",
    "fuel",
    "receipt",
    "receipt_count",
    "value",
    "storage_state",
    "rolled_back",
    "resource_count",
    "baseline_resource_count",
    "savepoint_restored",
    "stack_empty",
    "host_io_suspended",
    "leaf_callback_seen",
    "rollback_clean",
    "balances",
    "repeat_index",
    "state_before_sha256",
    "state_after_sha256",
];
const BALANCE_FIELDS: &[&str] = &[
    "before",
    "after",
    "restored",
    "burned_before",
    "burned_after",
    "supply_before",
    "supply_after",
    "floor_before",
    "floor_after",
    "floor_restored",
];

fn fields(value: &Value, names: &[&str], exact: bool, label: &str) -> Result<()> {
    let object = value
        .as_object()
        .with_context(|| format!("missing {label} fields"))?;
    ensure!(
        (!exact || object.len() == names.len())
            && names.iter().all(|name| object.contains_key(*name)),
        "missing {label} fields"
    );
    Ok(())
}
fn number(value: &Value, label: &str) -> Result<u64> {
    value.as_u64().with_context(|| format!("invalid {label}"))
}
fn selected(value: &Value, names: &[&str]) -> Value {
    names
        .iter()
        .map(|name| ((*name).to_owned(), value[*name].clone()))
        .collect()
}
fn key(chain: &Value, owned: bool) -> Result<(String, u64)> {
    let mode = chain["mode"].as_str().context("invalid chain mode")?;
    let stores = number(&chain["stores"], "chain key")?;
    ensure!(
        ["core", "paid", "view"].contains(&mode)
            && if owned {
                [64, 65].contains(&stores)
            } else {
                [33, 63, 64, 65].contains(&stores)
            },
        "unexpected chain key"
    );
    Ok((mode.to_owned(), stores))
}

fn decimal(value: &Value) -> Result<BigRational> {
    let text = value
        .as_str()
        .context("chain balances must be decimal strings")?
        .trim()
        .replace('_', "");
    let mut parts = text.split(['e', 'E']);
    let mantissa = parts.next().unwrap_or_default();
    let exponent = parts
        .next()
        .map(str::parse::<i64>)
        .transpose()
        .context("invalid chain decimal exponent")?
        .unwrap_or(0);
    ensure!(parts.next().is_none(), "invalid chain decimal");
    let negative = mantissa.starts_with('-');
    let mantissa = mantissa.strip_prefix(['+', '-']).unwrap_or(mantissa);
    let mut parts = mantissa.split('.');
    let whole = parts.next().unwrap_or_default();
    let fraction = parts.next().unwrap_or_default();
    ensure!(
        parts.next().is_none()
            && !(whole.is_empty() && fraction.is_empty())
            && whole
                .bytes()
                .chain(fraction.bytes())
                .all(|b| b.is_ascii_digit()),
        "invalid chain decimal"
    );
    let numerator = BigInt::parse_bytes(format!("{whole}{fraction}").as_bytes(), 10)
        .context("invalid chain decimal")?;
    if numerator.sign() == Sign::NoSign {
        return Ok(BigRational::from_integer(numerator));
    }
    ensure!(!negative, "invalid chain balance");
    let scale = i64::try_from(fraction.len())?
        .checked_sub(exponent)
        .context("chain decimal exponent overflow")?;
    // Bound allocations from diagnostic strings, independently of protocol gas or amount limits.
    ensure!(
        scale.unsigned_abs() <= 100_000,
        "chain evidence decimal exponent exceeds parser range"
    );
    let power = BigInt::from(10_u32).pow(scale.unsigned_abs() as u32);
    Ok(if scale >= 0 {
        BigRational::new(numerator, power)
    } else {
        BigRational::from_integer(numerator * power)
    })
}

fn accounting(trial: &Value, mode: &str, outcome: &str) -> Result<()> {
    let balances = &trial["balances"];
    fields(balances, BALANCE_FIELDS, true, "chain balances")?;
    let amounts = BALANCE_FIELDS
        .iter()
        .map(|name| Ok((*name, decimal(&balances[*name])?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
    let paid = &amounts["before"] - &amounts["after"];
    ensure!(
        paid == &amounts["burned_after"] - &amounts["burned_before"]
            && paid == &amounts["supply_before"] - &amounts["supply_after"],
        "chain accounting mismatch"
    );
    let zero = BigRational::from_integer(BigInt::from(0));
    ensure!(
        if mode == "paid" {
            paid > zero
        } else {
            paid == zero
        },
        "wrong chain payer charge"
    );
    ensure!(
        amounts["restored"] == amounts["before"]
            && amounts["floor_restored"] == amounts["floor_before"],
        "chain rollback changed balances"
    );
    if mode == "core" && outcome == "ok" {
        ensure!(
            amounts["floor_after"] < amounts["floor_before"],
            "Core overwrite did not remove prior deposit"
        );
    } else {
        ensure!(
            amounts["floor_after"] == amounts["floor_before"],
            "unexpected chain deposit change"
        );
    }
    Ok(())
}

pub fn validate(chains: &Value, target_os: &str, target_arch: &str) -> Result<Value> {
    let chains = chains.as_array().context("missing chain cells")?;
    ensure!(chains.len() == 12, "missing chain cells");
    let mut normalized = BTreeMap::new();
    for chain in chains {
        fields(chain, CHAIN_FIELDS, false, "chain")?;
        let (mode, stores) = key(chain, false)?;
        ensure!(
            !normalized.contains_key(&(mode.clone(), stores)),
            "duplicate chain key"
        );
        ensure!(
            chain["target_os"] == target_os && chain["target_arch"] == target_arch,
            "chain target mismatch"
        );
        ensure!(
            chain["engine_target"] == "pulley64-unknown-unknown-elf",
            "chain engine mismatch"
        );
        ensure!(
            chain["call_hook_installed"] == false,
            "chain enabled a test-only call hook"
        );
        ensure!(
            chain["max_wasm_stack"].as_u64() == Some(524288)
                && chain["async_stack_size"].as_u64() == Some(2097152),
            "chain stack settings mismatch"
        );
        fields(
            &chain["component_sha256"],
            &["error_test", "proxy"],
            true,
            "chain component hashes",
        )?;
        ensure!(
            chain["component_sha256"]
                .as_object()
                .unwrap()
                .values()
                .all(|v| hex_digest(v, 64)),
            "invalid chain component hash"
        );
        let trials = chain["trials"]
            .as_array()
            .context("chain requires three trials")?;
        ensure!(trials.len() == 3, "chain requires three trials");
        for (index, trial) in trials.iter().enumerate() {
            fields(trial, TRIAL_FIELDS, false, "chain trial")?;
            let outcome = if stores == 65 {
                "invocation_limit"
            } else if index == 1 {
                "trap"
            } else {
                "ok"
            };
            ensure!(
                trial["repeat_index"].as_u64() == Some(index as u64),
                "wrong chain repeat index"
            );
            ensure!(
                hex_digest(&trial["state_before_sha256"], 64)
                    && trial["state_after_sha256"] == trial["state_before_sha256"],
                "chain persisted state was not restored"
            );
            ensure!(trial["outcome"] == outcome, "wrong chain outcome");
            let value = if outcome == "ok" {
                json!("42")
            } else {
                Value::Null
            };
            ensure!(trial["value"] == value, "wrong chain result");
            ensure!(
                trial["storage_state"]
                    == if mode != "view" && outcome == "ok" {
                        "[2, 0, 0, 0]"
                    } else {
                        "[0, 0, 0, 0]"
                    },
                "wrong chain state"
            );
            for field in [
                "rolled_back",
                "rollback_clean",
                "savepoint_restored",
                "stack_empty",
            ] {
                ensure!(trial[field] == true, "chain cleanup failed: {field}");
            }
            for field in ["host_io_suspended", "leaf_callback_seen"] {
                ensure!(
                    trial[field] == (stores != 65),
                    "chain host callback mismatch: {field}"
                );
            }
            for field in ["resource_count", "baseline_resource_count", "receipt_count"] {
                number(&trial[field], &format!("chain {field}"))?;
            }
            ensure!(
                trial["resource_count"] == trial["baseline_resource_count"],
                "chain resources leaked"
            );
            ensure!(
                trial["receipt_count"]
                    == if mode == "view" {
                        0
                    } else if outcome == "ok" {
                        stores
                    } else {
                        1
                    },
                "wrong chain receipt count"
            );
            let receipt = &trial["receipt"];
            if mode == "view" {
                ensure!(receipt.is_null(), "view chain persisted a receipt");
            } else {
                fields(
                    receipt,
                    &["contract_id", "status", "gas", "value"],
                    true,
                    "chain receipt",
                )?;
                number(&receipt["contract_id"], "chain receipt contract")?;
                ensure!(
                    receipt["status"] == if outcome == "ok" { "Ok" } else { "Other" },
                    "wrong chain receipt status"
                );
                ensure!(
                    number(&receipt["gas"], "chain receipt gas")? > 0,
                    "invalid chain receipt gas"
                );
                ensure!(receipt["value"] == value, "wrong chain receipt value");
            }
            fields(
                &trial["fuel"],
                &["user", "system", "deposit"],
                true,
                "chain fuel",
            )?;
            for fuel in trial["fuel"].as_object().unwrap().values() {
                number(fuel, "chain fuel")?;
            }
            ensure!(
                trial["fuel"][if mode == "paid" { "user" } else { "system" }]
                    .as_u64()
                    .unwrap()
                    > 0,
                "chain fuel missing from expected category"
            );
            accounting(trial, &mode, outcome)?;
        }
        if stores == 65 {
            let repeated: Vec<Value> = trials
                .iter()
                .map(|trial| {
                    trial
                        .as_object()
                        .unwrap()
                        .iter()
                        .filter(|(key, _)| *key != "repeat_index")
                        .map(|(k, v)| (k.clone(), v.clone()))
                        .collect()
                })
                .collect();
            ensure!(
                repeated[0] == repeated[1] && repeated[1] == repeated[2],
                "over-cap chain trials differ"
            );
        }
        let result: Value = chain
            .as_object()
            .unwrap()
            .iter()
            .filter(|(k, _)| !["target_os", "target_arch"].contains(&k.as_str()))
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect();
        normalized.insert((mode, stores), result);
    }
    Ok(Value::Array(normalized.into_values().collect()))
}

pub fn validate_owned(
    owned: &Value,
    chains: &Value,
    target_os: &str,
    target_arch: &str,
) -> Result<Value> {
    validate(chains, target_os, target_arch)?;
    let owned = owned.as_array().context("missing owned chain cells")?;
    ensure!(owned.len() == 6, "missing owned chain cells");
    let mut oracle = BTreeMap::new();
    for chain in chains.as_array().context("missing chain oracle")? {
        let key = key(chain, false)?;
        ensure!(
            oracle.insert(key, chain).is_none(),
            "duplicate chain oracle key"
        );
    }
    let mut normalized = BTreeMap::new();
    let mut seen = BTreeSet::new();
    for chain in owned {
        fields(chain, CHAIN_FIELDS, false, "owned chain")?;
        let (mode, stores) = key(chain, true)?;
        ensure!(
            seen.insert((mode.clone(), stores)),
            "duplicate owned chain key"
        );
        let reference = oracle
            .get(&(mode.clone(), stores))
            .context("missing owned chain oracle")?;
        ensure!(
            chain["target_os"] == target_os && chain["target_arch"] == target_arch,
            "owned chain target mismatch"
        );
        for field in [
            "component_sha256",
            "engine_target",
            "max_wasm_stack",
            "async_stack_size",
            "call_hook_installed",
        ] {
            ensure!(
                chain[field] == reference[field],
                "owned chain: {field} differs"
            );
        }
        let trials = chain["trials"]
            .as_array()
            .context("missing owned boundary trial")?;
        ensure!(trials.len() == 1, "missing owned boundary trial");
        let trial = &trials[0];
        fields(trial, TRIAL_FIELDS, false, "owned chain trial")?;
        let owner = &trial["ownership"];
        let expected = json!({"kind": if mode == "view" { "api" } else { "canonical" }, "fuel_yield_interval": if mode == "view" { json!(100_000) } else { Value::Null }, "registered_peak": stores.min(64)});
        ensure!(
            *owner == expected,
            "owned chain: wrong owner policy or descendant count"
        );
        let first = reference["trials"]
            .as_array()
            .and_then(|t| t.first())
            .context("missing chain oracle trial")?;
        fields(first, TRIAL_FIELDS, false, "chain oracle trial")?;
        for field in TRIAL_FIELDS {
            ensure!(
                trial[*field] == first[*field],
                "owned chain: {field} differs from unowned oracle"
            );
        }
        normalized.insert((mode.clone(), stores), json!({"mode":mode,"stores":stores,"trial":selected(trial,TRIAL_FIELDS),"ownership":owner}));
    }
    Ok(Value::Array(normalized.into_values().collect()))
}

#[cfg(test)]
pub(super) mod tests;
