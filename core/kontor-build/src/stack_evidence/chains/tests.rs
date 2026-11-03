use num_bigint::BigInt;
use num_rational::BigRational;
use serde_json::{Value, json};

use super::{decimal, validate, validate_owned};

#[test]
fn decimal_accounting_is_exact_and_rejects_invalid_amounts() {
    let amount = |s: &str| decimal(&json!(s)).unwrap();
    assert_eq!(
        amount("1.000000000000000000000000000001") - amount("1"),
        amount("1e-30")
    );
    assert_eq!(
        amount("1234567890123456789012345678901234567890"),
        BigRational::from_integer(
            BigInt::parse_bytes(b"1234567890123456789012345678901234567890", 10).unwrap()
        )
    );
    assert_eq!(amount("+1_000.000"), amount("1e3"));
    assert_eq!(amount("-0.00"), amount("0"));
    assert_eq!(amount(".5"), amount("5e-1"));
    for value in [
        "NaN",
        "Infinity",
        "-1",
        "",
        ".",
        "1.2.3",
        "1/2",
        "1e100001",
        "1e-9223372036854775808",
    ] {
        assert!(decimal(&json!(value)).is_err(), "{value}");
    }
    for value in [json!(true), json!(1.25), json!(null)] {
        assert!(decimal(&value).is_err());
    }
}

fn fixture() -> (Value, Value) {
    let mut chains = Vec::new();
    let mut owned = Vec::new();
    for mode in ["core", "paid", "view"] {
        for stores in [33, 63, 64, 65] {
            let trials: Vec<_> = (0..3).map(|index| {
                let outcome = if stores == 65 { "invocation_limit" } else if index == 1 { "trap" } else { "ok" };
                let value = if outcome == "ok" { json!("42") } else { Value::Null };
                json!({"outcome": outcome, "value": value,
                    "fuel": {"user": if mode=="paid" {100} else {0}, "system": if mode=="paid" {0} else {100}, "deposit":0},
                    "receipt": if mode=="view" {Value::Null} else {json!({"contract_id": stores+5,"status":if outcome=="ok" {"Ok"} else {"Other"},"gas":10,"value":value})},
                    "repeat_index":index,"state_before_sha256":"1".repeat(64),"state_after_sha256":"1".repeat(64),
                    "receipt_count":if mode=="view" {0} else if outcome=="ok" {stores} else {1},
                    "storage_state":if mode!="view" && outcome=="ok" {"[2, 0, 0, 0]"} else {"[0, 0, 0, 0]"},
                    "rolled_back":true,"resource_count":0,"baseline_resource_count":0,"stack_empty":true,"savepoint_restored":true,"rollback_clean":true,
                    "host_io_suspended":stores!=65,"leaf_callback_seen":stores!=65,
                    "balances":{"before":"100","after":if mode=="paid" {"98.75"} else {"100"},"restored":"100",
                        "burned_before":"5","burned_after":if mode=="paid" {"6.25"} else {"5"},"supply_before":"1000","supply_after":if mode=="paid" {"998.75"} else {"1000"},
                        "floor_before":"10","floor_after":if mode=="core" && outcome=="ok" {"9"} else {"10"},"floor_restored":"10"}})
            }).collect();
            let chain = json!({"mode":mode,"stores":stores,"trials":trials,"component_sha256":{"error_test":"e".repeat(64),"proxy":"f".repeat(64)},
                "engine_target":"pulley64-unknown-unknown-elf","max_wasm_stack":524288,"async_stack_size":2097152,"target_os":"linux","target_arch":"x86_64","call_hook_installed":false});
            if stores >= 64 {
                let mut with_owner = chain.clone();
                let mut trial = trials[0].clone();
                trial["ownership"] = json!({"kind":if mode=="view" {"api"} else {"canonical"},"fuel_yield_interval":if mode=="view" {json!(100000)} else {Value::Null},"registered_peak":64});
                with_owner["trials"] = json!([trial]);
                owned.push(with_owner);
            }
            chains.push(chain);
        }
    }
    (json!(chains), json!(owned))
}

#[test]
fn all_chain_modes_capacities_and_owned_controls_keep_semantics() {
    let (chains, owned) = fixture();
    let normalized = validate(&chains, "linux", "x86_64").unwrap();
    assert_eq!(normalized.as_array().unwrap().len(), 12);
    assert!(normalized[0].get("target_os").is_none());
    let controls = validate_owned(&owned, &chains, "linux", "x86_64").unwrap();
    assert_eq!(controls.as_array().unwrap().len(), 6);
    for (os, arch) in [("linux", "aarch64"), ("macos", "aarch64")] {
        let mut cross = chains.clone();
        let mut cross_owned = owned.clone();
        for chain in cross
            .as_array_mut()
            .unwrap()
            .iter_mut()
            .chain(cross_owned.as_array_mut().unwrap())
        {
            chain["target_os"] = json!(os);
            chain["target_arch"] = json!(arch);
        }
        assert_eq!(validate(&cross, os, arch).unwrap(), normalized);
        assert_eq!(
            validate_owned(&cross_owned, &cross, os, arch).unwrap(),
            controls
        );
    }
    let mut reverse = chains.clone();
    reverse.as_array_mut().unwrap().reverse();
    assert_eq!(validate(&reverse, "linux", "x86_64").unwrap(), normalized);
}

#[test]
fn consistent_accounting_cleanup_receipt_and_identity_mutants_fail() {
    let (chains, _) = fixture();
    for (pointer, value) in [
        ("/0/trials/0/balances/burned_after", json!("7")),
        ("/0/trials/0/rollback_clean", json!(false)),
        ("/0/trials/0/receipt/contract_id", json!(true)),
        ("/0/trials/0/receipt/value", json!("wrong")),
        ("/0/trials/1/repeat_index", json!(0)),
        ("/0/trials/0/state_after_sha256", json!("2".repeat(64))),
        ("/0/trials/0/receipt_count", json!(1)),
        ("/0/trials/0/resource_count", json!(1)),
        ("/0/trials/0/stack_empty", json!(false)),
        ("/0/trials/0/savepoint_restored", json!(false)),
        ("/0/trials/0/host_io_suspended", json!(false)),
        ("/0/trials/0/leaf_callback_seen", json!(false)),
        ("/0/trials/0/fuel/system", json!(0)),
        ("/0/trials/0/fuel/user", json!(false)),
        ("/0/trials/0/balances/floor_after", json!("10")),
        ("/0/trials/1/balances/floor_after", json!("9")),
        ("/4/trials/0/balances/restored", json!("99")),
        ("/4/trials/0/balances/floor_restored", json!("9")),
        ("/8/trials/0/receipt", json!({})),
        ("/0/call_hook_installed", json!(true)),
        ("/0/engine_target", json!("native")),
        ("/0/max_wasm_stack", json!(524288.0)),
        ("/0/component_sha256/error_test", json!("bad")),
        ("/0/stores", json!(32)),
        ("/0/target_os", json!("macos")),
        ("/0/trials/0/outcome", json!("invocation_limit")),
    ] {
        let mut changed = chains.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(validate(&changed, "linux", "x86_64").is_err(), "{pointer}");
    }
    let mut changed = chains.clone();
    changed.as_array_mut().unwrap().pop();
    assert!(validate(&changed, "linux", "x86_64").is_err());
    let mut changed = chains.clone();
    changed[1] = changed[0].clone();
    assert!(validate(&changed, "linux", "x86_64").is_err());
    let mut changed = chains.clone();
    changed[3]["trials"][1]["fuel"]["system"] = json!(101);
    assert!(validate(&changed, "linux", "x86_64").is_err());
}

#[test]
fn sub_precision_accounting_errors_cannot_round_into_success() {
    let (mut chains, _) = fixture();
    for trial in chains[4]["trials"].as_array_mut().unwrap() {
        trial["balances"]["before"] =
            json!("10000000000000000000000000000000000000000.000000000000000000000000000001");
        trial["balances"]["after"] = json!("10000000000000000000000000000000000000000");
        trial["balances"]["restored"] = trial["balances"]["before"].clone();
        trial["balances"]["burned_before"] = json!("0");
        trial["balances"]["burned_after"] = json!("1e-30");
        trial["balances"]["supply_before"] = trial["balances"]["before"].clone();
        trial["balances"]["supply_after"] = trial["balances"]["after"].clone();
    }
    validate(&chains, "linux", "x86_64").unwrap();
    chains[4]["trials"][0]["balances"]["burned_after"] =
        json!("1.000000000000000000000000000001e-30");
    assert!(validate(&chains, "linux", "x86_64").is_err());
}

#[test]
fn owned_controls_reject_shared_regressions_and_incorrect_lifecycle() {
    let (chains, owned) = fixture();
    for (pointer, value) in [
        ("/0/trials/0/fuel/system", json!(101)),
        ("/0/trials/0/ownership/registered_peak", json!(63)),
        ("/0/trials/0/ownership/fuel_yield_interval", json!(100000)),
        ("/4/trials/0/ownership/kind", json!("canonical")),
        ("/0/stores", json!(33)),
        ("/0/trials/0/repeat_index", json!(1)),
        ("/0/target_arch", json!("aarch64")),
    ] {
        let mut changed = owned.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            validate_owned(&changed, &chains, "linux", "x86_64").is_err(),
            "{pointer}"
        );
    }
    let mut changed = owned.clone();
    changed[1] = changed[0].clone();
    assert!(validate_owned(&changed, &chains, "linux", "x86_64").is_err());
    changed = owned.clone();
    changed.as_array_mut().unwrap().pop();
    assert!(validate_owned(&changed, &chains, "linux", "x86_64").is_err());
    let mut bad_oracle = chains.clone();
    let mut bad_owned = owned.clone();
    bad_oracle[2]["trials"][0]["rollback_clean"] = json!(false);
    bad_owned[0]["trials"][0]["rollback_clean"] = json!(false);
    assert!(validate_owned(&bad_owned, &bad_oracle, "linux", "x86_64").is_err());
}
