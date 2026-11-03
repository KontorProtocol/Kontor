use super::*;
use std::path::PathBuf;

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}
fn fixture(name: &str) -> Value {
    serde_json::from_slice(
        &fs::read(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/node-evidence")
                .join(format!("{name}.json")),
        )
        .unwrap(),
    )
    .unwrap()
}
fn verify(name: &str, value: &Value) -> Result<Value> {
    match name {
        "transition" => transition(value, &root(), false),
        "recovery" => recovery(value),
        "authorization" => authorization(value),
        "join" => join(value),
        _ => unreachable!(),
    }
}
fn object_members(value: &Value, pointer: &str, paths: &mut Vec<(String, String)>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                paths.push((pointer.into(), key.clone()));
                object_members(value, &format!("{pointer}/{key}"), paths);
            }
        }
        Value::Array(array) => {
            for (index, value) in array.iter().enumerate() {
                object_members(value, &format!("{pointer}/{index}"), paths);
            }
        }
        _ => {}
    }
}
fn typed_leaves(value: &Value, pointer: &str, paths: &mut Vec<String>) {
    match value {
        Value::Object(object) => {
            for (key, value) in object {
                typed_leaves(value, &format!("{pointer}/{key}"), paths);
            }
        }
        Value::Array(array) => {
            for (index, value) in array.iter().enumerate() {
                typed_leaves(value, &format!("{pointer}/{index}"), paths);
            }
        }
        Value::Bool(_) | Value::Number(_) => paths.push(pointer.into()),
        _ => {}
    }
}
#[test]
fn all_reports_require_complete_nested_evidence_and_exact_types() -> Result<()> {
    for name in ["transition", "recovery", "authorization", "join"] {
        let original = fixture(name);
        verify(name, &original)?;
        for wrong in [
            Value::Null,
            json!([]),
            json!(1),
            json!(false),
            json!("report"),
        ] {
            assert!(verify(name, &wrong).is_err());
        }
        let mut members = Vec::new();
        object_members(&original, "", &mut members);
        for (pointer, key) in members {
            let mut value = original.clone();
            value
                .pointer_mut(&pointer)
                .unwrap()
                .as_object_mut()
                .unwrap()
                .remove(&key);
            assert!(
                verify(name, &value).is_err(),
                "{name}: omitted {pointer}/{key}"
            );
        }
        let mut leaves = Vec::new();
        typed_leaves(&original, "", &mut leaves);
        for pointer in leaves {
            let current = original.pointer(&pointer).unwrap();
            let invalid = if let Some(boolean) = current.as_bool() {
                vec![json!(!boolean), json!(u8::from(boolean))]
            } else {
                vec![json!(true), json!(current.as_u64().unwrap() as f64)]
            };
            for wrong in invalid {
                let mut value = original.clone();
                *value.pointer_mut(&pointer).unwrap() = wrong;
                assert!(
                    verify(name, &value).is_err(),
                    "{name}: wrong type/value at {pointer}"
                );
            }
        }
    }
    Ok(())
}
#[test]
fn live_idle_batches_normalize_only_after_validating_handoffs() -> Result<()> {
    let original = fixture("transition");
    let mut delayed = original.clone();
    delayed["block_decisions"] = json!([1, 4, 7, 11, 14, 18]);
    delayed["closed_decisions"] = json!(18);
    delayed["handoff_heights"] = json!([5, 12, 15]);
    assert_eq!(
        transition(&original, &root(), true)?,
        transition(&delayed, &root(), true)?
    );
    for (key, wrong) in [
        ("block_decisions", json!([1, 4, 7, 7, 14, 18])),
        ("block_decisions", json!([1, 4, 7, 11, 14])),
        ("closed_decisions", json!(17)),
        ("handoff_heights", json!([4, 12, 15])),
        ("handoff_heights", json!([5, 13, 15])),
    ] {
        let mut value = delayed.clone();
        value[key] = wrong;
        assert!(transition(&value, &root(), true).is_err());
    }
    Ok(())
}
#[test]
fn transition_binds_native_artifacts_and_rollback_contexts() {
    let original = fixture("transition");
    for (pointer,wrong) in [
        ("/second_protocol",original["first_protocol"].clone()),
        ("/native_provenance/upgraded/effective_artifact/execution_definition",original["native_provenance"]["publication"]["effective_artifact"]["execution_definition"].clone()),
        ("/native_provenance/upgraded/effective_artifact/sha256",original["native_provenance"]["publication"]["effective_artifact"]["sha256"].clone()),
        ("/native_provenance/upgraded/entries",json!([])),
        ("/client_contexts/1/execution_definition",json!("ff".repeat(32))),
        ("/client_contexts/1/protocol_id",json!("ff".repeat(32))),
        ("/client_contexts/1/simulation_height",json!("2")),
        ("/client_contexts/1/application_ordinal",json!(4)),
        ("/client_contexts/1/application_ordinal",json!("000")),
        ("/client_contexts/1/checkpoint_hash",json!(12)),
        ("/client_contexts/1/checkpoint_hash",json!("not a digest")),
        ("/client_contexts/1/checkpoint_height",Value::Null),
        ("/client_contexts/2/rollback_generation",original["client_contexts"][0]["rollback_generation"].clone()),
        ("/client_contexts/3/lineage",original["client_contexts"][1]["lineage"].clone()),
        ("/state/blocks/0",json!(-1)), ("/state/blocks/1",json!("not a digest")),
    ] {
        let mut value=original.clone(); *value.pointer_mut(pointer).unwrap()=wrong;
        assert!(transition(&value,&root(),false).is_err(),"{pointer}");
    }
}
#[test]
fn recovery_requires_distinct_crashes_replays_support_and_replacement() {
    let original = fixture("recovery");
    for pointer in ["/process_crashes", "/finality_replay"] {
        let mut value = original.clone();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_array_mut()
            .unwrap()
            .reverse();
        assert!(recovery(&value).is_err());
        let mut value = original.clone();
        value
            .pointer_mut(pointer)
            .unwrap()
            .as_array_mut()
            .unwrap()
            .pop();
        assert!(recovery(&value).is_err());
    }
    for (pointer, wrong) in [
        ("/successor_support/scope", json!("live mixed binaries")),
        ("/successor_support/supporting_successor_power", json!(200)),
        ("/empty_successor/closed_decisions", json!(14)),
        ("/token_count/checked_snapshots", json!(6)),
        ("/finality_replay/1/scenario", json!("SurvivingSchedule")),
        ("/finality_replay/0/closed_decisions", json!(7)),
        ("/finality_replay/0/confirmation/closed_decisions", json!(4)),
        (
            "/finality_replay/0/confirmation/replacement/replacement_height",
            json!(2),
        ),
    ] {
        let mut value = original.clone();
        *value.pointer_mut(pointer).unwrap() = wrong;
        assert!(recovery(&value).is_err(), "{pointer}");
    }
}
#[test]
fn successive_upgrades_require_distinct_protocols_and_full_notice() {
    let original = fixture("authorization");
    for (pointer, wrong) in [
        ("/notice_blocks", json!(1007)),
        ("/successive_upgrades/second_notice_blocks", json!(0)),
        ("/successive_upgrades/migration_applications", json!(1)),
        (
            "/successive_upgrades/protocols",
            json!(["11".repeat(32), "22".repeat(32), "22".repeat(32)]),
        ),
        (
            "/successive_upgrades/activation_heights",
            json!([1009, 1009]),
        ),
    ] {
        let mut value = original.clone();
        *value.pointer_mut(pointer).unwrap() = wrong;
        assert!(authorization(&value).is_err(), "{pointer}");
    }
}
#[test]
fn join_requires_progress_before_signing_and_decimal_runtime_height() -> Result<()> {
    let original = fixture("join");
    let mut stalled = original.clone();
    stalled["stalled_without_quorum"] = json!(false);
    assert!(
        join(&stalled)
            .unwrap_err()
            .to_string()
            .contains("join did not verify")
    );
    for (floor, signed) in [(0, 6), (3, 3), (7, 6)] {
        let mut value = original.clone();
        value["verified_floor"] = json!(floor);
        value["signed_decision"] = json!(signed);
        assert!(join(&value).is_err());
    }
    for height in [json!("5"), json!(""), json!("٧"), json!("7.0"), json!(7)] {
        let mut value = original.clone();
        value["promoted_runtime"]["consensus_height"] = height;
        assert!(join(&value).is_err());
    }
    for height in ["00007", "99999999999999999999999999999999999"] {
        let mut value = original.clone();
        value["promoted_runtime"]["consensus_height"] = json!(height);
        assert_eq!(join(&value)?, join(&original)?);
    }
    Ok(())
}
