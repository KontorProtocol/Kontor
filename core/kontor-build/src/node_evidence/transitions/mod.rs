use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};

use super::{field, hashed};
use crate::container::sha256;
use crate::recipes::executor_graphs;

mod constants;
use constants::{
    AUTHORIZATION_FLAGS, BUILD_RECORD_FLAGS, CONFIRMATION_FLAGS, CRASH_FLAGS, CRASH_STAGES,
    EMPTY_SUCCESSOR_FLAGS, JOIN_FLAGS, RECOVERY_FLAGS, REPLACEMENT_FLAGS, REPLAY_FLAGS,
    STATE_TABLES, SUPPORT_FLAGS, TOKEN_COUNT_FLAGS, TRANSITION_FLAGS, UNSUPPORTED_FLAGS,
};

fn section(
    value: &Value,
    flags: &[&str],
    expected: &[(&str, Value)],
    other: &[&str],
    message: &str,
) -> Result<()> {
    let keys: BTreeSet<_> = flags
        .iter()
        .copied()
        .chain(expected.iter().map(|(name, _)| *name))
        .chain(other.iter().copied())
        .collect();
    ensure!(
        value.as_object().is_some_and(|object| object
            .keys()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
            == keys)
            && flags.iter().all(|key| value[*key] == json!(true))
            && expected.iter().all(|(key, expected)| if expected.is_u64() {
                value[*key].as_u64() == expected.as_u64()
            } else {
                &value[*key] == expected
            }),
        "{message}"
    );
    Ok(())
}
fn digest(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}
fn decimal(value: &Value) -> Option<&str> {
    value
        .as_str()
        .filter(|text| !text.is_empty() && text.bytes().all(|byte| byte.is_ascii_digit()))
}
fn decimal_at_least(text: &str, minimum: u64) -> bool {
    let text = text.trim_start_matches('0');
    let minimum = minimum.to_string();
    text.len() > minimum.len() || (text.len() == minimum.len() && text >= minimum.as_str())
}
pub fn join(value: &Value) -> Result<Value> {
    let keys: Vec<_> = JOIN_FLAGS
        .iter()
        .copied()
        .chain([
            "validators",
            "initial_signers",
            "promotion_generation",
            "verified_floor",
            "signed_decision",
            "promoted_runtime",
        ])
        .collect();
    section(
        value,
        &[],
        &[],
        &keys,
        "validator join evidence missing or incomplete",
    )?;
    section(
        value,
        JOIN_FLAGS,
        &[
            ("validators", json!(4)),
            ("initial_signers", json!(3)),
            ("promotion_generation", json!(2)),
        ],
        &["verified_floor", "signed_decision", "promoted_runtime"],
        "validator join did not verify progress before promotion and signing",
    )?;
    let floor = value["verified_floor"]
        .as_u64()
        .context("invalid verified join floor")?;
    let signed = value["signed_decision"]
        .as_u64()
        .context("invalid signed decision")?;
    ensure!(
        floor > 0 && floor < signed,
        "validator join did not verify progress before promotion and signing"
    );
    let runtime = &value["promoted_runtime"];
    section(
        runtime,
        &["committee_member"],
        &[
            ("authority", json!("validator")),
            ("required_join_height", Value::Null),
        ],
        &["consensus_height"],
        "promoted runtime diagnostics are incomplete",
    )?;
    ensure!(
        decimal(&runtime["consensus_height"])
            .is_some_and(|height| decimal_at_least(height, signed)),
        "promoted runtime diagnostics are incomplete"
    );
    let mut result = value.as_object().unwrap().clone();
    // Idle batches can move heights between otherwise equivalent live runs.
    for field in ["verified_floor", "signed_decision", "promoted_runtime"] {
        result.remove(field);
    }
    Ok(Value::Object(result))
}
fn client_contexts(
    contexts: &Value,
    first: &Value,
    second: &Value,
    provenance: &Value,
) -> Result<()> {
    let contexts = contexts
        .as_array()
        .context("four execution-bound client contexts required")?;
    ensure!(
        contexts.len() == 4,
        "four execution-bound client contexts required"
    );
    for (index, item) in contexts.iter().enumerate() {
        let height = index % 2 + 1;
        let label = if index % 2 == 0 {
            "publication"
        } else {
            "upgraded"
        };
        section(
            item,
            &[],
            &[
                (
                    "protocol_id",
                    if index % 2 == 0 {
                        first.clone()
                    } else {
                        second.clone()
                    },
                ),
                (
                    "execution_definition",
                    provenance[label]["effective_artifact"]["execution_definition"].clone(),
                ),
                ("bitcoin_height", json!(height.to_string())),
                ("simulation_height", json!((height + 1).to_string())),
            ],
            &[
                "application_ordinal",
                "lineage",
                "bitcoin_hash",
                "checkpoint_height",
                "checkpoint_hash",
                "receipt_epoch",
                "rollback_generation",
            ],
            "client context does not match execution selection",
        )?;
        ensure!(
            ["lineage","bitcoin_hash","receipt_epoch"].iter().all(|key| digest(&item[*key]))
            && decimal(&item["application_ordinal"]).is_some_and(|text| text.bytes().any(|byte|byte != b'0'))
            && decimal(&item["rollback_generation"]).is_some()
            && (item["checkpoint_height"].is_null() || decimal(&item["checkpoint_height"]).is_some())
            && item["checkpoint_height"].is_null() == item["checkpoint_hash"].is_null()
            // SQLite hex() returns uppercase checkpoint hashes.
            && (item["checkpoint_hash"].is_null() || item["checkpoint_hash"].as_str().is_some_and(|text|digest(&json!(text.to_ascii_lowercase())))),
            "client context does not match execution selection"
        );
    }
    ensure!(
        contexts[0]["rollback_generation"] != contexts[2]["rollback_generation"]
            && contexts[1]["lineage"] != contexts[3]["lineage"],
        "client context did not distinguish rollback and reactivation"
    );
    Ok(())
}
pub fn transition(value: &Value, root: &Path, semantic_only: bool) -> Result<Value> {
    section(
        value,
        TRANSITION_FLAGS,
        &[
            ("validators", json!(3)),
            ("authorization_test", json!(false)),
        ],
        &[
            "closed_decisions",
            "block_decisions",
            "handoff_heights",
            "first_protocol",
            "second_protocol",
            "scope",
            "native_provenance",
            "state",
            "client_contexts",
        ],
        "transition evidence missing or incomplete",
    )?;
    let blocks = field(value, "block_decisions")?
        .as_array()
        .context("transition requires block decisions")?;
    let blocks: Vec<_> = blocks
        .iter()
        .map(|height| height.as_u64().context("invalid certified block decision"))
        .collect::<Result<_>>()?;
    ensure!(
        blocks.len() == 6 && blocks[0] == 1 && blocks.windows(2).all(|pair| pair[0] < pair[1]),
        "transition checks require six ordered certified block decisions"
    );
    let handoffs = [1, 3, 4]
        .into_iter()
        .map(|index| {
            blocks[index]
                .checked_add(1)
                .context("handoff height overflow")
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(
        value["closed_decisions"].as_u64() == Some(blocks[5])
            && value["handoff_heights"] == json!(handoffs),
        "transition checks did not complete with the required scope"
    );
    let first = &value["first_protocol"];
    let second = &value["second_protocol"];
    ensure!(
        digest(first) && digest(second) && first != second,
        "transition must exercise distinct protocol identities"
    );
    let provenance = &value["native_provenance"];
    section(
        provenance,
        &["restored_on_rollback", "unaffected_native_uses_publication"],
        &[],
        &["publication", "upgraded"],
        "transition provenance checks missing",
    )?;
    let recipes = executor_graphs(Some("managed-node"))?;
    let published = sha256(
        &root
            .join(&recipes["first"].source_root)
            .join("core/indexer/src/protocol/v1/native/token.wasm.br"),
    )?;
    for (label, graph, protocol, version, source) in [
        ("publication", "first", first, "v1", "publication"),
        ("upgraded", "observer", second, "v2", "protocol_native"),
    ] {
        let recipe = &recipes[graph];
        let graph_root = root.join(&recipe.source_root);
        let definition = fs::read(
            graph_root
                .join("protocol-bundles")
                .join(&recipe.directory)
                .join("definition.bin"),
        )?;
        let expected = json!({"sha256":sha256(&graph_root.join(format!("core/indexer/src/protocol/{version}/native/token.wasm.br")))?,"published_sha256":published,"source":source,"protocol_id":protocol,"execution_definition":hashed(b"kontor/execution-definition/v1",&definition)});
        section(
            &provenance[label],
            &[],
            &[("effective_artifact", expected)],
            &["entries"],
            &format!("transition {label} does not match the selected executor and native artifact"),
        )?;
    }
    ensure!(
        provenance["publication"]["entries"]
            .as_array()
            .is_some_and(|entries| !entries.is_empty())
            && provenance["publication"]["entries"] == provenance["upgraded"]["entries"],
        "native replacement changed the original publication claims"
    );
    client_contexts(&value["client_contexts"], first, second, provenance)?;
    let state = &value["state"];
    section(
        state,
        &[],
        &[],
        STATE_TABLES,
        "transition application-state comparison is incomplete",
    )?;
    ensure!(
        state
            .as_object()
            .unwrap()
            .values()
            .all(|item| item
                .as_array()
                .is_some_and(|row| row.len() == 2 && row[0].as_u64().is_some() && digest(&row[1]))),
        "transition application-state comparison is incomplete"
    );
    let mut result = value.as_object().unwrap().clone();
    if semantic_only {
        // Compare outcomes after validating C+1, not idle-batch timing between peers.
        for field in [
            "closed_decisions",
            "block_decisions",
            "handoff_heights",
            "client_contexts",
        ] {
            result.remove(field);
        }
    }
    Ok(Value::Object(result))
}
pub fn recovery(value: &Value) -> Result<Value> {
    section(
        value,
        RECOVERY_FLAGS,
        &[
            ("schema", json!(1)),
            ("closed_decisions", json!(1)),
            ("successor_height", json!(2)),
        ],
        &[
            "scope",
            "finality_replay",
            "token_count",
            "empty_successor",
            "successor_support",
            "unsupported_cancel",
            "process_crashes",
            "build_record",
        ],
        "managed recovery evidence missing or incomplete",
    )?;
    section(
        &value["build_record"],
        BUILD_RECORD_FLAGS,
        &[],
        &[],
        "embedded build record verification incomplete",
    )?;
    section(
        &value["unsupported_cancel"],
        UNSUPPORTED_FLAGS,
        &[("validators", json!(1))],
        &[],
        "unsupported-target cancellation evidence missing or incomplete",
    )?;
    let crashes = value["process_crashes"]
        .as_array()
        .context("process-crash checkpoints missing")?;
    ensure!(
        crashes.len() == CRASH_STAGES.len(),
        "process-crash checkpoints missing"
    );
    for (case, stage) in crashes.iter().zip(CRASH_STAGES) {
        section(
            case,
            CRASH_FLAGS,
            &[
                ("stage", json!(stage)),
                ("signature_retry_preserved", json!(*stage == "signed")),
            ],
            &[],
            "process-crash recovery evidence incomplete",
        )?;
    }
    section(
        &value["successor_support"],
        SUPPORT_FLAGS,
        &[
            ("activation_height", json!(13)),
            ("closed_decisions", json!(14)),
            ("old_signed_power", json!(300)),
            ("old_total_power", json!(400)),
            ("supporting_successor_power", json!(100)),
            ("successor_total_power", json!(200)),
            (
                "scope",
                json!("composed support assumption, not live mixed binaries"),
            ),
        ],
        &[],
        "successor support mismatch evidence incomplete",
    )?;
    section(
        &value["empty_successor"],
        EMPTY_SUCCESSOR_FLAGS,
        &[
            ("activation_height", json!(13)),
            ("authenticated_decisions", json!(14)),
            ("closed_decisions", json!(13)),
        ],
        &[],
        "empty successor authority gate evidence missing or incomplete",
    )?;
    section(
        &value["token_count"],
        TOKEN_COUNT_FLAGS,
        &[
            ("checked_snapshots", json!(7)),
            ("closed_decisions", json!(7)),
        ],
        &[],
        "managed token count mutation evidence missing or incomplete",
    )?;
    let cases = value["finality_replay"]
        .as_array()
        .context("managed recovery replay cases missing")?;
    ensure!(cases.len() == 3, "managed recovery replay cases missing");
    for (case, (name, height)) in cases.iter().zip([
        ("SurvivingSchedule", 8),
        ("UndoCancel", 9),
        ("UndoPostpone", 9),
    ]) {
        section(
            case,
            REPLAY_FLAGS,
            &[
                ("scenario", json!(name)),
                ("closed_decisions", json!(height)),
            ],
            if name == "SurvivingSchedule" {
                &["confirmation"]
            } else {
                &[]
            },
            "managed recovery replay case incomplete",
        )?;
        if name == "SurvivingSchedule" {
            let confirmation = &case["confirmation"];
            section(
                confirmation,
                CONFIRMATION_FLAGS,
                &[
                    ("confirmation_height", json!(3)),
                    ("closed_decisions", json!(5)),
                ],
                &["replacement"],
                "cross-activation confirmation evidence incomplete",
            )?;
            section(
                &confirmation["replacement"],
                REPLACEMENT_FLAGS,
                &[
                    ("replacement_height", json!(3)),
                    ("finality_height", json!(7)),
                    ("closed_decisions", json!(8)),
                ],
                &[],
                "cross-activation replacement evidence incomplete",
            )?;
        }
    }
    Ok(value.clone())
}
pub fn authorization(value: &Value) -> Result<Value> {
    section(
        value,
        AUTHORIZATION_FLAGS,
        &[
            ("schema", json!(1)),
            ("notice_blocks", json!(1008)),
            ("activation_height", json!(1009)),
            ("closed_decisions", json!(2028)),
        ],
        &["successive_upgrades"],
        "managed authorization replay evidence missing or incomplete",
    )?;
    let successive = &value["successive_upgrades"];
    section(
        successive,
        &[
            "qualification_only_p3",
            "fresh_second_approval",
            "p2_p3_share_executor",
            "reopen_and_genesis_replay_match",
            "node_local_epoch_excluded",
        ],
        &[
            ("second_notice_blocks", json!(1008)),
            ("migration_applications", json!(2)),
            ("closed_decisions", json!(2019)),
            ("activation_heights", json!([1009, 2017])),
        ],
        &["protocols"],
        "two successive authorized upgrades and replay are incomplete",
    )?;
    let protocols = successive["protocols"]
        .as_array()
        .context("successive protocol identities missing")?;
    ensure!(
        protocols.len() == 3
            && protocols.iter().all(digest)
            && protocols
                .iter()
                .filter_map(Value::as_str)
                .collect::<BTreeSet<_>>()
                .len()
                == 3,
        "two successive authorized upgrades and replay are incomplete"
    );
    Ok(value.clone())
}

#[cfg(test)]
mod tests;
