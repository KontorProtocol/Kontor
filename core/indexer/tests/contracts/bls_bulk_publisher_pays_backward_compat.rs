//! Backward-compat: when a publisher constructs an `AggregateInfo` without
//! explicitly setting `gas_paid_by_publisher` / `publisher_gas_limit_per_op`,
//! e.g. via a JSON / struct-literal path that omits the new fields, the
//! defaults (`false` and `0`) must take effect. This keeps every existing
//! aggregate-construction code path (with two-field `AggregateInfo` literals)
//! working — they now silently fall back to the legacy user-pays behavior.
//!
//! IMPORTANT LIMITATION (postcard ≤ 1.x):
//! `#[serde(default)]` does NOT automatically deserialize OLD postcard
//! payloads (encoded with only the original two fields) into the NEW struct
//! shape. Postcard is non-self-describing and fails with `DeserializeUnexpectedEnd`
//! when the buffer is exhausted before all struct fields are read. See
//! <https://github.com/jamesmunns/postcard/issues/159>. The `#[serde(default)]`
//! attributes still serve two purposes in this codebase:
//! 1. JSON deserialization paths (kontor-ts bindings, ts-rs exports,
//!    `serde_json::from_str`) populate the defaults correctly when fields
//!    are missing.
//! 2. Struct construction in Rust code can use `..` shorthand if the type
//!    ever derives `Default` (it doesn't today).
//!
//! Practical impact: if there are NO existing on-chain payloads using the
//! old 2-field `AggregateInfo` (BLS bulk is a recent feature), then strict
//! wire-level backward-compat is moot. If older payloads exist and need to
//! be replayed from history, a custom `Deserialize` impl would be required.

use anyhow::Result;
use indexer_types::AggregateInfo;
use serde::Serialize;
use testlib::*;

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn bls_bulk_publisher_pays_backward_compat() -> Result<()> {
    // JSON path: `#[serde(default)]` MUST kick in when the new fields are
    // absent from the input. This is the path most third-party clients
    // (kontor-ts, tooling) go through.
    let json_legacy = r#"{
        "signer_ids": [1, 2, 3],
        "signature": []
    }"#;
    let decoded: AggregateInfo = serde_json::from_str(json_legacy)?;
    assert_eq!(decoded.signer_ids, vec![1, 2, 3]);
    assert!(decoded.signature.is_empty());
    assert!(
        !decoded.gas_paid_by_publisher,
        "gas_paid_by_publisher must default to false when absent from JSON"
    );
    assert_eq!(
        decoded.publisher_gas_limit_per_op, 0,
        "publisher_gas_limit_per_op must default to 0 when absent from JSON"
    );

    // JSON path with all fields explicit: round-tripping a current-shape
    // payload preserves both new fields.
    let json_full = r#"{
        "signer_ids": [7],
        "signature": [1, 2],
        "gas_paid_by_publisher": true,
        "publisher_gas_limit_per_op": 50000
    }"#;
    let decoded: AggregateInfo = serde_json::from_str(json_full)?;
    assert!(decoded.gas_paid_by_publisher);
    assert_eq!(decoded.publisher_gas_limit_per_op, 50_000);

    // Postcard round-trip with the new fields: serialize and deserialize
    // a current-shape AggregateInfo to confirm wire-format stability. This
    // also pins the wire layout against accidental field-order changes.
    let current = AggregateInfo {
        signer_ids: vec![42, 43],
        signature: vec![1, 2, 3, 4],
        gas_paid_by_publisher: true,
        publisher_gas_limit_per_op: 7_500,
    };
    let bytes = indexer_types::serialize(&current)?;
    let decoded: AggregateInfo = indexer_types::deserialize(&bytes)?;
    assert_eq!(decoded.signer_ids, current.signer_ids);
    assert_eq!(decoded.signature, current.signature);
    assert!(decoded.gas_paid_by_publisher);
    assert_eq!(decoded.publisher_gas_limit_per_op, 7_500);

    // Postcard regression — document the known limitation explicitly. A
    // payload encoded with only the two original fields CANNOT decode into
    // the new struct shape; postcard's `SeqAccess` errors with
    // `DeserializeUnexpectedEnd` before `#[serde(default)]` can take effect.
    // If a future maintainer adds a custom Deserialize impl that tolerates
    // truncated input, this test will need to flip to `is_ok()` and verify
    // the defaults — until then, we pin the limitation so the regression is
    // intentional rather than accidental.
    #[derive(Serialize)]
    struct LegacyAggregateInfo {
        signer_ids: Vec<u64>,
        signature: Vec<u8>,
    }
    let legacy = LegacyAggregateInfo {
        signer_ids: vec![1, 2],
        signature: vec![9; 4],
    };
    let legacy_bytes = indexer_types::serialize(&legacy)?;
    let decoded: Result<AggregateInfo, _> = indexer_types::deserialize(&legacy_bytes);
    assert!(
        decoded.is_err(),
        "postcard payloads predating the new fields are NOT expected to \
         decode today — see comment above and \
         https://github.com/jamesmunns/postcard/issues/159"
    );

    Ok(())
}
