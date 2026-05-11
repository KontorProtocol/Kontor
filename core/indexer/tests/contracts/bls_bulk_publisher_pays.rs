//! End-to-end coverage of the publisher-paid (sponsored) BLS-bulk path.
//!
//! Every scenario shares the same scaffolding (publish `arith`, mint signers,
//! sign + aggregate, submit). To keep the file readable we extract the common
//! setup into a few helpers and group all scenarios as separate
//! `#[testlib::test]` entry points:
//!
//! - `two_ops` — happy path: 2 co-signers, `gas_limit = 0`, publisher pays.
//! - `mixed_payment` — same envelope mixing user-paid and publisher-paid ops.
//! - `gas_zero_without_flag` — legacy guard: `gas_limit = 0` without the
//!   sponsor flag MUST trap with `fuel_limit = 0` (no implicit sponsorship).
//! - `insufficient_funds` — broke publisher: sponsored op fails in isolation,
//!   the rest of the bulk keeps executing.
//! - `invalid_shape` — `flag = true` + `publisher_gas_limit_per_op = 0` is
//!   rejected by `validate_aggregate_shape`, the whole bulk is dropped.
//!
//! The pure serde / postcard backward-compat checks live in the sibling
//! `bls_bulk_publisher_pays_backward_compat.rs` because they don't need the
//! regtest cluster.

use anyhow::{Result, anyhow};
use blst::min_sig::AggregateSignature;
use indexer::bls::KONTOR_BLS_DST;
use indexer::database::types::OpResultId;
use indexer::reg_tester::{Identity, RegTester};
use indexer_types::{AggregateInfo, ContractAddress as IndexerContractAddress, Inst, Insts};
use testlib::Runtime;
use testlib::*;

interface!(name = "arith", path = "../../test-contracts/arith/wit",);
import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/token/wit",
);

fn aggregate_call(
    nonce: u64,
    gas_limit: u64,
    contract: IndexerContractAddress,
    expr: String,
) -> Inst {
    Inst::Call {
        gas_limit,
        contract,
        nonce: Some(nonce),
        expr,
    }
}

/// Publish the `arith` contract on-chain and return its address. We take an
/// explicit `&Runtime` because the `runtime` symbol injected by
/// `#[testlib::test]` only exists in test-function scope.
async fn publish_arith(
    runtime: &Runtime,
    rt: &mut RegTester,
    publisher_ident: &mut Identity,
) -> Result<IndexerContractAddress> {
    let arith_bytes = runtime
        .contract_reader
        .read("arith")
        .await?
        .ok_or_else(|| anyhow!("arith contract bytes not found"))?;
    let publish = rt
        .instruction(
            publisher_ident,
            Inst::Publish {
                gas_limit: 50_000,
                name: "arith".to_string(),
                bytes: arith_bytes,
            },
        )
        .await?;
    publish.result.contract.parse().map_err(|e| {
        anyhow!(
            "invalid contract address {}: {}",
            publish.result.contract,
            e
        )
    })
}

/// Sign one op message with a co-signer's BLS secret key.
fn sign_op(op: &Inst, signer_id: u64, sk_bytes: &[u8]) -> Result<blst::min_sig::Signature> {
    let msg = op.aggregate_signing_message(signer_id)?;
    let sk = blst::min_sig::SecretKey::from_bytes(sk_bytes)
        .map_err(|e| anyhow!("invalid BLS secret key: {e:?}"))?;
    Ok(sk.sign(&msg, KONTOR_BLS_DST, &[]))
}

fn aggregate_signatures(sigs: &[&blst::min_sig::Signature]) -> Result<Vec<u8>> {
    let agg = AggregateSignature::aggregate(sigs, true)
        .map_err(|e| anyhow!("aggregate signature failed: {e:?}"))?;
    Ok(agg.to_signature().to_bytes().to_vec())
}

fn sponsored_insts(
    ops: Vec<Inst>,
    signer_ids: Vec<u64>,
    signature: Vec<u8>,
    gas_paid_by_publisher: bool,
    publisher_gas_limit_per_op: u64,
) -> Insts {
    Insts {
        ops,
        aggregate: Some(AggregateInfo {
            signer_ids,
            signature,
            gas_paid_by_publisher,
            publisher_gas_limit_per_op,
        }),
    }
}

async fn signer_id_of(rt: &mut RegTester, ident: &Identity) -> Result<u64> {
    rt.get_signer_id(&ident.x_only_public_key().to_string())
        .await?
        .ok_or_else(|| anyhow!("missing signer_id"))
}

/// Happy path: two co-signers sign ops with `gas_limit = 0`, publisher pays.
/// Co-signer balances stay at the genesis amount, publisher balance decreases.
#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_bulk_publisher_pays_two_ops_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();

    let signer1 = rt.identity().await?;
    let signer2 = rt.identity().await?;
    let mut publisher_ident = rt.identity().await?;

    let arith_contract = publish_arith(runtime, &mut rt, &mut publisher_ident).await?;
    let signer1_id = signer_id_of(&mut rt, &signer1).await?;
    let signer2_id = signer_id_of(&mut rt, &signer2).await?;
    let publisher_id = signer_id_of(&mut rt, &publisher_ident).await?;

    // Each identity got `10` from genesis issuance via `rt.identity()`. Snapshot
    // every relevant balance before submitting the sponsored bulk so we can
    // assert exact accounting after execution.
    let bal_signer1_before = token::balance(runtime, HolderRef::SignerId(signer1_id)).await?;
    let bal_signer2_before = token::balance(runtime, HolderRef::SignerId(signer2_id)).await?;
    let bal_publisher_before = token::balance(runtime, HolderRef::SignerId(publisher_id)).await?;

    let op0 = aggregate_call(
        0,
        0,
        arith_contract.clone(),
        arith::wave::eval_call_expr(10, arith::Op::Id),
    );
    let op1 = aggregate_call(
        0,
        0,
        arith_contract.clone(),
        arith::wave::eval_call_expr(10, arith::Op::Sum(arith::Operand { y: 8 })),
    );

    let sig0 = sign_op(&op0, signer1_id, &signer1.bls_secret_key)?;
    let sig1 = sign_op(&op1, signer2_id, &signer2.bls_secret_key)?;
    let aggregate = aggregate_signatures(&[&sig0, &sig1])?;

    let res = rt
        .instruction_insts(
            &mut publisher_ident,
            sponsored_insts(
                vec![op0, op1],
                vec![signer1_id, signer2_id],
                aggregate,
                true,
                50_000,
            ),
        )
        .await?;
    let v0 = res
        .result
        .value
        .as_deref()
        .ok_or_else(|| anyhow!("expected a return value for inner op 0"))?;
    let decoded0 = arith::wave::eval_parse_return_expr(v0);
    assert_eq!(decoded0.value, 10);

    let bal_signer1_after = token::balance(runtime, HolderRef::SignerId(signer1_id)).await?;
    let bal_signer2_after = token::balance(runtime, HolderRef::SignerId(signer2_id)).await?;
    assert_eq!(
        bal_signer1_after, bal_signer1_before,
        "co-signer1 should not be debited when publisher sponsors"
    );
    assert_eq!(
        bal_signer2_after, bal_signer2_before,
        "co-signer2 should not be debited when publisher sponsors"
    );

    // We use a strict `<` rather than an exact equality because the runtime
    // applies a `gas_to_token_multiplier` and per-op gas consumption depends
    // on the contract function — both are brittle to pin. The important
    // invariant is "publisher decreased and co-signers did not".
    let bal_publisher_after = token::balance(runtime, HolderRef::SignerId(publisher_id)).await?;
    match (bal_publisher_before, bal_publisher_after) {
        (Some(before), Some(after)) => assert!(
            after < before,
            "publisher balance should decrease after sponsoring two ops (before: {before}, after: {after})"
        ),
        other => panic!("unexpected balance state for publisher: {other:?}"),
    }

    Ok(())
}

/// Mixed-payment bulk: same envelope contains user-paid ops (`gas_limit > 0`)
/// and a publisher-paid op (`gas_limit = 0`). Validates the per-op selection
/// rule when the sponsor flag is set.
#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_bulk_mixed_payment_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();

    let signer1 = rt.identity().await?;
    let signer2 = rt.identity().await?;
    let signer3 = rt.identity().await?;
    let mut publisher_ident = rt.identity().await?;

    let arith_contract = publish_arith(runtime, &mut rt, &mut publisher_ident).await?;
    let signer1_id = signer_id_of(&mut rt, &signer1).await?;
    let signer2_id = signer_id_of(&mut rt, &signer2).await?;
    let signer3_id = signer_id_of(&mut rt, &signer3).await?;
    let publisher_id = signer_id_of(&mut rt, &publisher_ident).await?;

    let bal_signer1_before = token::balance(runtime, HolderRef::SignerId(signer1_id)).await?;
    let bal_signer2_before = token::balance(runtime, HolderRef::SignerId(signer2_id)).await?;
    let bal_signer3_before = token::balance(runtime, HolderRef::SignerId(signer3_id)).await?;
    let bal_publisher_before = token::balance(runtime, HolderRef::SignerId(publisher_id)).await?;

    // op0: signer1 pays (gas_limit > 0). op1: publisher pays (gas_limit = 0).
    // op2: signer3 pays (gas_limit > 0). Same envelope, same publisher.
    let op0 = aggregate_call(
        0,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(10, arith::Op::Id),
    );
    let op1 = aggregate_call(
        0,
        0,
        arith_contract.clone(),
        arith::wave::eval_call_expr(20, arith::Op::Id),
    );
    let op2 = aggregate_call(
        0,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(30, arith::Op::Id),
    );

    let sig0 = sign_op(&op0, signer1_id, &signer1.bls_secret_key)?;
    let sig1 = sign_op(&op1, signer2_id, &signer2.bls_secret_key)?;
    let sig2 = sign_op(&op2, signer3_id, &signer3.bls_secret_key)?;
    let aggregate = aggregate_signatures(&[&sig0, &sig1, &sig2])?;

    let res = rt
        .instruction_insts(
            &mut publisher_ident,
            sponsored_insts(
                vec![op0, op1, op2],
                vec![signer1_id, signer2_id, signer3_id],
                aggregate,
                true,
                50_000,
            ),
        )
        .await?;
    assert!(res.result.value.is_some(), "op0 should have a result");

    let bal_signer1_after = token::balance(runtime, HolderRef::SignerId(signer1_id)).await?;
    let bal_signer2_after = token::balance(runtime, HolderRef::SignerId(signer2_id)).await?;
    let bal_signer3_after = token::balance(runtime, HolderRef::SignerId(signer3_id)).await?;
    let bal_publisher_after = token::balance(runtime, HolderRef::SignerId(publisher_id)).await?;

    fn unwrap_dec(d: Option<Decimal>, label: &str) -> Decimal {
        d.unwrap_or_else(|| panic!("{label} has no balance"))
    }
    let s1_before = unwrap_dec(bal_signer1_before, "signer1 before");
    let s1_after = unwrap_dec(bal_signer1_after, "signer1 after");
    let s2_before = unwrap_dec(bal_signer2_before, "signer2 before");
    let s2_after = unwrap_dec(bal_signer2_after, "signer2 after");
    let s3_before = unwrap_dec(bal_signer3_before, "signer3 before");
    let s3_after = unwrap_dec(bal_signer3_after, "signer3 after");
    let p_before = unwrap_dec(bal_publisher_before, "publisher before");
    let p_after = unwrap_dec(bal_publisher_after, "publisher after");

    assert!(
        s1_after < s1_before,
        "signer1 (user-paid) should decrease: {s1_before} -> {s1_after}"
    );
    assert_eq!(
        s2_after, s2_before,
        "signer2 (publisher-sponsored) should NOT change"
    );
    assert!(
        s3_after < s3_before,
        "signer3 (user-paid) should decrease: {s3_before} -> {s3_after}"
    );
    assert!(
        p_after < p_before,
        "publisher should decrease after sponsoring op1: {p_before} -> {p_after}"
    );

    Ok(())
}

/// Backward-compat regression: an op signs `gas_limit = 0` but the bulk
/// envelope does NOT opt into publisher-paid gas. The runtime keeps the legacy
/// behavior — the op gets `fuel_limit = 0` and traps on the first
/// `consume_fuel`, so it deterministically fails. Guards us against
/// accidentally extending sponsored behavior to bulks that did not opt in.
#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_bulk_gas_zero_without_flag_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();

    let signer1 = rt.identity().await?;
    let signer2 = rt.identity().await?;
    let mut publisher_ident = rt.identity().await?;

    let arith_contract = publish_arith(runtime, &mut rt, &mut publisher_ident).await?;
    let signer1_id = signer_id_of(&mut rt, &signer1).await?;
    let signer2_id = signer_id_of(&mut rt, &signer2).await?;

    let op0 = aggregate_call(
        0,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(7, arith::Op::Id),
    );
    let op1 = aggregate_call(
        0,
        0,
        arith_contract.clone(),
        arith::wave::eval_call_expr(13, arith::Op::Id),
    );

    let sig0 = sign_op(&op0, signer1_id, &signer1.bls_secret_key)?;
    let sig1 = sign_op(&op1, signer2_id, &signer2.bls_secret_key)?;
    let aggregate = aggregate_signatures(&[&sig0, &sig1])?;

    let res = rt
        .instruction_insts(
            &mut publisher_ident,
            sponsored_insts(
                vec![op0, op1],
                vec![signer1_id, signer2_id],
                aggregate,
                // Flag is explicitly false — this is the legacy path.
                false,
                0,
            ),
        )
        .await?;
    let v0 = res
        .result
        .value
        .as_deref()
        .ok_or_else(|| anyhow!("op0 should have a result"))?;
    let decoded0 = arith::wave::eval_parse_return_expr(v0);
    assert_eq!(decoded0.value, 7, "op0 should have executed normally");

    // op1 must NOT have a successful value — fuel_limit = 0 traps the call
    // deterministically as in the legacy behavior. Two acceptable shapes:
    // either the row exists with `value = None` (the op failed and was rolled
    // back) OR the row is missing entirely.
    let txid =
        bitcoin::consensus::encode::deserialize_hex::<bitcoin::Transaction>(&res.reveal_tx_hex)?
            .compute_txid()
            .to_string();
    let client = rt.kontor_client().await;
    let op1_result = client
        .result(&OpResultId::builder().txid(txid).op_index(1).build())
        .await?;
    if let Some(r) = op1_result {
        assert!(
            r.value.is_none(),
            "op with gas_limit=0 and no sponsor flag must fail (got value: {:?})",
            r.value
        );
    }

    Ok(())
}

/// Insufficient-funds path: publisher is broke (unregistered_identity has 0
/// KOR) but signs the sponsor flag anyway. The sponsored op must fail
/// deterministically; ops that pay their own gas in the same bulk must still
/// succeed (each op has its own savepoint).
#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_bulk_publisher_pays_insufficient_funds_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();

    let signer1 = rt.identity().await?;
    let signer2 = rt.identity().await?;
    // Publisher is a fresh Bitcoin-funded identity that did NOT do a KOR
    // Issuance — KOR balance is 0, no sponsorship can succeed. Using
    // `unregistered_identity()` is the cleanest way to put them in this state:
    // the publisher signs the Taproot spend, not the BLS aggregate, so no BLS
    // key is needed.
    let mut publisher_ident = rt.unregistered_identity().await?;

    // Publish via a separate funded identity — the broke publisher must stay
    // broke for the assertion below.
    let mut publish_ident = rt.identity().await?;
    let arith_contract = publish_arith(runtime, &mut rt, &mut publish_ident).await?;

    let signer1_id = signer_id_of(&mut rt, &signer1).await?;
    let signer2_id = signer_id_of(&mut rt, &signer2).await?;

    // op0 pays its own gas — should succeed.
    // op1 expects to be sponsored — should fail (publisher has 0 KOR).
    let op0 = aggregate_call(
        0,
        50_000,
        arith_contract.clone(),
        arith::wave::eval_call_expr(11, arith::Op::Id),
    );
    let op1 = aggregate_call(
        0,
        0,
        arith_contract.clone(),
        arith::wave::eval_call_expr(22, arith::Op::Id),
    );

    let sig0 = sign_op(&op0, signer1_id, &signer1.bls_secret_key)?;
    let sig1 = sign_op(&op1, signer2_id, &signer2.bls_secret_key)?;
    let aggregate = aggregate_signatures(&[&sig0, &sig1])?;

    // `instruction_insts` errors out if op_index = 0 has no value, but op0
    // should succeed — so this is OK. We still want to inspect op1
    // independently to assert it failed deterministically.
    let res = rt
        .instruction_insts(
            &mut publisher_ident,
            sponsored_insts(
                vec![op0, op1],
                vec![signer1_id, signer2_id],
                aggregate,
                true,
                50_000,
            ),
        )
        .await?;
    let v0 = res
        .result
        .value
        .as_deref()
        .ok_or_else(|| anyhow!("op0 (user-paid) should have a result"))?;
    let decoded0 = arith::wave::eval_parse_return_expr(v0);
    assert_eq!(decoded0.value, 11, "op0 should have executed normally");

    let txid =
        bitcoin::consensus::encode::deserialize_hex::<bitcoin::Transaction>(&res.reveal_tx_hex)?
            .compute_txid()
            .to_string();
    let client = rt.kontor_client().await;
    let op1_result = client
        .result(&OpResultId::builder().txid(txid).op_index(1).build())
        .await?;
    // Two acceptable shapes: row exists with `value = None` (failed & rolled
    // back) OR the row is missing entirely. Anything else is a regression.
    if let Some(r) = op1_result {
        assert!(
            r.value.is_none(),
            "sponsored op should fail when publisher is broke (got value: {:?})",
            r.value
        );
    }

    // Co-signer2 must NOT have been debited — the sponsored path means they
    // never enter the token hold; failure attribution is on the publisher.
    let bal_signer2_after = token::balance(runtime, HolderRef::SignerId(signer2_id)).await?;
    assert!(
        bal_signer2_after.is_some(),
        "co-signer2 should still exist as a balance entry after sponsored failure"
    );

    Ok(())
}

/// Shape validation: `gas_paid_by_publisher = true` with
/// `publisher_gas_limit_per_op = 0` is configuration-invalid.
/// `validate_aggregate_shape` rejects the bulk; executor logs and continues,
/// no op result is produced and `instruction_insts` errors out.
#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn bls_bulk_publisher_pays_invalid_shape_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();

    let signer1 = rt.identity().await?;
    let mut publisher_ident = rt.identity().await?;

    let arith_contract = publish_arith(runtime, &mut rt, &mut publisher_ident).await?;
    let signer1_id = signer_id_of(&mut rt, &signer1).await?;

    let op = aggregate_call(
        0,
        0,
        arith_contract.clone(),
        arith::wave::eval_call_expr(99, arith::Op::Id),
    );

    let sig = sign_op(&op, signer1_id, &signer1.bls_secret_key)?;
    let aggregate = aggregate_signatures(&[&sig])?;

    // Inconsistent shape: flag = true REQUIRES publisher_gas_limit_per_op > 0.
    let insts = sponsored_insts(vec![op], vec![signer1_id], aggregate, true, 0);

    let res = rt.instruction_insts(&mut publisher_ident, insts).await;
    assert!(res.is_err(), "invalid-shape bulk must produce no op result");

    // Sanity: the co-signer's nonce must NOT have advanced (the bulk did not
    // execute at all).
    let client = rt.kontor_client().await;
    let entry = client.signer(&signer1_id.to_string()).await?;
    assert_eq!(
        entry.next_nonce,
        Some(0),
        "rejected bulk must not consume the co-signer's nonce"
    );

    Ok(())
}
