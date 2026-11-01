use std::io::Read;

use anyhow::{Context, Result, bail, ensure};
use brotli::CompressorReader;
use indexer_types::Payment;
use stdlib::to_wave_expr;
use wasmtime::Trap;
use wit_component::{StringEncoding, embed_component_metadata};
use wit_validator::Validator;

use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{
    ContractAddress, Decimal, ExecutionError, MAX_UNTRUSTED_GAS_LIMIT, TransactionContext,
    native_provenance,
};
use crate::test_utils::test_runtime;

const WIT: &str =
    include_str!("../../../../../../../test-contracts/canonical-probe/wit/contract.wit");
const WAT: &str = include_str!("../../../../../../../test-contracts/canonical-probe/fixture.wat");
const ACTOR_PUBKEY: &str = "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798";

fn fixture_bytes(realloc_body: &str, post_light: &str, post_heavy: &str) -> Result<Vec<u8>> {
    let (validation, resolve) = Validator::validate_str(WIT)?;
    ensure!(validation.is_valid(), "{validation}");
    let package = resolve
        .packages
        .iter()
        .find_map(|(id, package)| {
            (package.name.namespace == "root" && package.name.name == "component").then_some(id)
        })
        .context("canonical fixture package is missing")?;
    let world = resolve.select_world(&[package], Some("root"))?;
    let wat = WAT
        .replace("@@REALLOC_BODY@@", realloc_body)
        .replace("@@POST_LIGHT_BODY@@", post_light)
        .replace("@@POST_HEAVY_BODY@@", post_heavy);
    let mut module = wat::parse_str(&wat)?;
    // These core imports and exports use the legacy names of the committed contracts.
    embed_component_metadata(&mut module, &resolve, world, StringEncoding::UTF8, false)?;
    let mut compressed = Vec::new();
    CompressorReader::new(module.as_slice(), 4096, 5, 22).read_to_end(&mut compressed)?;
    Ok(compressed)
}

pub(super) fn fixture_bytes_for_kind(kind: &str) -> Result<Vec<u8>> {
    match kind {
        "view_canonical_echo" => fixture_bytes("i32.const 64", "", ""),
        "view_canonical_realloc_trap" => fixture_bytes("unreachable", "", ""),
        "view_canonical_realloc_import" => {
            fixture_bytes("i32.const 0 call $contract drop i32.const 64", "", "")
        }
        "paid_canonical_post_light" | "paid_canonical_post_heavy" => fixture_bytes(
            "i32.const 64",
            "i32.const 0 call $contract drop",
            "(local $i i32) (loop $work local.get $i i32.const 1 i32.add local.tee $i i32.const 16384 i32.lt_u br_if $work) i32.const 0 call $contract drop",
        ),
        _ => bail!("unknown canonical fixture kind {kind}"),
    }
}

#[tokio::test]
#[ignore = "run explicitly while validating publishable canonical ABI fixtures"]
async fn publishable_canonical_fixture_smoke() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let signer = Signer::Id(runtime.get_or_create_identity(ACTOR_PUBKEY).await?);
    token::issue_to(
        &mut runtime,
        &Signer::Core(Box::new(Signer::Nobody)),
        HolderRef::from(&signer),
        Decimal::from("100"),
    )
    .await??;
    let payment = Payment {
        signer_id: signer.signer_id().unwrap(),
        gas_limit: MAX_UNTRUSTED_GAS_LIMIT,
    };
    let variants = [
        ("canonical-success", "view_canonical_echo"),
        ("canonical-realloc-trap", "view_canonical_realloc_trap"),
        ("canonical-realloc-import", "view_canonical_realloc_import"),
        ("canonical-post-return", "paid_canonical_post_light"),
    ];
    for (tx_index, (name, kind)) in variants.iter().enumerate() {
        runtime
            .set_context(
                1,
                Some(
                    TransactionContext::builder()
                        .tx_index(u32::try_from(tx_index)?)
                        .build(),
                ),
                None,
                None,
            )
            .await;
        runtime
            .publish(
                &signer,
                payment.clone(),
                name,
                &fixture_bytes_for_kind(kind)?,
                &native_provenance()?,
            )
            .await?;
    }
    runtime.set_context(1, None, None, None).await;
    let address = |index: usize| ContractAddress {
        name: variants[index].0.into(),
        height: 1,
        tx_index: u32::try_from(index).unwrap(),
    };
    for index in 0..variants.len() {
        ensure!(
            runtime
                .storage
                .contract_id(&address(index))
                .await?
                .is_some()
        );
    }
    runtime
        .execute(None, None, &address(0), "view-run(\"ok\")")
        .await?;
    let echo = "native stack: こんにちは";
    let result = runtime
        .execute(
            None,
            None,
            &address(0),
            &format!("view-echo({})", to_wave_expr(echo)),
        )
        .await?;
    ensure!(
        result == to_wave_expr(echo),
        "canonical string roundtrip changed"
    );
    let large_echo = "x".repeat(16_384);
    let result = runtime
        .execute(
            None,
            None,
            &address(0),
            &format!("view-echo({})", to_wave_expr(large_echo.as_str())),
        )
        .await?;
    ensure!(
        result == to_wave_expr(large_echo.as_str()),
        "canonical maximum string roundtrip changed"
    );
    let large_input = format!("view-run({})", to_wave_expr(large_echo.as_str()));
    for (index, trap) in [
        (1, Trap::UnreachableCodeReached),
        (2, Trap::CannotLeaveComponent),
    ] {
        let result = runtime
            .execute(None, None, &address(index), &large_input)
            .await;
        match result {
            Err(ExecutionError::Deterministic(error)) => ensure!(
                error
                    .chain()
                    .any(|cause| cause.downcast_ref::<Trap>() == Some(&trap)),
                "wrong canonical realloc trap: {error:#}"
            ),
            other => bail!("canonical realloc did not trap deterministically: {other:?}"),
        }
    }
    for expression in ["paid-light()", "paid-heavy()"] {
        let result = runtime
            .execute(
                Some(&signer),
                Some(payment.clone()),
                &address(3),
                expression,
            )
            .await;
        match result {
            Err(ExecutionError::Deterministic(error)) => ensure!(
                error
                    .chain()
                    .any(|cause| cause.downcast_ref::<Trap>() == Some(&Trap::CannotLeaveComponent)),
                "wrong canonical post-return trap: {error:#}"
            ),
            other => bail!("canonical post-return did not trap deterministically: {other:?}"),
        }
    }
    ensure!(runtime.stack.is_empty().await);
    ensure!(runtime.storage.savepoint_stack.is_empty().await);
    Ok(())
}
