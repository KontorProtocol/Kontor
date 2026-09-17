use std::char::{DecodeUtf16Error, decode_utf16};
use std::str::{Utf8Error, from_utf8};

use anyhow::{Result, anyhow};
use wasmtime::component::{Accessor, Component, Linker, Val};
use wasmtime::{Error, OutOfMemory};

use crate::runtime::{ExecutionError, Runtime};
use crate::test_utils::test_runtime;

const BUDGET: u64 = 100_000;
const ALLOCATION_ERROR: &str = "too much data is being copied between the host and the guest: fuel allocated for hostcalls has been exhausted";
const BOUNDS_ERROR: &str = "string pointer/length out of bounds of memory";
const ALIGNMENT_ERROR: &str = "string pointer not aligned to 2";

#[tokio::test]
async fn actual_wasmtime_conversion_errors_match_the_compatibility_adapter() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    for fixture in [
        include_str!("fixtures/abi-string-return.wat"),
        include_str!("fixtures/abi-async-string-return.wat"),
    ] {
        for (encoding, ptr, len, allowance, expected) in [
            ("", 0, 8, 8, "valid"),
            ("", 0, 8, 7, ALLOCATION_ERROR),
            ("", 8, 1, 8, "utf8"),
            ("", 65535, 8, 8, BOUNDS_ERROR),
            (" string-encoding=utf16", 16, 1, 8, "utf16"),
            (" string-encoding=utf16", 1, 1, 8, ALIGNMENT_ERROR),
        ] {
            let wat = fixture.replace("(memory $", &format!("{encoding} (memory $"));
            let component = Component::new(&runtime.engine, wat)?;
            let mut store = runtime.make_store(BUDGET)?;
            store.set_hostcall_fuel(allowance);
            let instance = Linker::new(&runtime.engine)
                .instantiate_async(&mut store, &component)
                .await?;
            let func = instance.get_func(&mut store, "run").unwrap();
            let mut results = [Val::Bool(false)];
            let result = func
                .call_async(&mut store, &[Val::U32(ptr), Val::U32(len)], &mut results)
                .await;
            if expected == "valid" {
                result?;
                assert_eq!(results[0], Val::String("abcdefgh".into()));
                continue;
            }
            let error = result.unwrap_err();
            assert!(!error.is::<anyhow::Error>(), "{error:?}");
            match expected {
                "utf8" => assert!(error.root_cause().is::<Utf8Error>()),
                "utf16" => assert!(error.root_cause().is::<DecodeUtf16Error>()),
                message => assert_eq!(error.root_cause().to_string(), message),
            }
            let classified = Runtime::decode_result(
                false,
                Ok(Err(error.context("conversion"))),
                results.to_vec(),
                &mut store,
            )
            .await;
            assert!(
                matches!(classified, Err(ExecutionError::Deterministic(_))),
                "{expected}: {classified:?}"
            );
        }
    }
    Ok(())
}

wasmtime::component::bindgen!({
    inline: "package test:abi; world abi-host-errors { import fail: async func(kind: u32); }",
    anyhow: true,
    imports: { default: async | store | trappable },
});

impl AbiHostErrorsImports for Runtime {}

impl<T> AbiHostErrorsImportsWithStore<T> for Runtime {
    async fn fail(_accessor: &Accessor<T, Self>, kind: u32) -> Result<()> {
        tokio::task::yield_now().await;
        Err(match kind {
            0 => anyhow!(ALLOCATION_ERROR),
            1 => anyhow!(BOUNDS_ERROR),
            2 => anyhow!(ALIGNMENT_ERROR),
            3 => from_utf8(&[0xf0 | kind as u8]).unwrap_err().into(),
            4 => decode_utf16([0xd800]).next().unwrap().unwrap_err().into(),
            5 => OutOfMemory::new(1024).into(),
            _ => anyhow!("unknown host failure"),
        })
    }
}

#[tokio::test]
async fn generated_host_errors_cannot_impersonate_conversion_failures() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let component = Component::new(
        &runtime.engine,
        include_str!("fixtures/abi-host-errors.wat"),
    )?;
    let mut linker = Linker::new(&runtime.engine);
    AbiHostErrors::add_to_linker::<_, Runtime>(&mut linker, |runtime| runtime)?;
    for kind in 0..7 {
        let mut store = runtime.make_store(BUDGET)?;
        let instance = linker.instantiate_async(&mut store, &component).await?;
        let func = instance.get_func(&mut store, "run").unwrap();
        let mut results = [Val::Bool(false)];
        let mut error = func
            .call_async(&mut store, &[Val::U32(kind)], &mut results)
            .await
            .unwrap_err();
        assert!(error.is::<anyhow::Error>(), "{error:?}");
        for _ in 0..3 {
            let classified =
                Runtime::decode_result(false, Ok(Err(error)), results.to_vec(), &mut store).await;
            assert!(
                matches!(classified, Err(ExecutionError::NonDeterministic(_))),
                "kind {kind}: {classified:?}"
            );
            error = Error::from_anyhow(classified.unwrap_err().into());
        }
    }
    Ok(())
}

#[tokio::test]
async fn unknown_engine_errors_and_near_matches_remain_infrastructure_failures() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    for error in [
        Error::msg("unknown engine failure"),
        Error::msg(format!("{ALLOCATION_ERROR}!")),
        Error::msg(format!("prefix: {BOUNDS_ERROR}")),
        Error::msg("unknown engine failure").context(ALLOCATION_ERROR),
        Error::from(OutOfMemory::new(1024)).context(ALLOCATION_ERROR),
    ] {
        let mut store = runtime.make_store(BUDGET)?;
        let classified = Runtime::decode_result(false, Ok(Err(error)), vec![], &mut store).await;
        assert!(
            matches!(classified, Err(ExecutionError::NonDeterministic(_))),
            "{classified:?}"
        );
    }
    Ok(())
}
