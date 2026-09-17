use std::char::{CharTryFromError, DecodeUtf16Error, decode_utf16};
use std::str::{Utf8Error, from_utf8};

use anyhow::{Result, anyhow};
use wasmtime::component::{Accessor, Component, ComponentType, Lift, Linker, Val};
use wasmtime::{Error, OutOfMemory};

use crate::runtime::{ExecutionError, Runtime};
use crate::test_utils::test_runtime;

const BUDGET: u64 = 100_000;
const ALLOCATION_ERROR: &str = "too much data is being copied between the host and the guest: fuel allocated for hostcalls has been exhausted";
const BOUNDS_ERROR: &str = "string pointer/length out of bounds of memory";
const ALIGNMENT_ERROR: &str = "string pointer not aligned to 2";
const CONVERSION_MESSAGES: &[&str] = &[
    ALLOCATION_ERROR,
    BOUNDS_ERROR,
    ALIGNMENT_ERROR,
    "list pointer/length out of bounds of memory",
    "list pointer is not aligned",
    "return pointer not aligned",
    "pointer out of bounds of memory",
    "realloc return: result not aligned",
    "realloc return: beyond end of memory",
    "discriminant 2 out of range [0..2)",
    "invalid option discriminant",
    "invalid expected discriminant",
    "unexpected discriminant: 2",
];

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

async fn assert_conversion_result(
    runtime: &Runtime,
    wat: &str,
    params: &[Val],
    expected: &str,
) -> Result<()> {
    let component = Component::new(&runtime.engine, wat)?;
    let mut store = runtime.make_store(BUDGET)?;
    let instance = Linker::new(&runtime.engine)
        .instantiate_async(&mut store, &component)
        .await?;
    let func = instance.get_func(&mut store, "run").unwrap();
    let mut results = [Val::Bool(false)];
    let result = func.call_async(&mut store, params, &mut results).await;
    if expected == "valid" {
        result?;
        return Ok(());
    }
    let error = result.unwrap_err();
    assert!(!error.is::<anyhow::Error>(), "{error:?}");
    if expected == "char" {
        assert!(error.root_cause().is::<CharTryFromError>(), "{error:?}");
    } else {
        assert_eq!(error.root_cause().to_string(), expected);
    }
    let mut error = error.context("conversion");
    for _ in 0..3 {
        let classified =
            Runtime::decode_result(false, Ok(Err(error)), results.to_vec(), &mut store).await;
        assert!(
            matches!(classified, Err(ExecutionError::Deterministic(_))),
            "{expected}: {classified:?}"
        );
        error = Error::from_anyhow(classified.unwrap_err().into());
    }
    Ok(())
}

#[tokio::test]
async fn malformed_list_results_are_contract_failures() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    for fixture in [
        include_str!("fixtures/abi-string-return.wat"),
        include_str!("fixtures/abi-async-string-return.wat"),
    ] {
        let wat = fixture.replace("(result string)", "(result (list u32))");
        for (ptr, len, expected) in [
            (0, 1, "valid"),
            (65536, 0, "valid"),
            (65532, 2, "list pointer/length out of bounds of memory"),
            (0, u32::MAX, "list pointer/length out of bounds of memory"),
            (1, 1, "list pointer is not aligned"),
        ] {
            assert_conversion_result(&runtime, &wat, &[Val::U32(ptr), Val::U32(len)], expected)
                .await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn malformed_return_pointers_are_contract_failures() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    for asynchronous in [false, true] {
        // Async returns permit 16 flat values; 17 fields exercise its pointer path.
        let fields = (0..17)
            .map(|i| format!(r#"(field "f{i}" u32)"#))
            .collect::<Vec<_>>()
            .join(" ");
        let definitions = format!(
            r#"(type $record-inner (record {fields}))
            (export $record "record" (type $record-inner))"#
        );
        let wat = if asynchronous {
            format!(
                r#"(component {definitions}
                (core module $memory (memory (export "memory") 1))
                (core instance $memory (instantiate $memory))
                (core func $return (canon task.return (result $record) (memory $memory "memory")))
                (core module $code
                    (import "host" "return" (func $return (param i32)))
                    (func (export "run") (param i32) (result i32)
                        local.get 0 call $return i32.const 0)
                    (func (export "callback") (param i32 i32 i32) (result i32) i32.const 0))
                (core instance $code (instantiate $code
                    (with "host" (instance (export "return" (func $return))))))
                (func (export "run") async (param "ptr" u32) (result $record)
                    (canon lift (core func $code "run") async (memory $memory "memory")
                        (callback (func $code "callback")))))"#
            )
        } else {
            format!(
                r#"(component {definitions}
                (core module $code
                    (memory (export "memory") 1)
                    (func (export "run") (param i32) (result i32) local.get 0))
                (core instance $code (instantiate $code))
                (func (export "run") (param "ptr" u32) (result $record)
                    (canon lift (core func $code "run") (memory $code "memory"))))"#
            )
        };
        for (ptr, expected) in [
            (0, "valid"),
            (65536 - 17 * 4, "valid"),
            (1, "return pointer not aligned"),
            (65532, "pointer out of bounds of memory"),
            (u32::MAX - 3, "pointer out of bounds of memory"),
        ] {
            assert_conversion_result(&runtime, &wat, &[Val::U32(ptr)], expected).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn malformed_tags_and_characters_are_contract_failures() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    for (ty, payload, tag, expected) in [
        ("char", false, 0xd800, "char"),
        ("char", false, 0x110000, "char"),
        (
            "(enum \"a\" \"b\")",
            false,
            2,
            "discriminant 2 out of range [0..2)",
        ),
        (
            "(enum \"a\" \"b\")",
            false,
            u32::MAX,
            "discriminant 4294967295 out of range [0..2)",
        ),
        (
            "(enum \"a\" \"b\" \"c\")",
            false,
            3,
            "discriminant 3 out of range [0..3)",
        ),
        (
            "(variant (case \"a\" u32) (case \"b\"))",
            true,
            2,
            "discriminant 2 out of range [0..2)",
        ),
        (
            "(option u32)",
            true,
            2,
            "discriminant 2 out of range [0..2)",
        ),
        (
            "(result u32 (error u32))",
            true,
            2,
            "discriminant 2 out of range [0..2)",
        ),
    ] {
        let definitions = if ty == "char" {
            String::new()
        } else {
            format!(
                r#"(type $result-inner {ty}) (export $result "result-type" (type $result-inner))"#
            )
        };
        let ty = if ty == "char" { "char" } else { "$result" };
        for asynchronous in [false, true] {
            let wat = if asynchronous {
                let extra_param = if payload { "i32" } else { "" };
                let extra_arg = if payload { "i32.const 0" } else { "" };
                format!(
                    r#"(component {definitions}
                    (core func $return (canon task.return (result {ty})))
                    (core module $code
                        (import "host" "return" (func $return (param i32 {extra_param})))
                        (func (export "run") (param i32) (result i32)
                            local.get 0 {extra_arg} call $return i32.const 0)
                        (func (export "callback") (param i32 i32 i32) (result i32) i32.const 0))
                    (core instance $code (instantiate $code
                        (with "host" (instance (export "return" (func $return))))))
                    (func (export "run") async (param "tag" u32) (result {ty})
                        (canon lift (core func $code "run") async
                            (callback (func $code "callback")))))"#
                )
            } else {
                let body = if payload {
                    "i32.const 64 local.get 0 i32.store i32.const 64"
                } else {
                    "local.get 0"
                };
                format!(
                    r#"(component {definitions}
                    (core module $code
                        (memory (export "memory") 1)
                        (func (export "run") (param i32) (result i32) {body}))
                    (core instance $code (instantiate $code))
                    (func (export "run") (param "tag" u32) (result {ty})
                        (canon lift (core func $code "run") (memory $code "memory"))))"#
                )
            };
            assert_conversion_result(&runtime, &wat, &[Val::U32(0)], "valid").await?;
            assert_conversion_result(&runtime, &wat, &[Val::U32(tag)], expected).await?;
        }
    }
    Ok(())
}

#[tokio::test]
async fn malformed_guest_allocator_results_are_contract_failures() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    for fixture in [
        include_str!("fixtures/abi-realloc.wat"),
        include_str!("fixtures/abi-async-realloc.wat"),
    ] {
        for (ptr, expected) in [
            (64, "valid"),
            (1, "realloc return: result not aligned"),
            (65536, "realloc return: beyond end of memory"),
        ] {
            let wat = fixture.replace("i32.const 64", &format!("i32.const {ptr}"));
            assert_conversion_result(&runtime, &wat, &[Val::List(vec![Val::U32(42)])], expected)
                .await?;
        }
    }
    Ok(())
}

#[derive(Debug, PartialEq, ComponentType, Lift)]
#[component(enum)]
#[repr(u8)]
enum Choice {
    #[component(name = "a")]
    A,
    #[component(name = "b")]
    B,
}

#[derive(Debug, ComponentType, Lift)]
#[component(variant)]
enum Payload {
    #[component(name = "a")]
    A(u32),
    #[component(name = "b")]
    B,
}

#[tokio::test]
async fn typed_tag_conversions_are_contract_failures() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    for (ty, indirect, expected) in [
        ("(option u32)", true, "invalid option discriminant"),
        (
            "(result u32 (error u32))",
            true,
            "invalid expected discriminant",
        ),
        ("(enum \"a\" \"b\")", false, "unexpected discriminant: 2"),
        (
            "(variant (case \"a\" u32) (case \"b\"))",
            true,
            "unexpected discriminant: 2",
        ),
    ] {
        let body = if indirect {
            "i32.const 64 local.get 0 i32.store i32.const 64"
        } else {
            "local.get 0"
        };
        let wat = format!(
            r#"(component
            (type $inner {ty}) (export $result "result-type" (type $inner))
            (core module $code
                (memory (export "memory") 1)
                (func (export "run") (param i32) (result i32) {body}))
            (core instance $code (instantiate $code))
            (func (export "run") (param "tag" u32) (result $result)
                (canon lift (core func $code "run") (memory $code "memory"))))"#
        );
        let component = Component::new(&runtime.engine, wat)?;
        let mut store = runtime.make_store(BUDGET)?;
        let instance = Linker::new(&runtime.engine)
            .instantiate_async(&mut store, &component)
            .await?;
        let error = match expected {
            "invalid option discriminant" => {
                let func = instance.get_typed_func::<(u32,), (Option<u32>,)>(&mut store, "run")?;
                assert_eq!(func.call_async(&mut store, (0,)).await?, (None,));
                func.call_async(&mut store, (2,)).await.unwrap_err()
            }
            "invalid expected discriminant" => {
                let func =
                    instance.get_typed_func::<(u32,), (Result<u32, u32>,)>(&mut store, "run")?;
                assert_eq!(func.call_async(&mut store, (0,)).await?, (Ok(0),));
                func.call_async(&mut store, (2,)).await.unwrap_err()
            }
            _ if indirect => {
                let func = instance.get_typed_func::<(u32,), (Payload,)>(&mut store, "run")?;
                assert!(matches!(
                    func.call_async(&mut store, (0,)).await?,
                    (Payload::A(0),)
                ));
                func.call_async(&mut store, (2,)).await.unwrap_err()
            }
            _ => {
                let func = instance.get_typed_func::<(u32,), (Choice,)>(&mut store, "run")?;
                assert_eq!(func.call_async(&mut store, (0,)).await?, (Choice::A,));
                assert_eq!(func.call_async(&mut store, (1,)).await?, (Choice::B,));
                func.call_async(&mut store, (2,)).await.unwrap_err()
            }
        };
        assert_eq!(error.root_cause().to_string(), expected);
        assert!(!error.is::<anyhow::Error>(), "{error:?}");
        let classified = Runtime::decode_result(false, Ok(Err(error)), vec![], &mut store).await;
        assert!(
            matches!(classified, Err(ExecutionError::Deterministic(_))),
            "{classified:?}"
        );
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
        if let Some(message) = CONVERSION_MESSAGES.get(kind as usize) {
            return Err(anyhow!("{message}"));
        }
        Err(match kind as usize - CONVERSION_MESSAGES.len() {
            0 => from_utf8(&[0xf0 | kind as u8]).unwrap_err().into(),
            1 => decode_utf16([0xd800]).next().unwrap().unwrap_err().into(),
            2 => char::try_from(0xd800_u32).unwrap_err().into(),
            3 => OutOfMemory::new(1024).into(),
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
    for kind in 0..u32::try_from(CONVERSION_MESSAGES.len() + 5)? {
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
    let mut errors = vec![
        Error::msg("unknown engine failure"),
        Error::msg("discriminant 1 out of range [0..2)"),
        Error::msg("discriminant 02 out of range [0..2)"),
        Error::msg("discriminant +2 out of range [0..2)"),
        Error::msg("discriminant 2 out of range [0..02)"),
        Error::msg("discriminant 4294967296 out of range [0..2)"),
        Error::msg("discriminant 2 out of range [0..4294967296)"),
        Error::msg("discriminant two out of range [0..2)"),
        Error::msg("unexpected discriminant: +2"),
        Error::msg("unexpected discriminant: 02"),
        Error::msg("unexpected discriminant: 4294967296"),
        Error::msg("unexpected discriminant: -1"),
        Error::msg(format!("{ALLOCATION_ERROR}!")),
        Error::msg(format!("prefix: {BOUNDS_ERROR}")),
        Error::msg("unknown engine failure").context(ALLOCATION_ERROR),
        Error::from(OutOfMemory::new(1024)).context(ALLOCATION_ERROR),
    ];
    for message in CONVERSION_MESSAGES {
        errors.push(Error::msg(format!("{message}!")));
        errors.push(Error::msg(format!("prefix: {message}")));
        errors.push(Error::msg("unknown engine failure").context(*message));
    }
    for error in errors {
        let mut store = runtime.make_store(BUDGET)?;
        let classified = Runtime::decode_result(false, Ok(Err(error)), vec![], &mut store).await;
        assert!(
            matches!(classified, Err(ExecutionError::NonDeterministic(_))),
            "{classified:?}"
        );
    }
    Ok(())
}
