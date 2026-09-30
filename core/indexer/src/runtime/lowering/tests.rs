use std::sync::{Arc, Mutex};

use anyhow::Result;
use wasmtime::component::{Component, Val};
use wasmtime::{AsContext, AsContextMut, Trap};

use super::{Linker, Lowering, charge};
use crate::runtime::fuel::{FuelDiscriminants, FuelGauge};
use crate::runtime::{Error, Runtime};
use crate::test_utils::test_runtime;

fn component(import: &str, ty: &str, encoding: &str, trap: bool, count: u32) -> String {
    // "get" models async built-ins; the other fixtures use synchronous WIT imports.
    let async_ = if import == "get" { "async" } else { "" };
    let allocate = if trap {
        "unreachable"
    } else {
        "(local $n i32)
         i32.const 16 local.set $n
         loop $work
             local.get $n i32.const 1 i32.sub local.tee $n br_if $work
         end
         i32.const 1024"
    };
    format!(
        r#"(component
            (import "{import}" (func $get {async_} (result {ty})))
            (core module $memory
                (memory (export "memory") 1)
                (func (export "realloc") (param i32 i32 i32 i32) (result i32)
                    {allocate}))
            (core instance $memory (instantiate $memory))
            (core func $get (canon lower (func $get)
                (memory $memory "memory") (realloc (func $memory "realloc")) {encoding}))
            (core module $guest
                (import "host" "memory" (memory 1))
                (import "host" "get" (func $get (param i32)))
                (func (export "run") (result i32) (local $n i32)
                    i32.const {count} local.set $n
                    loop $again
                        i32.const 0 call $get
                        local.get $n i32.const 1 i32.sub local.tee $n br_if $again
                    end
                    i32.const 4 i32.load i32.const 2147483647 i32.and))
            (core instance $guest (instantiate $guest
                (with "host" (instance
                    (export "memory" (memory $memory "memory"))
                    (export "get" (func $get))))))
            (func (export "run") {async_} (result u32) (canon lift (core func $guest "run"))))"#
    )
}

#[tokio::test]
async fn blocking_async_returns_keep_metering_after_linker_clone() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let linker = Linker::<Runtime>::new(&runtime.engine);
    let mut linker = linker.clone();
    linker
        .allow_shadowing(true)
        .root()
        .func_wrap_async("blocking-get", |mut store, (): ()| {
            Box::new(async move {
                tokio::task::yield_now().await;
                store.set_fuel(20)?;
                Ok(("aé𝄞".to_string(),))
            })
        })?;
    let component = Component::new(
        &runtime.engine,
        component("blocking-get", "string", "", true, 1),
    )?;
    let mut store = runtime.make_store(100_000)?;
    let instance = linker.instantiate_async(&mut store, &component).await?;
    let run = instance.get_func(&mut store, "run").unwrap();
    let error = run
        .call_async(&mut store, &[], &mut [Val::U32(0)])
        .await
        .unwrap_err();
    assert_eq!(error.downcast_ref::<Trap>(), Some(&Trap::OutOfFuel));
    assert_eq!(store.get_fuel()?, 20);
    Ok(())
}

#[tokio::test]
async fn string_reservations_precede_allocator_and_survive_its_failure() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let text = "aé𝄞".to_string();
    let charge = text.lowering_bytes()?;
    for budget in [charge - 1, 10_000] {
        let mut linker = Linker::<Runtime>::new(&runtime.engine);
        let text = text.clone();
        let entered = Arc::new(Mutex::new(false));
        let observed = entered.clone();
        linker
            .root()
            .func_wrap_concurrent("get", move |accessor, (): ()| {
                let text = text.clone();
                let observed = observed.clone();
                Box::pin(async move {
                    tokio::task::yield_now().await;
                    let accessor = accessor.with_getter::<Runtime>(|runtime| runtime);
                    *observed.lock().unwrap() = true;
                    accessor.with(|mut access| access.as_context_mut().set_fuel(budget))?;
                    Ok((text,))
                })
            })?;
        let component = Component::new(&runtime.engine, component("get", "string", "", true, 1))?;
        let mut store = runtime.make_store(100_000)?;
        let instance = linker.instantiate_async(&mut store, &component).await?;
        let run = instance.get_func(&mut store, "run").unwrap();
        let error = run
            .call_async(&mut store, &[], &mut [Val::U32(0)])
            .await
            .unwrap_err();
        assert!(
            *entered.lock().unwrap(),
            "must reach the precharge boundary"
        );
        if budget < charge {
            assert_eq!(error.downcast_ref::<Trap>(), Some(&Trap::OutOfFuel));
            assert_eq!(store.get_fuel()?, budget);
        } else {
            assert_eq!(
                error.downcast_ref::<Trap>(),
                Some(&Trap::UnreachableCodeReached)
            );
            assert!(store.get_fuel()? <= budget - charge);
        }
    }
    Ok(())
}

#[tokio::test]
async fn repeated_async_returns_share_fuel_with_allocator_for_all_string_encodings() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    for (encoding, expected_len) in [("utf8", 7), ("utf16", 4), ("latin1+utf16", 4)] {
        let gauge = FuelGauge::with_profiling();
        runtime.gauge = Some(gauge.clone());
        let mut linker = Linker::<Runtime>::new(&runtime.engine);
        let charges = Arc::new(Mutex::new(Vec::new()));
        let observed = charges.clone();
        linker
            .root()
            .func_wrap_concurrent("get", move |accessor, (): ()| {
                let observed = observed.clone();
                Box::pin(async move {
                    tokio::task::yield_now().await;
                    let accessor = accessor.with_getter::<Runtime>(|runtime| runtime);
                    let before = accessor.with(|access| access.as_context().get_fuel())?;
                    observed.lock().unwrap().push(before);
                    Ok(("aé𝄞".to_string(),))
                })
            })?;
        let component = Component::new(
            &runtime.engine,
            component(
                "get",
                "string",
                &format!("string-encoding={encoding}"),
                false,
                2,
            ),
        )?;
        let mut store = runtime.make_store(100_000)?;
        let instance = linker.instantiate_async(&mut store, &component).await?;
        let run = instance.get_func(&mut store, "run").unwrap();
        let mut results = [Val::U32(0)];
        run.call_async(&mut store, &[], &mut results).await?;
        assert_eq!(results, [Val::U32(expected_len)]);
        let charges = charges.lock().unwrap();
        assert_eq!(charges.len(), 2);
        let profile = gauge.report()?.profile.unwrap();
        let stats = &profile.per_type[&FuelDiscriminants::LoweringBytes];
        assert_eq!(stats.consumed_count, 2);
        assert_eq!(stats.consumed_fuel, 42);
        assert!(
            charges[1] < charges[0] - 21,
            "allocator and guest instructions must spend the remaining balance"
        );
        assert!(store.get_fuel()? < charges[1] - 21);
    }
    Ok(())
}

#[tokio::test]
async fn synchronous_byte_returns_reserve_before_guest_allocation() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    for (budget, trap) in [(511, true), (100_000, true), (100_000, false)] {
        let mut linker = Linker::<Runtime>::new(&runtime.engine);
        linker.root().func_wrap("bytes", move |mut store, (): ()| {
            store.set_fuel(budget)?;
            Ok((vec![7_u8; 512],))
        })?;
        let component = Component::new(
            &runtime.engine,
            component("bytes", "(list u8)", "", trap, 1),
        )?;
        let mut store = runtime.make_store(100_000)?;
        let instance = linker.instantiate_async(&mut store, &component).await?;
        let run = instance.get_func(&mut store, "run").unwrap();
        let mut results = [Val::U32(0)];
        let result = run.call_async(&mut store, &[], &mut results).await;
        if budget == 511 {
            assert_eq!(
                result.unwrap_err().downcast_ref::<Trap>(),
                Some(&Trap::OutOfFuel)
            );
            assert_eq!(store.get_fuel()?, budget);
        } else if trap {
            assert_eq!(
                result.unwrap_err().downcast_ref::<Trap>(),
                Some(&Trap::UnreachableCodeReached)
            );
            assert!(store.get_fuel()? <= budget - 512);
        } else {
            result?;
            assert_eq!(results, [Val::U32(512)]);
            assert!(store.get_fuel()? < budget - 512);
        }
    }
    Ok(())
}

#[tokio::test]
async fn error_payloads_and_tuple_reservations_are_atomic() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let value: Result<Option<(Vec<u8>, String)>, Error> = Ok(Some((vec![1, 2], "é".into())));
    let error: Result<u64, Error> = Err(Error::Validation("bad input".into()));
    assert_reservation(&runtime, &value, 8)?;
    assert_reservation(&runtime, &error, 27)?;
    assert_reservation(&runtime, &None::<String>, 0)?;
    assert_reservation(&runtime, &(Vec::new(), String::new()), 0)?;
    Ok(())
}

#[tokio::test]
async fn generated_bindings_charge_returns_without_handler_instrumentation() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let component = Component::new(&runtime.engine, include_str!("generated-bindings.wat"))?;
    for budget in [531, 100_000] {
        let gauge = FuelGauge::with_profiling();
        runtime.gauge = Some(gauge.clone());
        let mut store = runtime.make_store(100_000)?;
        let instance = runtime
            .linkers
            .user
            .instantiate_async(&mut store, &component)
            .await?;
        store.set_fuel(budget)?;
        let run = instance.get_func(&mut store, "run").unwrap();
        let mut results = [Val::U32(0)];
        let result = run.call_async(&mut store, &[], &mut results).await;
        let profile = gauge.report()?.profile.unwrap();
        assert_eq!(
            profile.per_type[&FuelDiscriminants::CryptoHash].consumed_fuel,
            500
        );
        let lowering = &profile.per_type[&FuelDiscriminants::LoweringBytes];
        if budget == 531 {
            assert_eq!(
                result.unwrap_err().downcast_ref::<Trap>(),
                Some(&Trap::OutOfFuel)
            );
            assert_eq!(lowering.rejected_count, 1);
            assert_eq!(lowering.rejected_fuel, 32);
            assert_eq!(lowering.consumed_count, 0);
        } else {
            result?;
            assert_eq!(results, [Val::U32(0xe3 + 32)]);
            assert_eq!(lowering.consumed_count, 1);
            assert_eq!(lowering.consumed_fuel, 32);
            assert_eq!(lowering.rejected_count, 0);
        }
    }
    Ok(())
}

fn assert_reservation(runtime: &Runtime, value: &impl Lowering, cost: u64) -> Result<()> {
    assert_eq!(value.lowering_bytes()?, cost);
    let mut store = runtime.make_store(cost)?;
    charge(store.as_context_mut(), value.lowering_bytes()?)?;
    assert_eq!(store.get_fuel()?, 0);
    if cost != 0 {
        store.set_fuel(cost - 1)?;
        let result = charge(store.as_context_mut(), value.lowering_bytes()?);
        assert_eq!(
            result.unwrap_err().downcast_ref::<Trap>(),
            Some(&Trap::OutOfFuel)
        );
        assert_eq!(store.get_fuel()?, cost - 1);
    }
    Ok(())
}
