use anyhow::Result;
use result_encoder::{
    ENCODER_IMPORT, OUTPUT_IMPORT, PRIVATE_PREFIX, encoder_module, prepare_component,
};
use wasmtime::component::{Component, Linker, Val, WasmList};
use wasmtime::{Config, Engine, Module, Result as WasmResult, Store, Trap};

fn engine() -> Result<Engine> {
    let mut config = Config::new();
    config
        .consume_fuel(true)
        .memory_init_cow(false)
        .wasm_component_model_async(true)
        .wasm_multi_memory(true);
    Ok(Engine::new(&config)?)
}

fn linker(engine: &Engine) -> Result<Linker<Option<String>>> {
    let module = Module::from_binary(engine, &encoder_module()?)?;
    let mut linker = Linker::new(engine);
    linker.root().module(ENCODER_IMPORT, &module)?;
    linker
        .root()
        .func_wrap(OUTPUT_IMPORT, |mut store, (bytes,): (WasmList<u8>,)| {
            store.set_fuel(
                store
                    .get_fuel()?
                    .checked_sub(200 + bytes.len() as u64)
                    .ok_or(Trap::OutOfFuel)?,
            )?;
            let value = String::from_utf8(bytes.as_le_slice(&store).to_vec())?;
            *store.data_mut() = Some(value);
            Ok(())
        })?;
    Ok(linker)
}

async fn compare(wat: &str, name: &str) -> Result<(u64, String)> {
    let engine = engine()?;
    let bytes = wat::parse_str(wat)?;
    let original = Component::from_binary(&engine, &bytes)?;
    let prepared = Component::from_binary(&engine, &prepare_component(&bytes)?)?;
    let linker = linker(&engine)?;
    let mut store = Store::new(&engine, None);
    store.set_fuel(100_000_000)?;
    let instance = linker.instantiate_async(&mut store, &original).await?;
    let mut results = [Val::Bool(false)];
    instance
        .get_func(&mut store, name)
        .unwrap()
        .call_async(&mut store, &[], &mut results)
        .await?;
    let expected = results[0].to_wave()?;
    let mut store = Store::new(&engine, None);
    store.set_fuel(100_000_000)?;
    let instance = linker.instantiate_async(&mut store, &prepared).await?;
    let func = instance.get_typed_func::<(), ()>(&mut store, &format!("{PRIVATE_PREFIX}{name}"))?;
    store.set_fuel(100_000_000)?;
    func.call_async(&mut store, ()).await?;
    assert_eq!(store.data().as_ref().unwrap(), &expected);
    Ok((100_000_000 - store.get_fuel()?, expected))
}

#[tokio::test]
async fn scalar_boundaries() -> Result<()> {
    for (ty, core, value) in [
        ("u32", "i32", "-1"),
        ("s64", "i64", "-9223372036854775808"),
        ("u64", "i64", "-1"),
        ("bool", "i32", "256"),
        ("char", "i32", "129408"),
    ] {
        compare(
            &format!(
                r#"(component
            (core module $m (func (export "read") (result {core}) {core}.const {value}))
            (core instance $m (instantiate $m))
            (func (export "read") (result {ty}) (canon lift (core func $m "read"))))"#
            ),
            "read",
        )
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn unicode_string() -> Result<()> {
    let value = "ascii\n\r\t\0\\\"'é中🦀e\u{301}\u{200d}\u{7f}";
    let data: String = value.bytes().map(|byte| format!("\\{byte:02x}")).collect();
    compare(&format!(r#"(component
        (core module $m
          (memory (export "memory") 1)
          (data (i32.const 64) "{data}")
          (func (export "read") (result i32)
            i32.const 0 i32.const 64 i32.store
            i32.const 4 i32.const {} i32.store i32.const 0))
        (core instance $m (instantiate $m))
        (func (export "read") (result string) (canon lift (core func $m "read") (memory $m "memory"))))"#, value.len()), "read").await?;
    Ok(())
}

#[tokio::test]
async fn cleanup_keeps_component_reentry_restrictions() -> Result<()> {
    let engine = engine()?;
    let bytes = wat::parse_str(
        r#"(component
        (import "host" (func $host))
        (core func $host (canon lower (func $host)))
        (core module $m
          (import "env" "host" (func $host))
          (func (export "read") (result i32) i32.const 42)
          (func (export "cleanup") (param i32) call $host))
        (core instance $m (instantiate $m (with "env" (instance (export "host" (func $host))))))
        (func (export "read") (result u32)
          (canon lift (core func $m "read") (post-return (func $m "cleanup")))))"#,
    )?;
    let mut linker = linker(&engine)?;
    linker
        .root()
        .func_wrap("host", |_, (): ()| -> WasmResult<()> {
            panic!("cleanup must not enter the host")
        })?;
    for prepared in [false, true] {
        let component = Component::from_binary(
            &engine,
            &if prepared {
                prepare_component(&bytes)?
            } else {
                bytes.clone()
            },
        )?;
        let mut store = Store::new(&engine, None);
        store.set_fuel(100_000_000)?;
        let instance = linker.instantiate_async(&mut store, &component).await?;
        let name = if prepared {
            "kontor-encoded-read"
        } else {
            "read"
        };
        let mut results = vec![Val::Bool(false); usize::from(!prepared)];
        let error = instance
            .get_func(&mut store, name)
            .unwrap()
            .call_async(&mut store, &[], &mut results)
            .await
            .unwrap_err();
        assert!(
            matches!(
                error.downcast_ref::<Trap>(),
                Some(Trap::CannotLeaveComponent)
            ),
            "{error:#}"
        );
    }
    Ok(())
}

#[tokio::test]
async fn async_task_return_encodes_before_guest_cleanup() -> Result<()> {
    let engine = engine()?;
    let bytes = wat::parse_str(include_str!("fixtures/async.wat"))?;
    let original = Component::from_binary(&engine, &bytes)?;
    let prepared_bytes = prepare_component(&bytes)?;
    let prepared = Component::from_binary(&engine, &prepared_bytes)?;
    let linker = linker(&engine)?;
    for length in [3, 8192] {
        let mut before = Store::new(&engine, None);
        before.set_fuel(100_000_000)?;
        let instance = linker.instantiate_async(&mut before, &original).await?;
        let mut values = [Val::Bool(false)];
        instance
            .get_func(&mut before, "read")
            .unwrap()
            .call_async(&mut before, &[Val::U32(length)], &mut values)
            .await?;
        let expected = values[0].to_wave()?;
        let mut after = Store::new(&engine, None);
        after.set_fuel(100_000_000)?;
        let instance = linker.instantiate_async(&mut after, &prepared).await?;
        instance
            .get_typed_func::<(u32,), ()>(&mut after, "kontor-encoded-read")?
            .call_async(&mut after, (length,))
            .await?;
        assert_eq!(after.data().as_ref().unwrap(), &expected);
    }
    Ok(())
}

fn page_fixture(
    count: usize,
    next: bool,
    asynchronous: bool,
    malformed: Option<&str>,
) -> Result<String> {
    let mut bytes = vec![0u8; 136 + count * 16];
    let text = 128 + count * 16;
    bytes[text..text + 4].copy_from_slice(b"text");
    let list = text + 4;
    bytes.resize(list + 8, 0);
    let set = |bytes: &mut [u8], offset: usize, value: u32| {
        bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes())
    };
    set(&mut bytes, list, text as u32);
    set(&mut bytes, list + 4, 4);
    set(&mut bytes, 64, text as u32);
    set(&mut bytes, 68, 4);
    set(&mut bytes, 72, 128);
    set(&mut bytes, 76, count as u32);
    bytes[80] = u8::from(next);
    set(&mut bytes, 84, if next { text as u32 } else { u32::MAX });
    set(&mut bytes, 88, if next { 4 } else { u32::MAX });
    for index in 0..count {
        let position = 128 + index * 16;
        set(
            &mut bytes,
            position,
            if index == 0 { u32::MAX } else { index as u32 },
        );
        bytes[position + 4] = (index % 3) as u8;
        let (pointer, length) = match index % 3 {
            0 => (u32::MAX, u32::MAX),
            1 => (text as u32, 4),
            _ => (list as u32, 1),
        };
        set(&mut bytes, position + 8, pointer);
        set(&mut bytes, position + 12, length);
    }
    match malformed {
        Some("option") => bytes[80] = 2,
        Some("variant") => bytes[132] = 3,
        Some("list-length") => set(&mut bytes, 76, u32::MAX),
        Some("list-alignment") => set(&mut bytes, 72, 129),
        Some("utf8") => bytes[text + 3] = 0xff,
        None => {}
        _ => panic!("unknown malformed fixture"),
    }
    let data = bytes
        .iter()
        .map(|byte| format!("\\{byte:02x}"))
        .collect::<String>();
    let types = r#"
        (type $state (variant (case "none") (case "text" string) (case "names" (list string))))
        (import "state" (type $s (eq $state)))
        (type $entry (record (field "id" u32) (field "state" $s)))
        (import "entry" (type $e (eq $entry)))
        (type $page (record (field "label" string) (field "entries" (list $e)) (field "next" (option string))))
        (import "page" (type $p (eq $page)))
    "#;
    let memory = format!(
        r#"(core module $memory (memory (export "memory") 2) (data (i32.const 0) "{data}"))
        (core instance $memory (instantiate $memory))"#
    );
    if asynchronous {
        Ok(format!(
            r#"(component {types} {memory}
          (core func $return (canon task.return (result $p) (memory $memory "memory")))
          (core module $code
            (import "env" "memory" (memory 2))
            (import "env" "return" (func $return (param i32 i32 i32 i32 i32 i32 i32)))
            (func (export "read") (result i32)
              i32.const 64 i32.load i32.const 68 i32.load
              i32.const 72 i32.load i32.const 76 i32.load
              i32.const 80 i32.load8_u i32.const 84 i32.load i32.const 88 i32.load
              call $return i32.const 0)
            (func (export "callback") (param i32 i32 i32) (result i32) i32.const 0))
          (core instance $code (instantiate $code (with "env" (instance
            (export "memory" (memory $memory "memory")) (export "return" (func $return))))))
          (func (export "read") async (result $p) (canon lift (core func $code "read")
            async (memory $memory "memory") (callback (func $code "callback")))))"#
        ))
    } else {
        Ok(format!(
            r#"(component {types} {memory}
          (core module $code (func (export "read") (result i32) i32.const 64))
          (core instance $code (instantiate $code))
          (func (export "read") (result $p) (canon lift (core func $code "read") (memory $memory "memory"))))"#
        ))
    }
}

#[tokio::test]
async fn records_lists_options_and_variants() -> Result<()> {
    for asynchronous in [false, true] {
        for count in [0, 3, 128] {
            for next in [false, true] {
                compare(&page_fixture(count, next, asynchronous, None)?, "read").await?;
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn malformed_results_fail_before_delivery() -> Result<()> {
    let engine = engine()?;
    let linker = linker(&engine)?;
    for asynchronous in [false, true] {
        for malformed in ["option", "variant", "list-length", "list-alignment", "utf8"] {
            let bytes = wat::parse_str(page_fixture(3, true, asynchronous, Some(malformed))?)?;
            for prepared in [false, true] {
                let component = Component::from_binary(
                    &engine,
                    &if prepared {
                        prepare_component(&bytes)?
                    } else {
                        bytes.clone()
                    },
                )?;
                let mut store = Store::new(&engine, None);
                store.set_fuel(100_000_000)?;
                let instance = linker.instantiate_async(&mut store, &component).await?;
                let mut values = vec![Val::Bool(false); usize::from(!prepared)];
                let name = if prepared {
                    "kontor-encoded-read"
                } else {
                    "read"
                };
                let result = instance
                    .get_func(&mut store, name)
                    .unwrap()
                    .call_async(&mut store, &[], &mut values)
                    .await;
                assert!(
                    result.is_err(),
                    "{malformed}, async={asynchronous}, prepared={prepared}"
                );
                assert!(store.data().is_none());
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn async_indirect_result_and_joined_variant_payload() -> Result<()> {
    let fields = (0..20)
        .map(|i| format!("(field \"f{i}\" u32)"))
        .collect::<String>();
    let data = (0u32..20)
        .flat_map(u32::to_le_bytes)
        .map(|b| format!("\\{b:02x}"))
        .collect::<String>();
    compare(&format!(r#"(component
      (type $record (record {fields})) (import "record" (type $r (eq $record)))
      (core module $memory (memory (export "memory") 1) (data (i32.const 64) "{data}"))
      (core instance $memory (instantiate $memory))
      (core func $return (canon task.return (result $r) (memory $memory "memory")))
      (core module $code (import "env" "return" (func $return (param i32)))
        (func (export "read") (result i32) i32.const 64 call $return i32.const 0)
        (func (export "callback") (param i32 i32 i32) (result i32) i32.const 0))
      (core instance $code (instantiate $code (with "env" (instance (export "return" (func $return))))))
      (func (export "read") async (result $r) (canon lift (core func $code "read") async
        (memory $memory "memory") (callback (func $code "callback")))))"#), "read").await?;
    for tag in [0, 1] {
        compare(&format!(r#"(component
          (type $choice (variant (case "wide" u64) (case "small" s8)))
          (import "choice" (type $c (eq $choice)))
          (core module $memory (memory (export "memory") 1))
          (core instance $memory (instantiate $memory))
          (core func $return (canon task.return (result $c) (memory $memory "memory")))
          (core module $code (import "env" "return" (func $return (param i32 i64)))
            (func (export "read") (result i32) i32.const {tag} i64.const -1 call $return i32.const 0)
            (func (export "callback") (param i32 i32 i32) (result i32) i32.const 0))
          (core instance $code (instantiate $code (with "env" (instance (export "return" (func $return))))))
          (func (export "read") async (result $c) (canon lift (core func $code "read") async
            (memory $memory "memory") (callback (func $code "callback")))))"#), "read").await?;
    }
    Ok(())
}

#[tokio::test]
async fn async_rejects_wrong_task_return_type() -> Result<()> {
    let bytes = wat::parse_str(
        r#"(component
      (core func $wrong (canon task.return (result s32)))
      (core module $code (import "env" "wrong" (func $wrong (param i32)))
        (func (export "read") (result i32) i32.const 42 call $wrong i32.const 0)
        (func (export "other") (result i32) i32.const 42 call $wrong i32.const 0)
        (func (export "callback") (param i32 i32 i32) (result i32) i32.const 0))
      (core instance $code (instantiate $code (with "env" (instance (export "wrong" (func $wrong))))))
      (func (export "read") async (result u32) (canon lift (core func $code "read") async (callback (func $code "callback"))))
      (func (export "other") async (result s32) (canon lift (core func $code "other") async (callback (func $code "callback")))))"#,
    )?;
    let engine = engine()?;
    let linker = linker(&engine)?;
    for prepared in [false, true] {
        let component = Component::from_binary(
            &engine,
            &if prepared {
                prepare_component(&bytes)?
            } else {
                bytes.clone()
            },
        )?;
        let mut store = Store::new(&engine, None);
        store.set_fuel(1_000_000)?;
        let instance = linker.instantiate_async(&mut store, &component).await?;
        let name = if prepared {
            "kontor-encoded-read"
        } else {
            "read"
        };
        let mut values = vec![Val::Bool(false); usize::from(!prepared)];
        assert!(
            instance
                .get_func(&mut store, name)
                .unwrap()
                .call_async(&mut store, &[], &mut values)
                .await
                .is_err()
        );
        assert!(store.data().is_none());
    }
    Ok(())
}

#[tokio::test]
async fn alternate_string_encodings() -> Result<()> {
    for (encoding, value, bytes, length) in [
        (
            "utf16",
            "aé🦀",
            "aé🦀"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<_>>(),
            4u32,
        ),
        ("latin1+utf16", "aé", vec![b'a', 0xe9], 2),
        (
            "latin1+utf16",
            "aé🦀",
            "aé🦀".encode_utf16().flat_map(u16::to_le_bytes).collect(),
            0x80000004,
        ),
    ] {
        let data = bytes
            .iter()
            .map(|b| format!("\\{b:02x}"))
            .collect::<String>();
        let (_, result) = compare(&format!(r#"(component
          (core module $m (memory (export "memory") 1) (data (i32.const 64) "{data}")
            (func (export "read") (result i32) i32.const 0 i32.const 64 i32.store
              i32.const 4 i32.const {length} i32.store i32.const 0))
          (core instance $m (instantiate $m))
          (func (export "read") (result string) (canon lift (core func $m "read") (memory $m "memory") string-encoding={encoding})))"#), "read").await?;
        assert_eq!(result, Val::String(value.into()).to_wave()?);
    }
    Ok(())
}

#[tokio::test]
async fn guest_fuel_stops_repeated_payload_amplification() -> Result<()> {
    let engine = engine()?;
    let bytes = wat::parse_str(page_fixture(1024, true, false, None)?)?;
    let component = Component::from_binary(&engine, &prepare_component(&bytes)?)?;
    let linker = linker(&engine)?;
    let mut store = Store::new(&engine, None);
    store.set_fuel(1_000_000)?;
    let instance = linker.instantiate_async(&mut store, &component).await?;
    store.set_fuel(500)?;
    let error = instance
        .get_typed_func::<(), ()>(&mut store, "kontor-encoded-read")?
        .call_async(&mut store, ())
        .await
        .unwrap_err();
    assert!(
        matches!(error.downcast_ref::<Trap>(), Some(Trap::OutOfFuel)),
        "{error:#}"
    );
    assert!(store.data().is_none());
    Ok(())
}

#[tokio::test]
#[ignore = "manual production encoder comparison; run with --ignored --nocapture"]
async fn production_encoder_performance() -> Result<()> {
    let engine = engine()?;
    let linker = linker(&engine)?;
    for (name, wat) in [
        ("ascii-1MiB".to_owned(), string_fixture(&"x".repeat(1_048_576))),
        ("unicode-12KiB".to_owned(), string_fixture(&"é\n".repeat(4096))),
        ("scalar".to_owned(), r#"(component (core module $m (func (export "read") (result i32) i32.const 42))
          (core instance $m (instantiate $m)) (func (export "read") (result u32) (canon lift (core func $m "read"))))"#.to_owned()),
        ("page-128".to_owned(), page_fixture(128, true, false, None)?),
        ("page-4096".to_owned(), page_fixture(4096, true, false, None)?),
        ("async-page-4096".to_owned(), page_fixture(4096, true, true, None)?),
    ] {
        let bytes = wat::parse_str(wat)?;
        let prepared = prepare_component(&bytes)?;
        let before = Component::from_binary(&engine, &bytes)?;
        let after = Component::from_binary(&engine, &prepared)?;
        for fresh in [false, true] {
            let mut stats = Vec::new();
            for (encoded, component) in [(false, &before), (true, &after)] {
                let mut times = Vec::new();
                let mut fuel = 0;
                let mut size = 0;
                let mut store = Store::new(&engine, None);
                store.set_fuel(1_000_000_000)?;
                let mut instance = linker.instantiate_async(&mut store, component).await?;
                for _ in 0..31 {
                    let start = std::time::Instant::now();
                    if fresh {
                        store = Store::new(&engine, None);
                        store.set_fuel(1_000_000_000)?;
                        instance = linker.instantiate_async(&mut store, component).await?;
                    } else { store.set_fuel(1_000_000_000)?; }
                    let name = if encoded { "kontor-encoded-read" } else { "read" };
                    let mut values = vec![Val::Bool(false); usize::from(!encoded)];
                    instance.get_func(&mut store, name).unwrap().call_async(&mut store, &[], &mut values).await?;
                    let result = if encoded { store.data_mut().take().unwrap() } else { values[0].to_wave()? };
                    size = result.len();
                    fuel = 1_000_000_000 - store.get_fuel()?;
                    if !encoded { fuel += 200 + 10 * size as u64 + 50 * nodes(&values[0]); }
                    std::hint::black_box(result);
                    times.push(start.elapsed());
                }
                times.sort();
                stats.push((times[15], fuel, size));
            }
            println!("{name} fresh={fresh} component={}->{}B old={:?} new={:?}", bytes.len(), prepared.len(), stats[0], stats[1]);
        }
    }
    Ok(())
}

fn nodes(value: &Val) -> u64 {
    1 + match value {
        Val::Record(fields) => fields.iter().map(|(_, v)| nodes(v)).sum(),
        Val::List(values) => values.iter().map(nodes).sum(),
        Val::Variant(_, Some(value)) | Val::Option(Some(value)) => nodes(value),
        _ => 0,
    }
}

#[tokio::test]
async fn value_depth_counts_active_payloads() -> Result<()> {
    let engine = engine()?;
    let linker = linker(&engine)?;
    for (depth, active, succeeds) in [(64, true, true), (65, true, false), (65, false, true)] {
        let mut types = String::new();
        let mut inner = "bool".to_owned();
        for i in 0..depth {
            types.push_str(&format!(
                r#"(type $t{i} (option {inner})) (import "t{i}" (type $p{i} (eq $t{i})))"#
            ));
            inner = format!("$p{i}");
        }
        let data = if active {
            "\\01".repeat(depth + 1)
        } else {
            String::new()
        };
        let bytes = wat::parse_str(format!(
            r#"(component {types}
          (core module $m (memory (export "memory") 1) (data (i32.const 64) "{data}")
            (func (export "read") (result i32) i32.const 64))
          (core instance $m (instantiate $m))
          (func (export "read") (result {inner}) (canon lift (core func $m "read") (memory $m "memory"))))"#
        ))?;
        let component = Component::from_binary(&engine, &prepare_component(&bytes)?)?;
        let mut store = Store::new(&engine, None);
        store.set_fuel(1_000_000)?;
        let instance = linker.instantiate_async(&mut store, &component).await?;
        let result = instance
            .get_typed_func::<(), ()>(&mut store, "kontor-encoded-read")?
            .call_async(&mut store, ())
            .await;
        assert_eq!(
            result.is_ok(),
            succeeds,
            "depth={depth}, active={active}: {result:?}"
        );
        if !succeeds {
            assert!(store.data().is_none());
        }
    }
    Ok(())
}

#[tokio::test]
async fn fallback_is_raw_and_unit_results_are_empty() -> Result<()> {
    let engine = engine()?;
    let linker = linker(&engine)?;
    for asynchronous in [false, true] {
        let bytes = wat::parse_str(if asynchronous {
            r#"(component
          (core module $m (memory (export "memory") 1) (data (i32.const 64) "some(42)"))
          (core instance $m (instantiate $m))
          (core func $string (canon task.return (result string) (memory $m "memory")))
          (core func $unit (canon task.return))
          (core module $code
            (import "env" "string" (func $string (param i32 i32)))
            (import "env" "unit" (func $unit))
            (func (export "fallback") (result i32) i32.const 64 i32.const 8 call $string i32.const 0)
            (func (export "finish") (result i32) call $unit i32.const 0)
            (func (export "callback") (param i32 i32 i32) (result i32) i32.const 0))
          (core instance $code (instantiate $code (with "env" (instance (export "string" (func $string)) (export "unit" (func $unit))))))
          (func (export "fallback") async (result string) (canon lift (core func $code "fallback") async (memory $m "memory") (callback (func $code "callback"))))
          (func (export "finish") async (canon lift (core func $code "finish") async (callback (func $code "callback")))))"#
        } else {
            r#"(component
          (core module $m (memory (export "memory") 1) (data (i32.const 64) "some(42)")
            (func (export "fallback") (result i32) i32.const 0 i32.const 64 i32.store i32.const 4 i32.const 8 i32.store i32.const 0)
            (func (export "finish")))
          (core instance $m (instantiate $m))
          (func (export "fallback") (result string) (canon lift (core func $m "fallback") (memory $m "memory")))
          (func (export "finish") (canon lift (core func $m "finish"))))"#
        })?;
        let component = Component::from_binary(&engine, &prepare_component(&bytes)?)?;
        for (name, expected) in [("fallback", "some(42)"), ("finish", "")] {
            let mut store = Store::new(&engine, None);
            store.set_fuel(1_000_000)?;
            let instance = linker.instantiate_async(&mut store, &component).await?;
            instance
                .get_typed_func::<(), ()>(&mut store, &format!("{PRIVATE_PREFIX}{name}"))?
                .call_async(&mut store, ())
                .await?;
            assert_eq!(store.data().as_deref(), Some(expected));
        }
    }
    Ok(())
}

fn string_fixture(value: &str) -> String {
    let pages = (value.len() + 64).div_ceil(65536);
    let data = value
        .bytes()
        .map(|b| format!("\\{b:02x}"))
        .collect::<String>();
    format!(
        r#"(component
      (core module $m (memory (export "memory") {pages}) (data (i32.const 64) "{data}")
        (func (export "read") (result i32) i32.const 0 i32.const 64 i32.store i32.const 4 i32.const {} i32.store i32.const 0))
      (core instance $m (instantiate $m))
      (func (export "read") (result string) (canon lift (core func $m "read") (memory $m "memory"))))"#,
        value.len()
    )
}

#[tokio::test]
async fn async_preserves_memory_and_string_encoding_checks() -> Result<()> {
    let engine = engine()?;
    let linker = linker(&engine)?;
    for (memory, encoding, succeeds) in [
        ("a", "utf16", true),
        ("a", "utf8", false),
        ("b", "utf16", false),
    ] {
        let bytes = wat::parse_str(format!(
            r#"(component
          (core module $m (memory (export "memory") 1) (data (i32.const 64) "a\00b\00"))
          (core instance $a (instantiate $m)) (core instance $b (instantiate $m))
          (core func $return (canon task.return (result string) (memory ${memory} "memory") string-encoding=utf16))
          (core module $code (import "env" "return" (func $return (param i32 i32)))
            (func (export "read") (result i32) i32.const 64 i32.const 2 call $return i32.const 0)
            (func (export "callback") (param i32 i32 i32) (result i32) i32.const 0))
          (core instance $code (instantiate $code (with "env" (instance (export "return" (func $return))))))
          (func (export "read") async (result string) (canon lift (core func $code "read") async
            (memory $a "memory") string-encoding={encoding} (callback (func $code "callback")))))"#
        ))?;
        for prepared in [false, true] {
            let prepared_bytes = if prepared {
                prepare_component(&bytes)
            } else {
                Ok(bytes.clone())
            };
            let component = Component::from_binary(&engine, &prepared_bytes?)?;
            let mut store = Store::new(&engine, None);
            store.set_fuel(1_000_000)?;
            let instance = linker.instantiate_async(&mut store, &component).await?;
            let name = if prepared {
                "kontor-encoded-read"
            } else {
                "read"
            };
            let mut values = vec![Val::Bool(false); usize::from(!prepared)];
            let result = instance
                .get_func(&mut store, name)
                .unwrap()
                .call_async(&mut store, &[], &mut values)
                .await;
            assert_eq!(
                result.is_ok(),
                succeeds,
                "memory={memory}, encoding={encoding}, prepared={prepared}: {result:?}"
            );
            if succeeds && prepared {
                assert_eq!(store.data().as_deref(), Some("\"ab\""));
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn async_failure_after_delivery_matches_original() -> Result<()> {
    let engine = engine()?;
    let linker = linker(&engine)?;
    for tail in ["unreachable", "i32.const 64 i32.const 3 call $return", ""] {
        let source = include_str!("fixtures/async.wat")
            .replace("i32.const 64 i32.const 122 i32.store8", tail);
        let bytes = wat::parse_str(source)?;
        let mut outcomes = Vec::new();
        for prepared in [false, true] {
            let component = Component::from_binary(
                &engine,
                &if prepared {
                    prepare_component(&bytes)?
                } else {
                    bytes.clone()
                },
            )?;
            let mut store = Store::new(&engine, None);
            store.set_fuel(1_000_000)?;
            let instance = linker.instantiate_async(&mut store, &component).await?;
            let name = if prepared {
                "kontor-encoded-read"
            } else {
                "read"
            };
            let mut values = vec![Val::Bool(false); usize::from(!prepared)];
            let result = instance
                .get_func(&mut store, name)
                .unwrap()
                .call_async(&mut store, &[Val::U32(3)], &mut values)
                .await;
            outcomes.push(result.is_ok());
        }
        assert_eq!(outcomes[0], outcomes[1], "{tail}");
        assert_eq!(outcomes[0], tail.is_empty());
    }
    Ok(())
}

#[test]
fn preparation_bounds_shared_schema_expansion() -> Result<()> {
    let fields = (0..128)
        .map(|i| format!("(field \"f{i}\" u32)"))
        .collect::<String>();
    let exports = (0..256).map(|i| format!(r#"(func (export "read-{i}") (result $r) (canon lift (core func $m "read") (memory $m "memory")))"#)).collect::<String>();
    let bytes = wat::parse_str(format!(
        r#"(component
      (type $record (record {fields})) (import "record" (type $r (eq $record)))
      (core module $m (memory (export "memory") 1) (func (export "read") (result i32) i32.const 0))
      (core instance $m (instantiate $m)) {exports})"#
    ))?;
    let error = prepare_component(&bytes).unwrap_err();
    assert!(
        error.to_string().contains("schema budget exceeded"),
        "{error:#}"
    );
    Ok(())
}
