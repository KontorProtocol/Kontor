use std::fmt::Debug;
use std::mem::{align_of, size_of};

use anyhow::Result;
use built_in_types::file_registry_types::{ChallengeInput, RawFileDescriptor};
use wasmtime::component::{Component, ComponentType, Lift, Linker, Val};
use wasmtime::{Engine, Store};

use crate::runtime::Runtime;

const FUEL: u64 = 1_000_000;
const ALLOCATION_ERROR: &str = "too much data is being copied between the host and the guest: fuel allocated for hostcalls has been exhausted";

#[test]
fn host_layouts_match_allowance_baseline() {
    fn check<T>(name: &str, size: usize, alignment: usize) {
        assert_eq!(size_of::<T>(), size, "{name}");
        assert_eq!(align_of::<T>(), alignment, "{name}");
        println!("hostcall-layout {name}: size={size} alignment={alignment}");
    }

    // Literal expectations catch changes shared by both CI platforms as well.
    check::<Val>("Val", 48, 8);
    check::<(Val, Val)>("(Val, Val)", 96, 8);
    check::<u8>("u8", 1, 1);
    check::<Vec<u8>>("Vec<u8>", 24, 8);
    check::<(Vec<u8>, u64, u64)>("file tuple", 40, 8);
    check::<(String, Vec<u8>, u64, u64)>("proof file tuple", 64, 8);
    check::<ChallengeInput>("ChallengeInput", 208, 8);
    check::<RawFileDescriptor>("RawFileDescriptor", 136, 8);
}

#[derive(Clone, Copy, Debug)]
enum Boundary {
    SyncResult,
    AsyncResult,
    AsyncImport,
}

struct Fixture {
    name: &'static str,
    declarations: &'static str,
    element: &'static str,
    count: u32,
    memory: Vec<u8>,
}

impl Fixture {
    fn new(name: &'static str, element: &'static str, count: u32) -> Self {
        let mut fixture = Self {
            name,
            declarations: "",
            element,
            count,
            memory: vec![0; 1024],
        };
        fixture.word(0, 64);
        fixture.word(4, count);
        fixture
    }

    fn word(&mut self, offset: usize, value: u32) {
        self.memory[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
    }

    fn bytes(&mut self, offset: usize, value: &[u8]) {
        self.memory[offset..offset + value.len()].copy_from_slice(value);
    }

    fn component(&self, engine: &Engine, boundary: Boundary) -> Result<Component> {
        let data: String = self
            .memory
            .iter()
            .map(|byte| format!("\\{byte:02x}"))
            .collect();
        let element = self.element;
        let count = self.count;
        let memory = format!(
            r#"(core module $memory
                (memory (export "memory") 1)
                (data (i32.const 0) "{data}"))
            (core instance $memory (instantiate $memory))"#
        );
        let body = match boundary {
            Boundary::SyncResult => format!(
                r#"{memory}
                (core module $code
                    (func (export "run") (result i32) i32.const 0))
                (core instance $code (instantiate $code))
                (func (export "run") (result (list {element}))
                    (canon lift (core func $code "run") (memory $memory "memory")))"#
            ),
            Boundary::AsyncResult => format!(
                r#"{memory}
                (core func $return (canon task.return
                    (result (list {element})) (memory $memory "memory")))
                (core module $code
                    (import "host" "return" (func $return (param i32 i32)))
                    (func (export "run") (result i32)
                        i32.const 64 i32.const {count} call $return i32.const 0)
                    (func (export "callback") (param i32 i32 i32) (result i32) i32.const 0))
                (core instance $code (instantiate $code
                    (with "host" (instance (export "return" (func $return))))))
                (func (export "run") async (result (list {element}))
                    (canon lift (core func $code "run") async (memory $memory "memory")
                        (callback (func $code "callback"))))"#
            ),
            Boundary::AsyncImport => format!(
                r#"(import "accept" (func $accept async (param "items" (list {element}))))
                {memory}
                (core func $accept (canon lower (func $accept) (memory $memory "memory")))
                (core func $return (canon task.return))
                (core module $code
                    (import "host" "accept" (func $accept (param i32 i32)))
                    (import "host" "return" (func $return))
                    (func (export "run") (result i32)
                        i32.const 64 i32.const {count} call $accept
                        call $return i32.const 0)
                    (func (export "callback") (param i32 i32 i32) (result i32) i32.const 0))
                (core instance $code (instantiate $code
                    (with "host" (instance
                        (export "accept" (func $accept)) (export "return" (func $return))))))
                (func (export "run") async
                    (canon lift (core func $code "run") async (memory $memory "memory")
                        (callback (func $code "callback"))))"#
            ),
        };
        Ok(Component::new(
            engine,
            format!("(component {} {body})", self.declarations),
        )?)
    }
}

fn store(engine: &Engine, allowance: usize) -> Result<Store<usize>> {
    let mut store = Store::new(engine, 0);
    store.set_fuel(FUEL)?;
    store.set_hostcall_fuel(allowance);
    Ok(store)
}

async fn dynamic_case(fixture: Fixture, expected: Val, allowance: usize) -> Result<()> {
    let engine = Runtime::new_engine()?;
    for boundary in [Boundary::SyncResult, Boundary::AsyncResult] {
        let component = fixture.component(&engine, boundary)?;
        for limit in [allowance.saturating_sub(1), allowance] {
            let mut store = store(&engine, limit)?;
            let instance = Linker::new(&engine)
                .instantiate_async(&mut store, &component)
                .await?;
            let func = instance.get_func(&mut store, "run").unwrap();
            let mut result = [Val::Bool(false)];
            let outcome = func.call_async(&mut store, &[], &mut result).await;
            if limit < allowance {
                assert_eq!(
                    outcome.unwrap_err().root_cause().to_string(),
                    ALLOCATION_ERROR
                );
            } else {
                outcome?;
                assert_eq!(result[0], expected, "{} {boundary:?}", fixture.name);
            }
        }
        println!(
            "hostcall-allowance dynamic {} {boundary:?}: {allowance}",
            fixture.name
        );
    }
    Ok(())
}

async fn typed_case<T>(fixture: Fixture, expected: Vec<T>, allowance: usize) -> Result<()>
where
    T: ComponentType + Lift + Clone + Debug + PartialEq + Send + Sync + 'static,
{
    let engine = Runtime::new_engine()?;
    for boundary in [
        Boundary::SyncResult,
        Boundary::AsyncResult,
        Boundary::AsyncImport,
    ] {
        let component = fixture.component(&engine, boundary)?;
        for limit in [allowance - 1, allowance] {
            let mut store = store(&engine, limit)?;
            let mut linker = Linker::new(&engine);
            let expected_import = expected.clone();
            if matches!(boundary, Boundary::AsyncImport) {
                linker.root().func_wrap_concurrent(
                    "accept",
                    move |accessor, (items,): (Vec<T>,)| {
                        let expected = expected_import.clone();
                        Box::pin(async move {
                            assert_eq!(items, expected);
                            accessor.with(|mut access| *access.get() += 1);
                            tokio::task::yield_now().await;
                            Ok(())
                        })
                    },
                )?;
            }
            let instance = linker.instantiate_async(&mut store, &component).await?;
            let outcome = if matches!(boundary, Boundary::AsyncImport) {
                let func = instance.get_typed_func::<(), ()>(&mut store, "run")?;
                func.call_async(&mut store, ()).await
            } else {
                let func = instance.get_typed_func::<(), (Vec<T>,)>(&mut store, "run")?;
                func.call_async(&mut store, ())
                    .await
                    .map(|(items,)| assert_eq!(items, expected))
            };
            if limit < allowance {
                assert_eq!(
                    outcome.unwrap_err().root_cause().to_string(),
                    ALLOCATION_ERROR
                );
                assert_eq!(*store.data(), 0);
            } else {
                outcome?;
                if matches!(boundary, Boundary::AsyncImport) {
                    assert_eq!(*store.data(), 1);
                }
            }
        }
        println!(
            "hostcall-allowance typed {} {boundary:?}: {allowance}",
            fixture.name
        );
    }
    Ok(())
}

#[tokio::test]
async fn dynamic_allowance_thresholds_match_baseline() -> Result<()> {
    let mut bytes = Fixture::new("bytes", "u8", 2);
    bytes.bytes(64, &[7, 9]);
    dynamic_case(bytes, Val::List(vec![Val::U8(7), Val::U8(9)]), 96).await?;

    let mut string = Fixture::new("string", "string", 1);
    string.word(64, 512);
    string.word(68, 3);
    string.bytes(512, b"abc");
    dynamic_case(string, Val::List(vec![Val::String("abc".into())]), 51).await?;

    for (present, allowance) in [(false, 48), (true, 96)] {
        let mut option = Fixture::new("option", "(option u32)", 1);
        option.word(64, u32::from(present));
        option.word(68, 7);
        let payload = present.then(|| Box::new(Val::U32(7)));
        dynamic_case(option, Val::List(vec![Val::Option(payload)]), allowance).await?;
    }

    let mut record = Fixture::new("record", "$entry", 1);
    record.declarations = r#"(type $inner (record (field "name" string) (field "maybe" (option u32))))
        (export $entry "entry" (type $inner))"#;
    record.word(64, 512);
    record.word(68, 2);
    record.word(72, 1);
    record.word(76, 7);
    record.bytes(512, b"ab");
    dynamic_case(
        record,
        Val::List(vec![Val::Record(vec![
            ("name".into(), Val::String("ab".into())),
            ("maybe".into(), Val::Option(Some(Box::new(Val::U32(7))))),
        ])]),
        203,
    )
    .await?;

    let mut tuple = Fixture::new("tuple", "(tuple string u64)", 1);
    tuple.word(64, 512);
    tuple.word(68, 2);
    tuple.word(72, 7);
    tuple.bytes(512, b"ab");
    dynamic_case(
        tuple,
        Val::List(vec![Val::Tuple(vec![
            Val::String("ab".into()),
            Val::U64(7),
        ])]),
        146,
    )
    .await?;

    let mut nested = Fixture::new("nested-list", "(list u8)", 1);
    nested.word(64, 512);
    nested.word(68, 2);
    nested.bytes(512, &[7, 9]);
    dynamic_case(
        nested,
        Val::List(vec![Val::List(vec![Val::U8(7), Val::U8(9)])]),
        144,
    )
    .await?;

    let mut variant = Fixture::new("variant", "$entry", 1);
    variant.declarations = r#"(type $inner (variant (case "text" string) (case "none")))
        (export $entry "entry" (type $inner))"#;
    variant.word(68, 512);
    variant.word(72, 2);
    variant.bytes(512, b"ab");
    dynamic_case(
        variant,
        Val::List(vec![Val::Variant(
            "text".into(),
            Some(Box::new(Val::String("ab".into()))),
        )]),
        102,
    )
    .await?;

    let mut enumeration = Fixture::new("enum", "$entry", 1);
    enumeration.declarations =
        r#"(type $inner (enum "ok" "other")) (export $entry "entry" (type $inner))"#;
    dynamic_case(enumeration, Val::List(vec![Val::Enum("ok".into())]), 50).await?;

    let mut flags = Fixture::new("flags", "$entry", 1);
    flags.declarations =
        r#"(type $inner (flags "red" "blue")) (export $entry "entry" (type $inner))"#;
    flags.word(64, 3);
    dynamic_case(
        flags,
        Val::List(vec![Val::Flags(vec!["red".into(), "blue".into()])]),
        55,
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn typed_allowance_thresholds_match_baseline() -> Result<()> {
    let mut bytes = Fixture::new("bytes", "u8", 2);
    bytes.bytes(64, &[7, 9]);
    typed_case(bytes, vec![7_u8, 9], 2).await?;

    let mut string = Fixture::new("string", "string", 1);
    string.word(64, 512);
    string.word(68, 3);
    string.bytes(512, b"abc");
    typed_case(string, vec!["abc".to_string()], 27).await?;

    let mut nested = Fixture::new("nested-list", "(list u8)", 1);
    nested.word(64, 512);
    nested.word(68, 2);
    nested.bytes(512, &[7, 9]);
    typed_case(nested, vec![vec![7_u8, 9]], 26).await?;

    let mut file = Fixture::new("file-tuple", "(tuple (list u8) u64 u64)", 1);
    file.word(64, 512);
    file.word(68, 2);
    file.bytes(512, &[7, 9]);
    typed_case(file, vec![(vec![7_u8, 9], 0_u64, 0_u64)], 42).await?;

    let mut proof = Fixture::new("proof-file-tuple", "(tuple string (list u8) u64 u64)", 1);
    proof.word(64, 512);
    proof.word(68, 3);
    proof.bytes(512, b"abc");
    proof.word(72, 520);
    proof.word(76, 2);
    proof.bytes(520, &[7, 9]);
    typed_case(
        proof,
        vec![("abc".to_string(), vec![7_u8, 9], 0_u64, 0_u64)],
        69,
    )
    .await?;
    Ok(())
}
