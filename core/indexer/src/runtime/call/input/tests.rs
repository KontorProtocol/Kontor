use std::hint::black_box;
use std::time::Instant;

use anyhow::Result;
use wasmtime::component::{
    Component, Type, Val, types::ComponentItem, wasm_wave::untyped::UntypedFuncCall,
};
use wasmtime::{Store, Trap};

use super::params;
use crate::runtime::Runtime;
use crate::runtime::fuel::{Fuel, FuelDiscriminants, FuelGauge};
use crate::test_utils::test_runtime;

fn ty(runtime: &Runtime, definition: &str) -> Result<Type> {
    ty_with_definitions(runtime, "", definition)
}

fn ty_with_definitions(runtime: &Runtime, definitions: &str, definition: &str) -> Result<Type> {
    let component = Component::new(
        &runtime.engine,
        format!(
            r#"(component {definitions} (type $value {definition}) (export "value" (type $value)))"#
        ),
    )?;
    let component_ty = component.component_type();
    let export = component_ty.get_export(&runtime.engine, "value").unwrap();
    let ComponentItem::Type(ty) = export.ty else {
        panic!("expected value type")
    };
    Ok(ty)
}

fn parse(store: &mut Store<Runtime>, ty: &Type, source: &str) -> Result<Vec<Val>> {
    let source = format!("f({source})");
    let call = UntypedFuncCall::parse(&source)?;
    params(&call, [ty.clone()].into_iter(), store)
}

#[tokio::test]
async fn bounded_builder_matches_standard_wave_semantics() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let cases = [
        (
            "(list (option u32))",
            vec!["[]", "[none, some(1), 2]", "[some(false)]"],
        ),
        (
            "(record (field \"a\" u32) (field \"b\" (option string)))",
            vec![
                "{a: 1}",
                "{b: some(\"é\\n\"), a: 2}",
                "{a: 1, a: 2}",
                "{a: 1, extra: false}",
                "{:}",
            ],
        ),
        (
            "(tuple string (list u8))",
            vec!["(\"é\\n\", [1, 2])", "(\"x\",)", "(\"x\", [], false)"],
        ),
        (
            "(variant (case \"empty\") (case \"value\" (option u32)))",
            vec![
                "empty",
                "value(none)",
                "value(some(7))",
                "value",
                "empty(1)",
                "unknown",
            ],
        ),
        ("(enum \"one\" \"two\")", vec!["one", "two", "three"]),
        (
            "(flags \"one\" \"two\")",
            vec!["{}", "{two, one}", "{one, one}", "{three}"],
        ),
        (
            "(option (option u32))",
            vec!["none", "some(none)", "some(some(3))", "3"],
        ),
        (
            "(result u32 (error string))",
            vec!["ok(2)", "2", "err(\"bad\")", "ok", "err(2)"],
        ),
        (
            "(result (option u32))",
            vec!["ok(none)", "ok(some(2))", "err", "none"],
        ),
    ];
    for (definition, sources) in cases {
        let ty = ty(&runtime, definition)?;
        for source in sources {
            let expression = format!("f({source})");
            let mut store = runtime.make_store(1_000_000)?;
            let bounded = parse(&mut store, &ty, source);
            let Ok(call) = UntypedFuncCall::parse(&expression) else {
                assert!(bounded.is_err(), "{source}");
                continue;
            };
            let stock = call.to_wasm_params::<Val>([&ty]);
            match (stock, bounded) {
                (Ok(stock), Ok(bounded)) => assert_eq!(stock, bounded, "{definition}: {source}"),
                (Err(_), Err(_)) => (),
                (stock, bounded) => {
                    panic!("{definition}: {source}: stock={stock:?}, bounded={bounded:?}")
                }
            }
        }
    }
    Ok(())
}

#[tokio::test]
async fn omitted_fields_stop_construction_at_the_budget() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let fields = (0..512)
        .map(|i| format!(r#"(field "field{i:04}" (option u32))"#))
        .collect::<Vec<_>>()
        .join(" ");
    let ty = ty(&runtime, &format!("(record {fields})"))?;
    let field_cost = Fuel::WaveTypeField(9).cost() + Fuel::WaveValue.cost();
    for affordable in [0, 1, 16, 512] {
        let gauge = FuelGauge::with_profiling();
        runtime.gauge = Some(gauge.clone());
        let budget = Fuel::WaveValue.cost() + affordable * field_cost;
        let mut store = runtime.make_store(budget)?;
        let result = parse(&mut store, &ty, "{:}");
        if affordable == 512 {
            let Val::Record(fields) = &result?[0] else {
                panic!("expected record")
            };
            assert_eq!(fields.len(), 512);
        } else {
            assert!(matches!(
                result.unwrap_err().downcast_ref::<Trap>(),
                Some(Trap::OutOfFuel)
            ));
        }
        assert_eq!(store.get_fuel()?, 0);
        let profile = gauge.report()?.profile.unwrap();
        assert_eq!(
            profile.per_type[&FuelDiscriminants::WaveValue].consumed_count,
            affordable + 1
        );
        assert_eq!(
            profile.per_type[&FuelDiscriminants::WaveTypeField].consumed_count,
            affordable
        );
    }
    Ok(())
}

#[tokio::test]
async fn trailing_options_and_empty_calls_match_wave() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let option = ty(&runtime, "(option u32)")?;
    for expression in ["f()", "f(1)", "f(1, none)", "f(1, 2, 3)"] {
        let call = UntypedFuncCall::parse(expression)?;
        let types = [Type::U32, option.clone()];
        let stock = call.to_wasm_params::<Val>(types.iter());
        let mut store = runtime.make_store(1000)?;
        let result = params(&call, types.into_iter(), &mut store);
        assert_eq!(stock.is_ok(), result.is_ok(), "{expression}");
        if let Ok(stock) = stock {
            assert_eq!(result?, stock);
        }
    }
    Ok(())
}

#[tokio::test]
async fn only_selected_payloads_expand_and_schema_bytes_are_charged() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let record = r#"(type $inner (record (field "long-field-name" (option u32))))
        (export $record "record" (type $inner))"#;
    let optional = ty_with_definitions(&runtime, record, "(option $record)")?;
    let mut store = runtime.make_store(50)?;
    assert_eq!(
        parse(&mut store, &optional, "none")?,
        vec![Val::Option(None)]
    );
    assert_eq!(store.get_fuel()?, 0);
    let mut store = runtime.make_store(50 * 4 + 10 * 15)?;
    assert!(parse(&mut store, &optional, "some({:})").is_ok());
    assert_eq!(store.get_fuel()?, 0);
    let variant = ty_with_definitions(
        &runtime,
        record,
        "(variant (case \"empty\") (case \"full\" $record))",
    )?;
    let mut store = runtime.make_store(50 + 50 + 10 * 5)?;
    assert_eq!(
        parse(&mut store, &variant, "empty")?,
        vec![Val::Variant("empty".into(), None)]
    );
    assert_eq!(store.get_fuel()?, 0);
    Ok(())
}

#[tokio::test]
#[ignore = "manual standard versus metered WAVE construction comparison"]
async fn construction_overhead() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    for count in [16, 128, 512] {
        let fields = (0..count)
            .map(|i| format!(r#"(field "field{i:04}" (option u32))"#))
            .collect::<Vec<_>>()
            .join(" ");
        let ty = ty(&runtime, &format!("(record {fields})"))?;
        let call = UntypedFuncCall::parse("f({:})")?;
        let start = Instant::now();
        for _ in 0..1000 {
            black_box(call.to_wasm_params::<Val>([&ty])?);
        }
        let stock = start.elapsed();
        let mut store = runtime.make_store(1_000_000_000)?;
        let start = Instant::now();
        for _ in 0..1000 {
            black_box(params(&call, [ty.clone()].into_iter(), &mut store)?);
        }
        println!(
            "fields={count} stock={stock:?} metered={:?}",
            start.elapsed()
        );
    }
    Ok(())
}
