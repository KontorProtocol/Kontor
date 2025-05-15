use std::path::Path;

use anyhow::anyhow;
use kontor::logging;
use wasmtime::{
    Engine, Store,
    component::{Component, Linker, Type, Val, wasm_wave::parser::Parser as WaveParser},
};

fn default_val_for_type(ty: &Type) -> Val {
    match ty {
        Type::Bool => Val::Bool(false),
        Type::S8 => Val::S8(0),
        Type::U8 => Val::U8(0),
        Type::S16 => Val::S16(0),
        Type::U16 => Val::U16(0),
        Type::S32 => Val::S32(0),
        Type::U32 => Val::U32(0),
        Type::S64 => Val::S64(0),
        Type::U64 => Val::U64(0),
        Type::Float32 => Val::Float32(0.0),
        Type::Float64 => Val::Float64(0.0),
        Type::Char => Val::Char('\0'),
        Type::String => Val::String("".to_string()),
        Type::List(_) => Val::List(Vec::new()),
        Type::Record(record_ty) => {
            let fields = record_ty
                .fields()
                .map(|field| {
                    let field_val = default_val_for_type(&field.ty);
                    (field.name.to_string(), field_val)
                })
                .collect::<Vec<_>>();
            Val::Record(fields)
        }
        Type::Tuple(tuple_ty) => {
            let fields = tuple_ty
                .types()
                .map(|ty| default_val_for_type(&ty))
                .collect::<Vec<_>>();
            Val::Tuple(fields)
        }
        Type::Variant(variant_ty) => {
            let first_case = variant_ty
                .cases()
                .next()
                .expect("Variant must have at least one case");
            let payload = first_case.ty.map(|ty| Box::new(default_val_for_type(&ty)));
            Val::Variant(first_case.name.to_string(), payload)
        }
        Type::Enum(enum_ty) => {
            let first_case = enum_ty
                .names()
                .next()
                .expect("Enum must have at least one case");
            Val::Enum(first_case.to_string())
        }
        Type::Option(_) => Val::Option(None),
        Type::Result(result_ty) => {
            let ok_ty = result_ty.ok();
            if ok_ty.is_some() {
                Val::Result(Ok(None))
            } else {
                Val::Result(Err(None))
            }
        }
        Type::Flags(_) => Val::Flags(Vec::new()),
        Type::Own(_) => unimplemented!(),
        Type::Borrow(_) => unimplemented!(),
    }
}

#[tokio::test]
async fn test_fib_contract() -> Result<(), Box<dyn std::error::Error>> {
    logging::setup();

    let path = Path::new("../target/wasm32-unknown-unknown/debug/fib.wasm");
    let n = 8;
    let s = format!("fib({})", n);
    let call = WaveParser::new(s.as_str()).parse_raw_func_call()?;

    let mut config = wasmtime::Config::new();
    config.async_support(true);
    let engine = Engine::new(&config)?;
    let component = Component::from_file(&engine, path)?;
    let mut store = Store::new(&engine, ());
    let linker = Linker::new(&engine);

    let instance = linker.instantiate_async(&mut store, &component).await?;
    let f = instance
        .get_func(&mut store, call.name())
        .ok_or(anyhow!("can't find fib"))?;
    let params: Vec<Val> = call.to_wasm_params(f.params(&store).iter().map(|(_, t)| t))?;
    let mut results = f
        .results(&store)
        .iter()
        .map(default_val_for_type)
        .collect::<Vec<_>>();
    f.call_async(&mut store, &params, &mut results).await?;
    assert_eq!(results[0], Val::U64(21));
    Ok(())
}
