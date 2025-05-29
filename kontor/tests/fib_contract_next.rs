use std::path::Path;

use anyhow::Result;
use stdlib::{Contract, MyMonoidHostRep};
use tokio::fs::read;
use wasmtime::{
    Engine, Store,
    component::{
        Component, Linker, Resource, ResourceTable, Type, Val,
        wasm_wave::parser::Parser as WaveParser,
    },
};

struct HostCtx {
    table: ResourceTable,
}

impl HostCtx {
    fn new() -> Self {
        Self {
            table: ResourceTable::new(),
        }
    }
}

impl stdlib::Host for HostCtx {
    async fn test(&mut self) -> Result<bool> {
        Ok(true)
    }
}

impl stdlib::HostMonoid for HostCtx {
    async fn new(&mut self, address: u64) -> Result<Resource<MyMonoidHostRep>> {
        let rep = MyMonoidHostRep::new(address)?;
        Ok(self.table.push(rep)?)
    }

    async fn mzero(&mut self, handle: Resource<MyMonoidHostRep>) -> Result<u64> {
        let rep = self.table.get(&handle)?;
        let result = (rep.mzero_operation)();
        Ok(result)
    }

    async fn mappend(&mut self, handle: Resource<MyMonoidHostRep>, x: u64, y: u64) -> Result<u64> {
        let rep = self.table.get(&handle)?;
        let result = (rep.mappend_operation)(x, y);
        Ok(result)
    }

    async fn drop(&mut self, handle: Resource<MyMonoidHostRep>) -> Result<()> {
        let _rep: MyMonoidHostRep = self.table.delete(handle)?;
        Ok(())
    }
}

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
        Type::Char => Val::Char(' '),
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
            if let Some(ty) = result_ty.ok() {
                Val::Result(Ok(Some(Box::new(default_val_for_type(&ty)))))
            } else if let Some(ty) = result_ty.err() {
                Val::Result(Err(Some(Box::new(default_val_for_type(&ty)))))
            } else {
                Val::Result(Ok(None))
            }
        }
        Type::Flags(_) => Val::Flags(Vec::new()),
        Type::Own(_) => panic!("Cannot create a default Own value without a resource context"),
        Type::Borrow(_) => {
            panic!("Cannot create a default Borrow value without a resource context")
        }
    }
}

#[tokio::test]
#[ignore]
async fn test_fib_contract() -> Result<()> {
    let mut config = wasmtime::Config::new();
    config.async_support(true);
    config.wasm_component_model(true);
    let engine = Engine::new(&config)?;

    let host_ctx = HostCtx::new();
    let mut store = Store::new(&engine, host_ctx);

    let mut linker = Linker::<HostCtx>::new(&engine);
    Contract::add_to_linker(&mut linker, |s| s)?;

    let n = 8;
    let s = format!("fib({})", n);
    let call = WaveParser::new(&s).parse_raw_func_call()?;

    let path = Path::new("../target/wasm32-unknown-unknown/debug/fib.wasm");
    let wasm = read(path).await?;
    let component = Component::from_binary(&engine, &wasm)?;
    let instance = linker.instantiate_async(&mut store, &component).await?;

    let func = instance
        .get_func(&mut store, call.name())
        .expect("fib should exist in instance");
    let params = call.to_wasm_params(func.params(&store).iter().map(|(_, t)| t))?;
    let mut results = func
        .results(&store)
        .iter()
        .map(default_val_for_type)
        .collect::<Vec<_>>();
    func.call_async(&mut store, &params, &mut results).await?;
    assert_eq!(results[0], Val::U64(21));

    Ok(())
}
