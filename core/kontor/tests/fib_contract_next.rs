use std::sync::Arc;
use std::{collections::HashMap, path::Path};

use anyhow::Result;
use kontor::logging;
use stdlib::{Contract, MyMonoidHostRep};
use tokio::fs::read;
use tracing::info;
use wasmtime::component::ResourceType;
use wasmtime::{
    Engine, Store, StoreContextMut,
    component::{
        Component, Linker, Resource, ResourceTable, Type, Val,
        wasm_wave::parser::Parser as WaveParser,
    },
};
use wit_component::ComponentEncoder;
use wit_parser::WorldItem;

struct MyStorage {
    data: HashMap<String, u64>,
}

impl MyStorage {
    fn new() -> Self {
        Self {
            data: HashMap::new(),
        }
    }

    fn set(&mut self, key: String, value: u64) {
        self.data.insert(key, value);
    }

    fn get(&self, key: &str) -> u64 {
        self.data.get(key).unwrap().to_owned()
    }
}

struct HostCtx {
    pub table: ResourceTable,
    storage: HashMap<String, String>,
}

impl HostCtx {
    fn new() -> Self {
        Self {
            table: ResourceTable::new(),
            storage: HashMap::new(),
        }
    }
}

impl stdlib::Host for HostCtx {
    async fn set(&mut self, key: String, value: String) -> Result<()> {
        self.storage.insert(key, value);
        Ok(())
    }

    async fn get(&mut self, key: String) -> Result<Option<String>> {
        Ok(self.storage.get(&key).cloned())
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

struct SumService {
    engine: Engine,
    component: Component,
}

impl SumService {
    async fn new(engine: &Engine) -> Result<Arc<Self>> {
        let path = Path::new("../../contracts/target/wasm32-unknown-unknown/debug/sum.wasm");
        let module_bytes = read(path).await?;
        let component_bytes = ComponentEncoder::default()
            .module(&module_bytes)?
            .validate(true)
            .encode()?;
        let component = Component::from_binary(engine, &component_bytes)?;

        let service = Arc::new(Self {
            engine: engine.clone(),
            component,
        });
        Ok(service)
    }

    async fn call_sum(&self, x: u64, y: u64) -> Result<u64> {
        let host_ctx = HostCtx::new();
        let mut store = Store::new(&self.engine, host_ctx);
        let mut linker = Linker::<HostCtx>::new(&self.engine);
        Contract::add_to_linker(&mut linker, |s| s)?;

        let s = format!("sum({}, {})", x, y);
        let call = WaveParser::new(&s).parse_raw_func_call()?;

        let instance = linker
            .instantiate_async(&mut store, &self.component)
            .await?;

        let func = instance
            .get_func(&mut store, call.name())
            .ok_or_else(|| anyhow::anyhow!("sum function not found in instance"))?;
        let params = call.to_wasm_params(func.params(&store).iter().map(|(_, t)| t))?;
        let mut results = func
            .results(&store)
            .iter()
            .map(default_val_for_type)
            .collect::<Vec<_>>();
        func.call_async(&mut store, &params, &mut results).await?;

        match &results[0] {
            Val::U64(value) => Ok(*value),
            _ => Err(anyhow::anyhow!("Expected u64 result from sum function")),
        }
    }
}

struct FibCtx {
    host_ctx: HostCtx,
    sum_service: Arc<SumService>,
}

impl FibCtx {
    async fn new(engine: &Engine) -> Result<Self> {
        let host_ctx = HostCtx::new();
        let sum_service = SumService::new(engine).await?;
        Ok(Self {
            host_ctx,
            sum_service,
        })
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
async fn test_fib_contract() -> Result<()> {
    let mut config = wasmtime::Config::new();
    config.async_support(true);
    config.wasm_component_model(true);
    let engine = Engine::new(&config)?;

    let fib_ctx = FibCtx::new(&engine).await?;
    let mut store = Store::new(&engine, fib_ctx);
    let mut linker = Linker::<FibCtx>::new(&engine);
    Contract::add_to_linker(&mut linker, |s| &mut s.host_ctx)?;

    // Add the sum function implementation to the linker using store context
    linker.root().func_wrap_async(
        "sum",
        |store_context: StoreContextMut<'_, FibCtx>,
         (x, y): (u64, u64)|
         -> Box<dyn Future<Output = Result<(u64,), wasmtime::Error>> + Send> {
            Box::new(async move {
                let sum_service = store_context.data().sum_service.clone();
                let result = sum_service
                    .call_sum(x, y)
                    .await
                    .map_err(|e| wasmtime::Error::msg(format!("Sum WASM call failed: {}", e)))?;
                Ok((result,))
            })
        },
    )?;

    let n = 8;
    let s = format!("fib({})", n);
    let call = WaveParser::new(&s).parse_raw_func_call()?;

    let path = Path::new("../../contracts/target/wasm32-unknown-unknown/debug/fib.wasm");
    let module_bytes = read(path).await?;
    let component_bytes = ComponentEncoder::default()
        .module(&module_bytes)?
        .validate(true)
        .encode()?;

    logging::setup();
    linker.root().resource_async(
        "storage",
        ResourceType::host::<MyStorage>(),
        |mut context, id| {
            Box::new(async move {
                let handle = Resource::<MyStorage>::new_own(id);
                match context.data_mut().host_ctx.table.delete(handle) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e.into()),
                }
            })
        },
    )?;
    linker
        .root()
        .func_wrap_async("[constructor]storage", |mut context, ()| {
            Box::new(async move {
                let rep = MyStorage::new();
                context
                    .data_mut()
                    .host_ctx
                    .table
                    .push(rep)
                    .map(|r| (r,))
                    .map_err(Into::into)
            })
        })?;
    let wit = wit_component::decode(&component_bytes)?;
    let resolve = wit.resolve();
    for (_, i) in resolve.worlds.iter() {
        i.imports.iter().for_each(|(_, i)| {
            if let WorldItem::Function(f) = i {
                if f.name == "[method]storage.prop1" {
                    info!("Implementing {}", f.name);
                    linker
                        .root()
                        .func_wrap_async(
                            &f.name,
                            |mut context, (handle,): (Resource<MyStorage>,)| {
                                Box::new(async move {
                                    let rep = context.data_mut().host_ctx.table.get_mut(&handle)?;
                                    Ok((rep.get("prop1"),))
                                })
                            },
                        )
                        .unwrap();
                } else if f.name == "[method]storage.set-prop1" {
                    info!("Implementing {}", f.name);
                    linker
                        .root()
                        .func_wrap_async(
                            &f.name,
                            |mut context, (handle, value): (Resource<MyStorage>, u64)| {
                                Box::new(async move {
                                    let rep = context.data_mut().host_ctx.table.get_mut(&handle)?;
                                    rep.set("prop1".to_string(), value);
                                    Ok(())
                                })
                            },
                        )
                        .unwrap();
                }
            }
        });
    }
    linker.root().func_wrap_async(
        "[resource-drop]monoid",
        |mut context, (rep,): (Resource<MyStorage>,)| {
            Box::new(async move {
                match context.data_mut().host_ctx.table.delete(rep) {
                    Ok(_) => Ok(()),
                    Err(e) => Err(e.into()),
                }
            })
        },
    )?;

    let component = Component::from_binary(&engine, &component_bytes)?;
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
