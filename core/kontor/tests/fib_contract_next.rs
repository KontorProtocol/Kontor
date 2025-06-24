use std::path::Path;
use std::sync::Arc;

use anyhow::Result;
use stdlib::{Contract, MyMonoidHostRep, ForeignHostRep, default_val_for_type};
use tokio::fs::read;
use wasmtime::{
    Engine, Store,
    component::{
        Component, Linker, Resource, ResourceTable, Val,
        wasm_wave::parser::Parser as WaveParser,
    },
};
use wit_component::ComponentEncoder;

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

impl stdlib::HostForeign for HostCtx {
    async fn new(&mut self, address: String) -> Result<Resource<ForeignHostRep>> {
        let rep = ForeignHostRep::new(address).await?;
        Ok(self.table.push(rep)?)
    }

    async fn call(&mut self, handle: Resource<ForeignHostRep>, name: String, args: String) -> Result<String> {
        let rep = self.table.get(&handle)?;
        let future = (rep.call_operation)(name, args);
        let result = future.await;
        Ok(result)
    }

    async fn drop(&mut self, handle: Resource<ForeignHostRep>) -> Result<()> {
        let _rep: ForeignHostRep = self.table.delete(handle)?;
        Ok(())
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
            component 
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
        
        let instance = linker.instantiate_async(&mut store, &self.component).await?;
        
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
        |store_context: wasmtime::StoreContextMut<'_, FibCtx>,
         (x, y): (u64, u64)|
         -> Box<dyn std::future::Future<Output = Result<(u64,), wasmtime::Error>> + Send> {
            Box::new(async move {
                let sum_service = store_context.data().sum_service.clone();
                let result = sum_service.call_sum(x, y).await
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
