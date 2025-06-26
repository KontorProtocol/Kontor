use lru::LruCache;
use std::num::NonZeroUsize;
use std::path::Path;

use anyhow::Result;
use stdlib::{Contract, ForeignHostRep, MyMonoidHostRep, default_val_for_type};
use tokio::fs::read;
use wasmtime::{
    Engine, Store,
    component::{
        Component, Linker, Resource, ResourceTable, Val, wasm_wave::parser::Parser as WaveParser,
    },
};
use wit_component::ComponentEncoder;

const COMPONENT_CACHE_CAPACITY: usize = 64;

struct HostCtx {
    table: ResourceTable,
    engine: Engine,
    component_cache: LruCache<String, Component>,
}

impl HostCtx {
    fn new(engine: Engine) -> Self {
        Self {
            table: ResourceTable::new(),
            engine,
            component_cache: LruCache::new(NonZeroUsize::new(COMPONENT_CACHE_CAPACITY).unwrap()),
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
        let component_dir = "../../contracts/target/wasm32-unknown-unknown/debug/";
        let rep = ForeignHostRep::new(
            &self.engine,
            &mut self.component_cache,
            component_dir.to_string(),
            address,
        )
        .await?;
        Ok(self.table.push(rep)?)
    }

    async fn call(&mut self, handle: Resource<ForeignHostRep>, expr: String) -> Result<String> {
        let rep = self.table.get(&handle)?;
        rep.call(&expr)
            .await
            .map_err(|e| anyhow::anyhow!("Foreign call failed: {}", e))
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

#[tokio::test]
async fn test_fib_contract() -> Result<()> {
    let mut config = wasmtime::Config::new();
    config.async_support(true);
    config.wasm_component_model(true);
    let engine = Engine::new(&config)?;

    let host_ctx = HostCtx::new(engine.clone());
    let mut store = Store::new(&engine, host_ctx);
    let mut linker = Linker::<HostCtx>::new(&engine);
    Contract::add_to_linker(&mut linker, |s| s)?;

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
