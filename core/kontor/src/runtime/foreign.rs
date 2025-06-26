use anyhow::{Result, anyhow};
use lru::LruCache;
use std::path::Path;
use tokio::fs::read;
use wasmtime::{
    Engine, Store,
    component::{Component, Linker, wasm_wave::parser::Parser as WaveParser},
};
use wit_component::ComponentEncoder;

use crate::runtime::types::default_val_for_type;

#[derive(Clone)]
pub struct Foreign {
    engine: Engine,
    component: Component,
}

impl Foreign {
    pub async fn new(
        engine: &Engine,
        component_cache: &mut LruCache<String, Component>,
        component_dir: String,
        address: String,
    ) -> Result<Self> {
        let component = if let Some(cached_component) = component_cache.get(&address) {
            cached_component.clone()
        } else {
            let path_str = format!("{}{}.wasm", component_dir, address);
            let path = Path::new(&path_str);
            // Check if the file exists
            if !path.exists() {
                return Err(anyhow!(
                    "Invalid address: {} provided to foreign constructor. WASM file not found at {}",
                    address,
                    path.display()
                ));
            }

            let module_bytes = read(path).await?;
            let component_bytes = ComponentEncoder::default()
                .module(&module_bytes)?
                .validate(true)
                .encode()?;

            let component = Component::from_binary(engine, &component_bytes)?;

            component_cache.put(address.clone(), component.clone());
            component
        };

        Ok(Self {
            engine: engine.clone(),
            component,
        })
    }

    pub async fn call(&self, expr: &str) -> Result<String> {
        let mut store = Store::new(&self.engine, ());
        let linker = Linker::new(&self.engine);

        let call = WaveParser::new(expr).parse_raw_func_call()?;

        let instance = linker
            .instantiate_async(&mut store, &self.component)
            .await?;

        let func = instance
            .get_func(&mut store, call.name())
            .ok_or_else(|| anyhow::anyhow!("{} function not found in instance", call.name()))?;
        let params = call.to_wasm_params(func.params(&store).iter().map(|(_, t)| t))?;
        let mut results = func
            .results(&store)
            .iter()
            .map(default_val_for_type)
            .collect::<Vec<_>>();
        func.call_async(&mut store, &params, &mut results).await?;

        if results.is_empty() {
            return Ok("()".to_string());
        }

        if results.len() == 1 {
            return results[0].to_wave();
        }

        // Multiple results are not supported
        Err(anyhow!(
            "Functions with multiple return values are not supported"
        ))
    }
}
