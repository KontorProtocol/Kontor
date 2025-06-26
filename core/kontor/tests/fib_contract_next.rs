use std::path::Path;

use anyhow::Result;
use clap::Parser;
use kontor::{
    config::Config,
    runtime::{Context, Contract, Storage, default_val_for_type},
    utils::new_test_db,
};
use tokio::fs::read;
use wasmtime::{
    Engine, Store,
    component::{Component, Linker, Val, wasm_wave::parser::Parser as WaveParser},
};
use wit_component::ComponentEncoder;

#[tokio::test]
async fn test_fib_contract() -> Result<()> {
    let mut config = wasmtime::Config::new();
    config.async_support(true);
    config.wasm_component_model(true);
    let engine = Engine::new(&config)?;
    let (_, writer, _test_db_dir) = new_test_db(&Config::parse()).await?;

    let storage = Storage {
        conn: writer.connection(),
        contract_id: "test".to_string(),
        tx_id: 1,
        height: 1,
    };
    let host_ctx = Context::new(engine.clone(), storage);
    let mut store = Store::new(&engine, host_ctx);
    let mut linker = Linker::<Context>::new(&engine);
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
