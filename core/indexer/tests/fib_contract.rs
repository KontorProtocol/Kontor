use anyhow::Result;
use clap::Parser;
use indexer::{
    config::Config,
    runtime::{ComponentCache, Runtime, Storage},
    test_utils::new_test_db,
};
use wasmtime::component::wasm_wave::{to_string as to_wave, value::Value};

#[tokio::test]
async fn test_fib_contract() -> Result<()> {
    let (_, writer, _test_db_dir) = new_test_db(&Config::parse()).await?;
    let storage = Storage::builder().conn(writer.connection()).build();
    let signer = "test_signer".to_string();
    let contract_id = "fib".to_string();
    let component_cache = ComponentCache::new();
    let runtime = Runtime::new(storage, component_cache, signer, contract_id)?;

    let n = 8;
    let expr = format!("fib({})", to_wave(&Value::from(n))?);
    let result = runtime.execute(None, &expr).await?;
    assert_eq!(result, "21");
    Ok(())
}
