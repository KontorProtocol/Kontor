use std::fmt::{self, Write};

use anyhow::{Result, anyhow, ensure};
use wasmtime::component::{Resource, Val, wasm_wave::writer::Writer};
use wasmtime::{Store, Trap};

use crate::runtime::Runtime;
use crate::runtime::fuel::Fuel;
use crate::runtime::wit::Contract;

#[cfg(test)]
mod tests;

struct Output {
    value: String,
    limit: u64,
    charged_bytes: u64,
    exhausted: bool,
}

impl Output {
    fn new(limit: u64) -> Self {
        Self {
            value: String::new(),
            limit,
            charged_bytes: 0,
            exhausted: false,
        }
    }

    fn accept(&mut self, bytes: usize) -> fmt::Result {
        if self.exhausted || bytes as u64 > self.limit - self.charged_bytes {
            // Charge the affordable prefix even if this write crosses it in one
            // chunk. Billing must not depend on the formatter's write boundaries.
            self.charged_bytes = self.limit;
            self.exhausted = true;
            return Err(fmt::Error);
        }
        self.charged_bytes += bytes as u64;
        Ok(())
    }
}

impl Write for Output {
    fn write_str(&mut self, value: &str) -> fmt::Result {
        self.accept(value.len())?;
        self.value.push_str(value);
        Ok(())
    }
}

pub(super) async fn encode_init(
    mut results: Vec<Val>,
    store: &mut Store<Runtime>,
) -> Result<String> {
    Fuel::Result.consume_with_store(store)?;
    ensure!(results.len() == 1, "init must return one contract resource");
    let value = project_resource(results.pop().unwrap(), store).await?;
    // This host-owned address has one record and three scalar fields. Ordinary
    // guest results are traversed and formatted in the metered Wasm encoder.
    for _ in 0..4 {
        Fuel::WaveValue.consume_with_store(store)?;
    }
    let mut output = Output::new(store.get_fuel()? / Fuel::InitResultBytes(1).cost());
    let result = Writer::new(&mut output).write_value(&value);
    Fuel::InitResultBytes(output.charged_bytes).consume_with_store(store)?;
    if output.exhausted {
        return Err(Trap::OutOfFuel.into());
    }
    result?;
    Ok(output.value)
}

async fn project_resource(value: Val, store: &mut Store<Runtime>) -> Result<Val> {
    let Val::Resource(resource) = value else {
        return Err(anyhow!("init must return a contract resource"));
    };
    // Init returns a Contract resource. Other resources are not serializable
    // results, and passing them to WAVE's writer would panic.
    let handle: Resource<Contract> = resource
        .try_into_resource::<Contract>(&mut *store)
        .map_err(|error| {
            anyhow!("function returned a resource that is not a `contract`: {error}")
        })?;
    let contract = store.data().table.lock().await.delete(handle)?;
    let address = contract.address;
    Ok(Val::Record(vec![
        ("name".into(), Val::String(address.name)),
        ("height".into(), Val::U64(address.height)),
        ("tx-index".into(), Val::U32(address.tx_index)),
    ]))
}
