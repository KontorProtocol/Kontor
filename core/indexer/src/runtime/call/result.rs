use std::fmt::{self, Write};

use anyhow::{Result, anyhow, ensure};
use wasmtime::component::{
    Resource, Val,
    wasm_wave::{
        wasm::{WasmTypeKind, WasmValue},
        writer::Writer,
    },
};
use wasmtime::{Store, Trap};

use super::MAX_EXPR_DEPTH;
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

    fn take_raw(&mut self, value: String) -> fmt::Result {
        self.accept(value.len())?;
        self.value = value;
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

pub(super) async fn encode(
    mut results: Vec<Val>,
    is_fallback: bool,
    store: &mut Store<Runtime>,
) -> Result<String> {
    Fuel::Result.consume_with_store(store)?;
    if results.len() > 1 {
        return Err(anyhow!(
            "Functions with multiple return values are not supported"
        ));
    }
    let value = match results.pop() {
        Some(value) if !is_fallback => {
            let value = project_resource(value, store).await?;
            visit(
                &value,
                &mut || Fuel::WaveValue.consume_with_store(store).map(|_| ()),
                0,
            )?;
            Some(value)
        }
        value => value,
    };
    let mut output = Output::new(store.get_fuel()? / Fuel::ResultBytes(1).cost());
    let result: Result<()> = match value {
        None => Ok(()),
        Some(Val::String(value)) if is_fallback => output.take_raw(value).map_err(Into::into),
        Some(_) if is_fallback => Err(anyhow!("fallback did not return a string")),
        Some(value) => Writer::new(&mut output)
            .write_value(&value)
            .map_err(Into::into),
    };
    // Settle once, including partial output on failure, before call commit or
    // returning a nested call's remaining fuel to its parent.
    Fuel::ResultBytes(output.charged_bytes).consume_with_store(store)?;
    if output.exhausted {
        return Err(Trap::OutOfFuel.into());
    }
    result?;
    Ok(output.value)
}

// The writer skips absent record fields without touching its byte sink. Bound
// its structural work first, including those fields, without cloning values or
// walking string bytes. The writer still bounds escaping/appends incrementally.
fn visit<V: WasmValue>(
    value: &V,
    charge: &mut impl FnMut() -> Result<()>,
    depth: usize,
) -> Result<()> {
    ensure!(depth <= MAX_EXPR_DEPTH, "WAVE value nesting is too deep");
    charge()?;
    match value.kind() {
        WasmTypeKind::List | WasmTypeKind::FixedLengthList => {
            for value in value.unwrap_list() {
                visit(&*value, charge, depth + 1)?;
            }
        }
        WasmTypeKind::Tuple => {
            for value in value.unwrap_tuple() {
                visit(&*value, charge, depth + 1)?;
            }
        }
        WasmTypeKind::Record => {
            for (_, value) in value.unwrap_record() {
                visit(&*value, charge, depth + 1)?;
            }
        }
        WasmTypeKind::Option => {
            if let Some(value) = value.unwrap_option() {
                visit(&*value, charge, depth + 1)?;
            }
        }
        WasmTypeKind::Variant => {
            if let Some(value) = value.unwrap_variant().1 {
                visit(&*value, charge, depth + 1)?;
            }
        }
        WasmTypeKind::Result => {
            let (Ok(value) | Err(value)) = value.unwrap_result();
            if let Some(value) = value {
                visit(&*value, charge, depth + 1)?;
            }
        }
        WasmTypeKind::Flags => {
            for _ in value.unwrap_flags() {
                charge()?;
            }
        }
        WasmTypeKind::Unsupported => return Err(anyhow!("unsupported WAVE result type")),
        _ => (),
    }
    Ok(())
}

async fn project_resource(value: Val, store: &mut Store<Runtime>) -> Result<Val> {
    let Val::Resource(resource) = value else {
        return Ok(value);
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
