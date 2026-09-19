use std::sync::{Arc, Mutex};

use super::fuel::Fuel;
use super::{ExecutionError, Runtime};
use anyhow::{Result, anyhow};
use wasmtime::component::{Linker, WasmList};
use wasmtime::{Engine, Error as WasmError, Module};

use ::result_encoder::{ENCODER_IMPORT, OUTPUT_IMPORT, encoder_module};
pub(super) use ::result_encoder::{PRIVATE_PREFIX, prepare_component as encode};

// Host imports clone Runtime during async execution. Share this invocation's
// staging slot so cleanup cannot accidentally clone a large encoded payload.
#[derive(Clone, Default)]
pub(super) struct EncodedResult(Arc<Mutex<Option<String>>>);

impl EncodedResult {
    pub(super) fn take(&self) -> Result<String> {
        self.0
            .lock()
            .map_err(|_| anyhow!("result slot poisoned"))?
            .take()
            .ok_or_else(|| anyhow!("contract did not deliver its result"))
    }

    #[cfg(test)]
    pub(super) fn is_empty(&self) -> bool {
        self.0.lock().unwrap().is_none()
    }
}

pub(super) fn module(engine: &Engine) -> Result<Module> {
    Ok(Module::from_binary(engine, &encoder_module()?)?)
}

pub(super) fn add_to_linker(linker: &mut Linker<Runtime>, module: &Module) -> Result<()> {
    linker.root().module(ENCODER_IMPORT, module)?;
    linker
        .root()
        .func_wrap(OUTPUT_IMPORT, |mut store, (bytes,): (WasmList<u8>,)| {
            let slot = store.data().encoded_result.0.clone();
            let mut slot = slot
                .lock()
                .map_err(|_| WasmError::from_anyhow(anyhow!("result slot poisoned")))?;
            if slot.is_some() {
                return Err(
                    ExecutionError::Deterministic(anyhow!("duplicate result delivery")).into(),
                );
            }
            Fuel::ResultCopyBytes(bytes.len() as u64)
                .consume_with_store(&mut store)
                .map_err(WasmError::from_anyhow)?;
            let result = String::from_utf8(bytes.as_le_slice(&store).to_vec())?;
            *slot = Some(result);
            Ok(())
        })?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::encode;
    use crate::database::native_contracts::NATIVE_CONTRACTS;
    use crate::test_utils::test_runtime;
    use anyhow::Result;
    use wasmtime::component::Component;

    #[tokio::test]
    async fn prepares_native_contracts() -> Result<()> {
        let (runtime, _dir, _name) = test_runtime().await?;
        for id in 1..=NATIVE_CONTRACTS.len() as u64 {
            let bytes = runtime.storage.component_bytes(id).await?;
            let bytes = encode(&bytes)?;
            let component = Component::from_binary(&runtime.engine, &bytes)?;
            runtime.linkers.encoded_native.instantiate_pre(&component)?;
            assert!(
                runtime.linkers.native.instantiate_pre(&component).is_err(),
                "publication linker must not expose the private encoder imports"
            );
        }
        Ok(())
    }
}
