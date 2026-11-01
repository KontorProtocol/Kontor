mod consensus;
mod vm;

#[path = "../../tools/native-crypto/fixtures/bundle.rs"]
mod crypto;

use std::any::Any;
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::PathBuf;
use std::time::Duration;

use consensus::HostCall;

fn guarded<T>(call: impl FnOnce() -> Result<T, String>) -> Result<T, String> {
    catch_unwind(AssertUnwindSafe(call)).unwrap_or_else(|_| Err("bundle call panicked".into()))
}

pub fn exercise() -> Result<(u64, usize, Vec<u8>), String> {
    guarded(|| {
        let (fuel, wakes) = vm::run();
        Ok((fuel, wakes, crypto::exercise()))
    })
}

pub fn exercise_vm() -> Result<(u64, usize), String> {
    guarded(|| Ok(vm::run()))
}

pub fn exercise_crypto() -> Result<Vec<u8>, String> {
    guarded(|| Ok(crypto::exercise()))
}

pub fn start(
    address: String,
    wal: PathBuf,
    height: u64,
    host: HostCall,
) -> Result<Box<dyn Any + Send>, String> {
    guarded(|| consensus::start(address, wal, height, host))
}

pub fn decide(handle: &mut (dyn Any + Send)) -> Result<u64, String> {
    guarded(|| consensus::decide(handle))
}

pub fn stop(handle: &mut (dyn Any + Send), limit: Duration) -> Result<bool, String> {
    guarded(|| consensus::stop(handle, limit))
}

pub fn callback(host: HostCall) -> HostCall {
    Box::new(move |input| {
        guarded(|| {
            let mut decimal = itoa::Buffer::new();
            assert_eq!(decimal.format(input.len()), "8");
            host(input)
        })
    })
}

pub fn shape() -> Result<Vec<String>, String> {
    guarded(|| {
        let object: serde_json::Value = serde_json::from_str(r#"{"z": 1, "a": 2}"#).unwrap();
        Ok(object.as_object().unwrap().keys().cloned().collect())
    })
}
