use anyhow::Result;
use wasmtime::{Config, Engine, InstanceAllocationStrategy, LiftingPrices};

use super::gas::{LIFT_METADATA_BYTE_FUEL, LIFT_STRING_BYTE_FUEL, LIFT_VALUE_FUEL};
use super::resources::GuestMemoryLimits;

pub(crate) fn new_engine() -> Result<Engine> {
    engine_with_async_stack_size(2 * 1024 * 1024)
}

#[cfg(test)]
pub(crate) fn new_resource_diagnostic_engine() -> Result<Engine> {
    engine_with_async_stack_size(1024 * 1024)
}

fn engine_with_async_stack_size(async_stack_size: usize) -> Result<Engine> {
    let reservation = u64::try_from(GuestMemoryLimits::default().per_root)?;
    engine_with_memory_reservation(async_stack_size, reservation)
}

#[cfg(test)]
pub(crate) fn new_previous_memory_reservation_engine() -> Result<Engine> {
    engine_with_memory_reservation(2 * 1024 * 1024, 4 * 1024 * 1024 * 1024)
}

fn engine_with_memory_reservation(
    async_stack_size: usize,
    memory_reservation: u64,
) -> Result<Engine> {
    let mut config = Config::new();
    config.target("pulley64-unknown-unknown-elf")?;
    config.max_wasm_stack(512 * 1024);
    config.async_stack_size(async_stack_size);
    config.wasm_component_model_async(false);
    config.wasm_component_model_more_async_builtins(false);
    config.wasm_component_model_async_stackful(false);
    config.wasm_component_model_threading(false);
    config.wasm_component_model_error_context(false);
    config.wasm_shared_everything_threads(false);
    config.wasm_stack_switching(false);
    config.wasm_threads(false);
    config.concurrency_support(false);
    config.consume_fuel(true);
    config.consume_lifting_fuel(Some(LiftingPrices {
        lift_value: LIFT_VALUE_FUEL,
        string_byte: LIFT_STRING_BYTE_FUEL,
        metadata_byte: LIFT_METADATA_BYTE_FUEL,
    }));
    // Wasmtime 48's Mach receiver aborts on an interrupted receive. Kontor
    // has no Mach-based crash handler, so use POSIX traps on macOS instead.
    config.macos_use_mach_ports(false);
    // CoW can skip metered initialization depending on OS/image availability.
    // Every node must copy the same data segments and charge the same fuel.
    config.memory_init_cow(false);
    config.wasm_custom_page_sizes(false);
    config.allocation_strategy(InstanceAllocationStrategy::OnDemand);
    // The shared root limit bounds each admitted memory. Wasmtime's 4 GiB
    // default reservation needlessly scales with suspended Store count.
    config.memory_reservation(memory_reservation);
    config.memory_may_move(true);
    config.wasm_relaxed_simd(false);
    config.cranelift_nan_canonicalization(true);
    let engine = Engine::new(&config)?;
    anyhow::ensure!(engine.is_pulley(), "production engine must use Pulley");
    anyhow::ensure!(
        engine.get_target().as_deref() == Some("pulley64-unknown-unknown-elf"),
        "unexpected Pulley target"
    );
    anyhow::ensure!(
        engine.get_max_wasm_stack() == 512 * 1024,
        "unexpected Pulley logical stack size"
    );
    anyhow::ensure!(
        engine.get_async_stack_size() == async_stack_size,
        "unexpected async fiber stack size"
    );
    Ok(engine)
}
