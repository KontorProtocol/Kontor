#![no_std]
contract!(name = "counter");

use stdlib::*;

#[derive(Clone, Default, StorageRoot)]
struct CounterStorage {
    pub value: u64,
}

impl Guest for Counter {
    fn init(ctx: &ProcContext) {
        CounterStorage::default().init(ctx);
    }

    fn increment(ctx: &ProcContext) {
        let model = ctx.model();
        let current = model.value();
        model.set_value(current + 1);
    }

    fn get(ctx: &ViewContext) -> u64 {
        ctx.model().value()
    }
}
