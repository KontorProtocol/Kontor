#![no_std]
contract!(name = "counter");

use stdlib::*;

#[derive(Clone, Default, StorageRoot)]
struct CounterStorage {
    pub value: u64,
    pub blob: String,
}

impl Guest for Counter {
    fn init(ctx: &ProcContext) -> Contract {
        CounterStorage::default().init(ctx);
        ctx.contract()
    }

    fn increment(ctx: &ProcContext) {
        let model = ctx.model();
        let current = model.value();
        model.set_value(current + 1);
    }

    fn get(ctx: &ViewContext) -> u64 {
        ctx.model().value()
    }

    fn get_blob(ctx: &ViewContext) -> String {
        ctx.model().blob()
    }

    fn fill_blob(ctx: &ProcContext, n: u32) {
        ctx.model().set_blob("a".repeat(n as usize));
    }

    fn set_blob_then_fail(ctx: &ProcContext, data: String) -> Result<(), Error> {
        // The write lands first, then the op fails — so the op savepoint rolls it
        // back and the deposit accumulator frame is discarded (no deposit locked).
        ctx.model().set_blob(data);
        Err(Error::Message("deliberate failure after write".into()))
    }
}
