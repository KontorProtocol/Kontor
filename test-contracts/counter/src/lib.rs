#![no_std]
contract!(name = "counter");

use core::ops::Bound;
use stdlib::*;

#[derive(Clone, Default, StorageRoot)]
struct CounterStorage {
    pub value: u64,
    pub blob: String,
    pub entries: Map<String, String>,
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
        // back and the row never enters the footprint (no floor effect).
        ctx.model().set_blob(data);
        Err(Error::Message("deliberate failure after write".into()))
    }

    // Write one map entry — its deposit is stamped to the op's signer, so distinct
    // signers writing distinct keys leaves a map of per-key setters.
    fn set_entry(ctx: &ProcContext, key: String, val: String) {
        ctx.model().entries().set(&key, val);
    }

    // Write an `n`-byte value under `key`, built guest-side from a small arg (so the
    // op expr stays tiny). Distinct keys accumulate footprint for the storage floor.
    fn fill_entry(ctx: &ProcContext, key: String, n: u32) {
        ctx.model().entries().set(&key, "a".repeat(n as usize));
    }

    // Delete one entry — frees that key's row, dropping it from its setter's
    // footprint (the floor relaxes; no token moves). Targeted rather than a
    // whole-map clear: regtest tests share one published instance, each owning
    // its own keys.
    fn remove_entry(ctx: &ProcContext, key: String) {
        ctx.model().entries().remove(&key);
    }

    fn entry_page(ctx: &ViewContext, after: Option<String>, limit: u64) -> MapPage {
        let limit = limit.min(100) as usize;
        if limit == 0 {
            return MapPage {
                items: Vec::new(),
                next: None,
            };
        }
        let bounds = (
            after.map_or(Bound::Unbounded, Bound::Excluded),
            Bound::Unbounded,
        );
        let mut rows: Vec<_> = ctx
            .model()
            .entries()
            .range(bounds)
            .entries()
            .take(limit + 1)
            .collect();
        let next = if rows.len() > limit {
            rows.pop();
            rows.last().map(|(key, _)| key.clone())
        } else {
            None
        };
        MapPage {
            items: rows
                .into_iter()
                .map(|(key, value)| MapEntry { key, value })
                .collect(),
            next,
        }
    }
}
