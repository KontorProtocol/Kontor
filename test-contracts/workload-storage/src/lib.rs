#![no_std]
contract!(name = "workload_storage");

use core::ops::Bound;
use stdlib::*;

#[derive(Clone, Default, StorageRoot)]
struct PaginationStorage {
    entries: Map<String, String>,
}

impl Guest for WorkloadStorage {
    fn init(ctx: &ProcContext) -> Contract {
        PaginationStorage::default().init(ctx);
        ctx.contract()
    }

    fn seed_entries(ctx: &ProcContext, start: u32, count: u32) {
        assert!(count <= 128);
        let end = start.checked_add(count).expect("entry range overflow");
        let model = ctx.model();
        for index in start..end {
            model
                .entries()
                .set(&format!("entry-{index:08}"), format!("value-{index:08}"));
        }
    }

    fn entries_page(
        ctx: &ViewContext,
        cursor: Option<String>,
        limit: u32,
        descending: bool,
    ) -> Vec<Entry> {
        assert!(limit <= 128);
        let cursor = cursor.map_or(Bound::Unbounded, Bound::Excluded);
        let bounds = if descending {
            (Bound::Unbounded, cursor)
        } else {
            (cursor, Bound::Unbounded)
        };
        let model = ctx.model();
        let range = model.entries().range(bounds);
        let range = if descending { range.rev() } else { range };
        range
            .entries()
            .take(limit as usize)
            .map(|(key, value)| Entry { key, value })
            .collect()
    }
}
