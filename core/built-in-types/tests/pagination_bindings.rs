// These fixtures compile guest bindings without invoking guest resource methods.
#![allow(clippy::disallowed_types)]

use stdlib::*;

contract!(name = "pagination", path = "tests/wit/pagination");
import!(
    name = "pagination",
    mod_name = "imported",
    height = 0,
    tx_index = 0,
    path = "tests/wit/pagination",
);

impl Guest for Pagination {
    fn init(ctx: &ProcContext) -> Contract {
        ctx.contract()
    }

    fn entries(_ctx: &ViewContext, _pagination: Request) -> EntriesPage {
        EntriesPage {
            items: vec![1, 2],
            next: None,
        }
    }
}

#[test]
fn direct_record_queries_need_no_error_import() {
    // A host test cannot construct a guest context; these calls are type-checked only.
    let _: fn(&ViewContext) = |ctx| {
        let _: Result<EntriesPage, _> = Pagination::entries(ctx).fetch();
        let _: Option<Result<u64, _>> = Pagination::entries(ctx).iter().next();
    };
    assert_eq!(imported::entries().iter().take(0).count(), 0);
}
