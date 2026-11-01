// These fixtures compile guest bindings without invoking guest resource methods.
#![allow(clippy::disallowed_types)]

use stdlib::*;

contract!(name = "query-names", path = "tests/wit/query-names");
import!(
    name = "query-names",
    mod_name = "imported",
    height = 0,
    tx_index = 0,
    path = "tests/wit/query-names",
);

impl Guest for QueryNames {
    fn init(ctx: &ProcContext) -> Contract {
        ctx.contract()
    }

    fn query(_ctx: &ViewContext) -> CursorQuery {
        CursorQuery { value: 1 }
    }

    fn async_query(_ctx: &ViewContext) -> AsyncCursorQuery {
        AsyncCursorQuery { value: 2 }
    }
}

#[test]
fn query_helpers_do_not_shadow_user_records() {
    let _: fn() -> imported::CursorQuery = imported::query;
    let _: fn() -> imported::AsyncCursorQuery = imported::async_query;
}
