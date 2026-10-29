#![no_std]
contract!(name = "stack-probe");

use core::hint::black_box;
use stdlib::*;

#[derive(Clone, Default, StorageRoot)]
struct StackProbeStorage {
    last_depth: u32,
}

#[inline(never)]
fn recurse_inner(depth: u32, leaf_host_call: bool) -> u32 {
    if depth == 0 {
        if leaf_host_call {
            let _ = testing::host_error();
        }
        return 0;
    }
    // Keep the call non-tail so the requested depth occupies real Wasm frames.
    black_box(recurse_inner(depth - 1, leaf_host_call)).wrapping_add(1)
}

macro_rules! retain_frame {
    ($source:expr, $base:expr, $child:expr) => {{
        let a00 = black_box($source[$base + 0]);
        let a01 = black_box($source[$base + 1]);
        let a02 = black_box($source[$base + 2]);
        let a03 = black_box($source[$base + 3]);
        let a04 = black_box($source[$base + 4]);
        let a05 = black_box($source[$base + 5]);
        let a06 = black_box($source[$base + 6]);
        let a07 = black_box($source[$base + 7]);
        let a08 = black_box($source[$base + 8]);
        let a09 = black_box($source[$base + 9]);
        let a10 = black_box($source[$base + 10]);
        let a11 = black_box($source[$base + 11]);
        let a12 = black_box($source[$base + 12]);
        let a13 = black_box($source[$base + 13]);
        let a14 = black_box($source[$base + 14]);
        let a15 = black_box($source[$base + 15]);
        let a16 = black_box($source[$base + 16]);
        let a17 = black_box($source[$base + 17]);
        let a18 = black_box($source[$base + 18]);
        let a19 = black_box($source[$base + 19]);
        let a20 = black_box($source[$base + 20]);
        let a21 = black_box($source[$base + 21]);
        let a22 = black_box($source[$base + 22]);
        let a23 = black_box($source[$base + 23]);
        let a24 = black_box($source[$base + 24]);
        let a25 = black_box($source[$base + 25]);
        let a26 = black_box($source[$base + 26]);
        let a27 = black_box($source[$base + 27]);
        let a28 = black_box($source[$base + 28]);
        let a29 = black_box($source[$base + 29]);
        let a30 = black_box($source[$base + 30]);
        let a31 = black_box($source[$base + 31]);
        let child = $child;
        child
            .wrapping_add(a00)
            .wrapping_add(a01)
            .wrapping_add(a02)
            .wrapping_add(a03)
            .wrapping_add(a04)
            .wrapping_add(a05)
            .wrapping_add(a06)
            .wrapping_add(a07)
            .wrapping_add(a08)
            .wrapping_add(a09)
            .wrapping_add(a10)
            .wrapping_add(a11)
            .wrapping_add(a12)
            .wrapping_add(a13)
            .wrapping_add(a14)
            .wrapping_add(a15)
            .wrapping_add(a16)
            .wrapping_add(a17)
            .wrapping_add(a18)
            .wrapping_add(a19)
            .wrapping_add(a20)
            .wrapping_add(a21)
            .wrapping_add(a22)
            .wrapping_add(a23)
            .wrapping_add(a24)
            .wrapping_add(a25)
            .wrapping_add(a26)
            .wrapping_add(a27)
            .wrapping_add(a28)
            .wrapping_add(a29)
            .wrapping_add(a30)
            .wrapping_add(a31)
    }};
}

#[inline(never)]
fn wide_recurse_inner(depth: u32, source: &[u64]) -> u64 {
    if depth == 0 {
        return 0;
    }
    retain_frame!(source, 0, wide_recurse_inner(depth - 1, source))
}

#[inline(never)]
fn one_huge_frame(source: &[u64]) -> u64 {
    retain_frame!(
        source,
        0,
        retain_frame!(
            source,
            32,
            retain_frame!(
                source,
                64,
                retain_frame!(
                    source,
                    96,
                    retain_frame!(
                        source,
                        128,
                        retain_frame!(
                            source,
                            160,
                            retain_frame!(source, 192, retain_frame!(source, 224, black_box(0u64)))
                        )
                    )
                )
            )
        )
    )
}

impl Guest for StackProbe {
    fn init(ctx: &ProcContext) -> Contract {
        StackProbeStorage::default().init(ctx);
        ctx.contract()
    }

    fn recurse(ctx: &ProcContext, depth: u32) -> u32 {
        ctx.model().set_last_depth(depth);
        recurse_inner(depth, black_box(false))
    }

    fn leaf_host_recurse(ctx: &ProcContext, depth: u32) -> u32 {
        ctx.model().set_last_depth(depth);
        recurse_inner(depth, black_box(true))
    }

    fn wide_recurse(ctx: &ProcContext, depth: u32, data: Vec<u64>) -> u64 {
        ctx.model().set_last_depth(depth);
        wide_recurse_inner(depth, &data)
    }

    fn huge_frame(ctx: &ProcContext, data: Vec<u64>) -> u64 {
        ctx.model().set_last_depth(1);
        one_huge_frame(&data)
    }

    fn view_recurse(_ctx: &ViewContext, depth: u32) -> u32 {
        recurse_inner(depth, black_box(false))
    }

    fn view_wide_recurse(_ctx: &ViewContext, depth: u32, data: Vec<u64>) -> u64 {
        wide_recurse_inner(depth, &data)
    }

    fn core_recurse(ctx: &CoreContext, depth: u32) -> u32 {
        ctx.proc_context().model().set_last_depth(depth);
        recurse_inner(depth, black_box(false))
    }

    fn core_wide_recurse(ctx: &CoreContext, depth: u32, data: Vec<u64>) -> u64 {
        ctx.proc_context().model().set_last_depth(depth);
        wide_recurse_inner(depth, &data)
    }

    fn last_depth(ctx: &ViewContext) -> u32 {
        ctx.model().last_depth()
    }

    fn reenter(ctx: &ProcContext, next: ContractAddress, depth: u32) -> u32 {
        if depth == 0 {
            return 0;
        }
        ctx.model().set_last_depth(depth);
        let subsequent = ContractAddress {
            tx_index: next.tx_index + 1,
            ..next.clone()
        };
        let expr = format!("reenter({}, {})", to_wave_expr(subsequent), depth - 1);
        let result = foreign::call(Some(ctx.signer()), &next, &expr);
        black_box(from_wave_expr::<u32>(&result)).wrapping_add(1)
    }
}
