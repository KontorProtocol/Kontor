use stdlib::*;

contract!(name = "fib");

// TODO: Fix import! macro for cross-contract calls
// import!(name = "arith", height = 0, tx_index = 0, path = "arith/wit");

#[derive(Clone, Default, Storage)]
struct FibValue {
    pub value: u64,
}

#[derive(Clone, Default, StorageRoot)]
struct FibStorage {
    pub cache: Map<u64, FibValue>,
}

impl Fib {
    fn raw_fib(ctx: &ProcContext, n: u64) -> u64 {
        let cache = storage(ctx).cache();
        if let Some(v) = cache.get(ctx, n).map(|v| v.value(ctx)) {
            return v;
        }

        let value = match n {
            0 | 1 => n,
            _ => {
                // TODO: Re-enable when import! is fixed
                // arith::eval(
                //     ctx.signer(),
                //     Self::raw_fib(ctx, n - 1),
                //     arith::Op::Sum(arith::Operand {
                //         y: Self::raw_fib(ctx, n - 2),
                //     }),
                // )
                // .value
                Self::raw_fib(ctx, n - 1) + Self::raw_fib(ctx, n - 2)
            }
        };
        cache.set(ctx, n, FibValue { value });
        value
    }
}

impl Guest for Fib {
    fn init(ctx: &ProcContext) {
        FibStorage {
            cache: Map::new(&[(0, FibValue { value: 0 })]),
        }
        .init(ctx);
    }

    fn fib(ctx: &ProcContext, n: u64) -> u64 {
        Self::raw_fib(ctx, n)
    }

    fn fib_of_sub(ctx: &ProcContext, x: String, y: String) -> Result<u64, Error> {
        // TODO: Re-enable when import! is fixed
        // let n = arith::checked_sub(&x, &y)?;
        let x_val = x.parse::<u64>()
            .map_err(|e| Error::Message(format!("Failed to parse x: {}", e)))?;
        let y_val = y.parse::<u64>()
            .map_err(|e| Error::Message(format!("Failed to parse y: {}", e)))?;
        let n = x_val.checked_sub(y_val)
            .ok_or(Error::Message("Underflow".to_string()))?;
        Ok(Fib::fib(ctx, n))
    }

    fn cached_values(ctx: &ViewContext) -> Vec<u64> {
        storage(ctx).cache().keys(ctx).collect()
    }
}
