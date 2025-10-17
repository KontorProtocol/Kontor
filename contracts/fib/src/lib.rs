use stdlib::*;

contract!(name = "fib");

interface!(name = "arith", path = "arith/wit");

#[derive(Clone, Default, Storage)]
struct FibValue {
    pub value: u64,
}

#[derive(Clone, Default, StorageRoot)]
struct FibStorage {
    pub cache: Map<u64, FibValue>,
}

impl Fib {
    fn raw_fib(ctx: &ProcContext, arith_address: ContractAddress, n: u64) -> u64 {
        let cache = storage(ctx).cache();
        if let Some(v) = cache.get(ctx, n).map(|v| v.value(ctx)) {
            return v;
        }

        let value = match n {
            0 | 1 => n,
            _ => {
                arith::eval(
                    &arith_address,
                    ctx.signer(),
                    Self::raw_fib(ctx, arith_address.clone(), n - 1),
                    arith::Op::Sum(arith::Operand {
                        y: Self::raw_fib(ctx, arith_address.clone(), n - 2),
                    }),
                )
                .value
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

    fn fib(ctx: &ProcContext, arith_address: ContractAddress, n: u64) -> u64 {
        Self::raw_fib(ctx, arith_address, n)
    }

    fn fib_of_sub(
        ctx: &ProcContext,
        arith_address: ContractAddress,
        x: String,
        y: String,
    ) -> Result<u64, Error> {
        let n = arith::checked_sub(&arith_address, &x, &y)?;
        Ok(Self::fib(ctx, arith_address, n))
    }

    fn cached_values(ctx: &ViewContext) -> Vec<u64> {
        storage(ctx).cache().keys(ctx).collect()
    }
}
