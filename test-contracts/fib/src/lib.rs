#![no_std]
contract!(name = "fib");

use stdlib::*;

interface!(name = "arith", path = "../arith/wit");

#[derive(Clone, Default, Storage)]
struct FibValue {
    pub value: u64,
}

// A storage enum (unit + payload variants) to exercise an enum-valued `Deque`.
#[derive(Clone, Storage)]
enum Step {
    Start,
    Value(u64),
}

#[derive(Clone, Default, StorageRoot)]
struct FibStorage {
    pub cache: Map<u64, FibValue>,
    // Exercise struct- and enum-valued `Deque`s (see `init`).
    pub history: Deque<FibValue>,
    pub steps: Deque<Step>,
}

impl Fib {
    fn raw_fib(ctx: &ProcContext, arith_address: ContractAddress, n: u64) -> u64 {
        let cache = ctx.model().cache();
        if let Some(v) = cache.get(&n).map(|v| v.value()) {
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
        cache.set(&n, FibValue { value });
        value
    }
}

impl Guest for Fib {
    fn init(ctx: &ProcContext) -> Contract {
        FibStorage {
            cache: Map::new(&[(0, FibValue { value: 0 })]),
            history: Deque::default(),
            steps: Deque::default(),
        }
        .init(ctx);

        // Enum-valued Deque: get/iter return the enum MODEL (`load()` it), pop
        // returns the owned enum VALUE. Same uniform value-model interface as the
        // struct case — no special handling in the Deque codegen.
        let s = ctx.model().steps();
        s.push_back(Step::Start);
        s.push_back(Step::Value(42));
        assert_eq!(s.len(), 2);
        assert!(matches!(s.get(1).map(|m| m.load()), Some(Step::Value(42))));
        assert!(matches!(s.pop_front(), Some(Step::Start)));
        assert!(matches!(s.pop_back(), Some(Step::Value(42))));
        assert!(s.is_empty());

        // Exercise a struct-valued `Deque` end-to-end at publish time: push (both
        // ends), index/iter via the value MODEL, and pop (returns the owned VALUE,
        // materialized via `load()`). A regression traps here and fails any test
        // that publishes this contract.
        let h = ctx.model().history();
        h.push_back(FibValue { value: 1 });
        h.push_back(FibValue { value: 2 });
        h.push_front(FibValue { value: 0 }); // [0, 1, 2]
        assert_eq!(h.len(), 3);
        assert_eq!(h.get(0).map(|m| m.value()), Some(0));
        assert_eq!(h.back().map(|m| m.value()), Some(2));
        let collected: Vec<u64> = h.iter().map(|m| m.value()).collect();
        assert_eq!(collected, [0, 1, 2]);
        assert_eq!(h.pop_front().map(|v| v.value), Some(0)); // pop → owned value
        assert_eq!(h.pop_back().map(|v| v.value), Some(2));
        assert_eq!(h.len(), 1);
        assert_eq!(h.get(0).map(|m| m.value()), Some(1));

        ctx.contract()
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
        ctx.model().cache().keys().collect()
    }
}
