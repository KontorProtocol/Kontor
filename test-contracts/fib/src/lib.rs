#![no_std]
contract!(name = "fib");

use built_in_types::context_types::HolderRef;
use built_in_types::numbers_types::{Decimal, Integer};
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

#[derive(Clone, Default, Storage)]
struct Empty {}

#[derive(Clone, Default, Storage)]
struct Rows {
    pub entries: Map<u64, u64>,
}

#[derive(Clone, Default, Storage)]
enum Choice {
    #[default]
    Absent,
    Empty(Empty),
    Rows(Rows),
}

#[derive(Clone, Storage)]
struct VariantRecord {
    pub empty: Option<Empty>,
    pub amount: Option<Decimal>,
    pub owner: Option<Holder>,
    pub address: Option<ContractAddress>,
}

#[derive(Clone, Storage)]
enum Wrapped {
    Amount(Integer),
    Nested(Step),
    Record(VariantRecord),
}

#[derive(Clone, Default, StorageRoot)]
struct FibStorage {
    pub cache: Map<u64, FibValue>,
    // Exercise struct- and enum-valued `Deque`s (see `init`).
    pub history: Deque<FibValue>,
    pub steps: Deque<Step>,
    // Enum-valued Map (no indexes) — exercises a non-primitive enum Map value.
    pub step_map: Map<u64, Step>,
    pub choice: Choice,
    pub optional: Option<Empty>,
    pub optional_value: Option<u64>,
    pub nested: Option<Wrapped>,
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
            step_map: Map::default(),
            ..FibStorage::default()
        }
        .init(ctx);

        // Enum-valued Map: get returns the enum MODEL (`load()` it), set/remove take
        // the value. No indexes, so the index path const-folds out.
        let sm = ctx.model().step_map();
        sm.set(&1, Step::Value(7));
        sm.set(&2, Step::Start);
        assert!(matches!(sm.get(&1).map(|m| m.load()), Some(Step::Value(7))));
        assert!(matches!(sm.get(&2).map(|m| m.load()), Some(Step::Start)));
        assert!(sm.remove(&2));
        assert!(sm.get(&2).is_none());

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

    fn set_variant(ctx: &ProcContext, kind: u64, count: u64, fail: bool) {
        let choice = match kind {
            0 => Choice::Absent,
            1 => Choice::Empty(Empty {}),
            2 => Choice::Rows(Rows {
                entries: Map::new(&(0..count).map(|i| (i, i)).collect::<Vec<_>>()),
            }),
            _ => panic!("unknown variant"),
        };
        ctx.model().set_choice(choice);
        ctx.model()
            .set_optional(if kind == 0 { None } else { Some(Empty {}) });
        ctx.model()
            .set_optional_value(if kind == 0 { None } else { Some(count) });
        assert!(!fail, "abort variant replacement");
    }

    fn variant_state(ctx: &ViewContext) -> Vec<u64> {
        let kind = match ctx.model().choice() {
            ChoiceModel::Absent => 0,
            ChoiceModel::Empty(_) => 1,
            ChoiceModel::Rows(_) => 2,
            ChoiceModel::__Phantom(_, impossible) => match impossible {},
        };
        [
            kind,
            u64::from(ctx.model().optional().is_some()),
            ctx.model().optional_value().unwrap_or(u64::MAX),
        ]
        .to_vec()
    }

    fn mutate_variant(ctx: &ProcContext, key: u64) {
        if let ChoiceWriteModel::Rows(rows) = ctx.model().choice() {
            rows.entries().set(&key, key);
        }
    }

    fn clear_variant(ctx: &ProcContext) {
        if let ChoiceWriteModel::Rows(rows) = ctx.model().choice() {
            let keys: Vec<_> = rows.entries().keys().collect();
            for key in keys {
                rows.entries().remove(&key);
            }
        }
    }

    fn set_nested_variant(ctx: &ProcContext, kind: u64, value: u64) {
        ctx.model().set_nested(match kind {
            0 => None,
            1 => Some(Wrapped::Amount(Integer::from(value))),
            2 => Some(Wrapped::Nested(if value == 0 {
                Step::Start
            } else {
                Step::Value(value)
            })),
            3 => Some(Wrapped::Record(VariantRecord {
                empty: if value == 0 { None } else { Some(Empty {}) },
                amount: Some(Decimal::try_from(value).unwrap()),
                owner: Some(Holder::from_ref(&HolderRef::Core).unwrap()),
                address: Some(ContractAddress {
                    name: "nested".into(),
                    height: value,
                    tx_index: 0,
                }),
            })),
            _ => panic!("unknown nested variant"),
        });
    }

    fn nested_variant_state(ctx: &ViewContext) -> Vec<u64> {
        let result = match ctx.model().nested() {
            None => [0, 0],
            Some(WrappedModel::Amount(value)) => [1, value.to_string().parse().unwrap()],
            Some(WrappedModel::Nested(step)) => match step {
                StepModel::Start => [2, 0],
                StepModel::Value(value) => [2, value],
                StepModel::__Phantom(_, impossible) => match impossible {},
            },
            Some(WrappedModel::Record(record)) => {
                let address = record.address().unwrap();
                assert_eq!(address.name, "nested");
                assert_eq!(record.empty().is_some(), address.height != 0);
                assert_eq!(
                    record.amount().unwrap(),
                    Decimal::try_from(address.height).unwrap()
                );
                assert_eq!(record.owner().unwrap().as_ref(), HolderRef::Core);
                [3, address.height]
            }
            Some(WrappedModel::__Phantom(_, impossible)) => match impossible {},
        };
        result.to_vec()
    }

    fn cached_values(ctx: &ViewContext) -> Vec<u64> {
        ctx.model().cache().keys().collect()
    }
}
