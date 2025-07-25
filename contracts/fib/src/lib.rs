#![allow(dead_code)]

use stdlib::DotPathBuf;

macros::contract!(name = "fib");

// macros::import!(name = "eval", path = "../eval/wit/contract.wit");
mod eval {
    use wasm_wave::wasm::WasmValue as _;

    use super::context;
    use super::foreign;

    const CONTRACT_NAME: &str = "eval";

    #[derive(Clone)]
    pub struct Operand {
        pub y: u64,
    }

    impl Operand {
        pub fn wave_type() -> wasm_wave::value::Type {
            wasm_wave::value::Type::record([("y", wasm_wave::value::Type::U64)]).unwrap()
        }
    }

    impl From<Operand> for wasm_wave::value::Value {
        fn from(value: Operand) -> Self {
            wasm_wave::value::Value::make_record(
                &Operand::wave_type(),
                [("y", wasm_wave::value::Value::from(value.y))],
            )
            .unwrap()
        }
    }

    impl From<wasm_wave::value::Value> for Operand {
        fn from(value: wasm_wave::value::Value) -> Self {
            let fields = value.unwrap_record();

            let mut y = None;
            for (name, val) in fields {
                match name.as_ref() {
                    "y" => y = Some(val.unwrap_u64()),
                    name => panic!("Unknown field: {name}"),
                }
            }
            let y = y.unwrap();

            Operand { y }
        }
    }

    #[derive(Clone)]
    pub enum Op {
        Id,
        Sum(Operand),
        Mul(Operand),
        Div(Operand),
    }

    impl Op {
        pub fn wave_type() -> wasm_wave::value::Type {
            wasm_wave::value::Type::variant([
                ("id", None),
                ("sum", Some(Operand::wave_type())),
                ("mul", Some(Operand::wave_type())),
                ("div", Some(Operand::wave_type())),
            ])
            .unwrap()
        }
    }

    impl From<Op> for wasm_wave::value::Value {
        fn from(value: Op) -> Self {
            match value {
                Op::Id => wasm_wave::value::Value::make_variant(&Op::wave_type(), "id", None),
                Op::Sum(operand) => wasm_wave::value::Value::make_variant(
                    &Op::wave_type(),
                    "sum",
                    Some(wasm_wave::value::Value::from(operand)),
                ),
                Op::Mul(operand) => wasm_wave::value::Value::make_variant(
                    &Op::wave_type(),
                    "mul",
                    Some(wasm_wave::value::Value::from(operand)),
                ),
                Op::Div(operand) => wasm_wave::value::Value::make_variant(
                    &Op::wave_type(),
                    "div",
                    Some(wasm_wave::value::Value::from(operand)),
                ),
            }
            .unwrap()
        }
    }

    impl From<wasm_wave::value::Value> for Op {
        fn from(value: wasm_wave::value::Value) -> Self {
            let (tag, value) = value.unwrap_variant();
            match tag {
                t if t.eq("id") => Op::Id,
                t if t.eq("sum") => Op::Sum(value.unwrap().into_owned().into()),
                t if t.eq("mul") => Op::Mul(value.unwrap().into_owned().into()),
                t if t.eq("div") => Op::Div(value.unwrap().into_owned().into()),
                _ => panic!("Unknown tag"),
            }
        }
    }

    #[derive(Clone)]
    pub struct EvalReturn {
        pub value: u64,
    }

    impl EvalReturn {
        pub fn wave_type() -> wasm_wave::value::Type {
            wasm_wave::value::Type::record([("value", wasm_wave::value::Type::U64)]).unwrap()
        }
    }

    impl From<EvalReturn> for wasm_wave::value::Value {
        fn from(value: EvalReturn) -> Self {
            wasm_wave::value::Value::make_record(
                &EvalReturn::wave_type(),
                [("value", wasm_wave::value::Value::from(value.value))],
            )
            .unwrap()
        }
    }

    impl From<wasm_wave::value::Value> for EvalReturn {
        fn from(value: wasm_wave::value::Value) -> Self {
            let fields = value.unwrap_record();

            let mut value = None;
            for (name, val) in fields {
                match name.as_ref() {
                    "value" => value = Some(val.unwrap_u64()),
                    name => panic!("Unknown field: {name}"),
                }
            }
            let value = value.unwrap();

            EvalReturn { value }
        }
    }

    pub fn eval(ctx: &context::ProcContext, x: u64, op: Op) -> EvalReturn {
        let expr = format!(
            "eval({}, {})",
            &wasm_wave::to_string(&wasm_wave::value::Value::from(x)).unwrap(),
            &wasm_wave::to_string(&wasm_wave::value::Value::from(op)).unwrap()
        );
        let ret = foreign::call_proc(
            &foreign::ContractAddress {
                name: CONTRACT_NAME.to_string(),
                height: 0,
                tx_index: 0,
            },
            ctx,
            expr.as_str(),
        );
        wasm_wave::from_str::<wasm_wave::value::Value>(&EvalReturn::wave_type(), &ret)
            .unwrap()
            .into()
    }
}

// #[storage]
#[derive(Clone)]
struct FibValue {
    value: u64,
}

// generated
impl Store for FibValue {
    fn __set(&self, ctx: &impl WriteContext, base_path: DotPathBuf) {
        ctx.write_storage()
            .set_u64(&base_path.push("value").to_string(), self.value);
    }
}

// generated
struct FibValueWrapper {
    pub base_path: DotPathBuf,
}

impl FibValueWrapper {
    pub fn new(_: &impl ReadContext, base_path: DotPathBuf) -> Self {
        Self { base_path }
    }

    pub fn value(&self, ctx: impl ReadContext) -> u64 {
        ctx.read_storage()
            .get_u64(&self.base_path.push("value").to_string())
            .unwrap()
    }

    pub fn set_value(&self, ctx: impl WriteContext, value: u64) {
        ctx.write_storage()
            .set_u64(&self.base_path.push("value").to_string(), value)
    }
}

// #[root_storage]
#[derive(Clone)]
struct FibStorage {
    pub cache: Map<u64, FibValue>,
}

// generated
impl Store for FibStorage {
    fn __set(&self, ctx: &impl WriteContext, base_path: DotPathBuf) {
        self.cache.__set(ctx, base_path.push("cache"))
    }
}

// generated
impl FibStorage {
    pub fn init(&self, ctx: &impl WriteContext) {
        self.__set(ctx, DotPathBuf::new())
    }
}

struct FibStorageCacheWrapper {
    pub base_path: DotPathBuf,
}

impl FibStorageCacheWrapper {
    pub fn get(&self, ctx: &impl ReadContext, key: u64) -> Option<FibValueWrapper> {
        let base_path = self.base_path.push(key.to_string());
        ctx.read_storage()
            .exists(&base_path.to_string())
            .then_some(FibValueWrapper::new(ctx, base_path))
    }

    pub fn set(&self, ctx: &impl WriteContext, key: u64, value: FibValue) {
        value.__set(ctx, self.base_path.push(key.to_string()))
    }
}

// generated
struct Storage;

impl Storage {
    pub fn cache() -> FibStorageCacheWrapper {
        FibStorageCacheWrapper {
            base_path: DotPathBuf::new().push("cache"),
        }
    }
}

impl Fib {
    fn raw_fib(ctx: &ProcContext, n: u64) -> u64 {
        let cache = Storage::cache();
        if let Some(v) = cache.get(&ctx, n).map(|v| v.value(ctx)) {
            return v;
        }

        let value = match n {
            0 | 1 => n,
            _ => {
                eval::eval(
                    ctx,
                    Self::raw_fib(ctx, n - 1),
                    eval::Op::Sum(eval::Operand {
                        y: Self::raw_fib(ctx, n - 2),
                    }),
                )
                .value
            }
        };
        cache.set(&ctx, n, FibValue { value });
        value
    }
}

impl Guest for Fib {
    fn init(ctx: &ProcContext) {
        FibStorage {
            cache: Map::new(&[(0, FibValue { value: 0 })]),
        }
        .init(&ctx);
    }

    fn fib(ctx: &ProcContext, n: u64) -> u64 {
        Self::raw_fib(ctx, n)
    }
}

export!(Fib);
