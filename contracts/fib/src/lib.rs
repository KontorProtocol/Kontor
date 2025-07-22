#![allow(dead_code)]

use stdlib::DotPathBuf;

macros::contract!(name = "fib");

// macros::import!(name = "sum", path = "../sum/wit/contract.wit");
mod sum {
    use wasm_wave::wasm::WasmValue as _;

    use super::context;
    use super::foreign;

    const CONTRACT_ID: &str = "sum";

    #[derive(Clone)]
    pub struct SumArgs {
        pub x: u64,
        pub y: u64,
    }

    impl SumArgs {
        pub fn wave_type() -> wasm_wave::value::Type {
            wasm_wave::value::Type::record([
                ("x", wasm_wave::value::Type::U64),
                ("y", wasm_wave::value::Type::U64),
            ])
            .unwrap()
        }
    }

    impl From<SumArgs> for wasm_wave::value::Value {
        fn from(value: SumArgs) -> Self {
            wasm_wave::value::Value::make_record(
                &SumArgs::wave_type(),
                [
                    ("x", wasm_wave::value::Value::from(value.x)),
                    ("y", wasm_wave::value::Value::from(value.y)),
                ],
            )
            .unwrap()
        }
    }

    impl From<wasm_wave::value::Value> for SumArgs {
        fn from(value: wasm_wave::value::Value) -> Self {
            let fields = value.unwrap_record();

            let mut x = None;
            let mut y = None;
            for (name, val) in fields {
                match name.as_ref() {
                    "x" => x = Some(val.unwrap_u64()),
                    "y" => y = Some(val.unwrap_u64()),
                    name => panic!("Unknown field: {name}"),
                }
            }
            let x = x.unwrap();
            let y = y.unwrap();

            SumArgs { x, y }
        }
    }

    #[derive(Clone)]
    pub struct SumReturn {
        pub value: u64,
    }

    impl SumReturn {
        pub fn wave_type() -> wasm_wave::value::Type {
            wasm_wave::value::Type::record([("value", wasm_wave::value::Type::U64)]).unwrap()
        }
    }

    impl From<SumReturn> for wasm_wave::value::Value {
        fn from(value: SumReturn) -> Self {
            wasm_wave::value::Value::make_record(
                &SumReturn::wave_type(),
                [("value", wasm_wave::value::Value::from(value.value))],
            )
            .unwrap()
        }
    }

    impl From<wasm_wave::value::Value> for SumReturn {
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

            SumReturn { value }
        }
    }

    pub fn sum(ctx: &context::ProcContext, args: SumArgs) -> SumReturn {
        let expr = [
            "sum(",
            &wasm_wave::to_string(&wasm_wave::value::Value::from(args)).unwrap(),
            ")",
        ]
        .join("");
        let ret = foreign::call_proc(CONTRACT_ID, ctx, expr.as_str());
        wasm_wave::from_str::<wasm_wave::value::Value>(&SumReturn::wave_type(), &ret)
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
    fn __set(&self, storage: &impl WriteStorage, base_path: DotPathBuf) {
        storage.set_u64(&base_path.push("value").to_string(), self.value);
    }
}

// generated
struct FibValueWrapper {
    pub base_path: DotPathBuf,
}

impl FibValueWrapper {
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
    fn __set(&self, storage: &impl WriteStorage, base_path: DotPathBuf) {
        self.cache.__set(storage, base_path.push("cache"))
    }
}

// generated
impl FibStorage {
    pub fn init(&self, ctx: impl WriteContext) {
        self.__set(&ctx.write_storage(), DotPathBuf::new())
    }
}

struct FibStorageCacheWrapper {
    pub base_path: DotPathBuf,
}

impl FibStorageCacheWrapper {
    pub fn get(&self, ctx: impl ReadContext, key: u64) -> Option<FibValueWrapper> {
        let base_path = self.base_path.push(key.to_string());
        ctx.read_storage()
            .exists(&base_path.to_string())
            .then_some(FibValueWrapper { base_path })
    }

    pub fn set(&self, ctx: impl WriteContext, key: u64, value: FibValue) {
        value.__set(&ctx.write_storage(), self.base_path.push(key.to_string()))
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
        if let Some(v) = cache.get(ctx, n).map(|v| v.value(ctx)) {
            return v;
        }

        let value = match n {
            0 | 1 => n,
            _ => {
                sum::sum(
                    ctx,
                    sum::SumArgs {
                        x: Self::raw_fib(ctx, n - 1),
                        y: Self::raw_fib(ctx, n - 2),
                    },
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

    fn fib(ctx: &ProcContext, n: u64) -> u64 {
        Self::raw_fib(ctx, n)
    }
}

export!(Fib);
