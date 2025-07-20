macros::contract!(name = "fib");

use stdlib::{memory_storage, storage_interface::Storage, store_and_return_int};

// Implement Storage trait directly on the generated proc-storage resource
impl Storage for storage::ProcStorage {
    fn get_str(&self, path: String) -> Option<String> {
        self.get_str(&path)
    }

    fn set_str(&self, path: String, value: String) {
        self.set_str(&path, &value);
    }

    fn get_u64(&self, path: String) -> Option<u64> {
        self.get_u64(&path)
    }

    fn set_u64(&self, path: String, value: u64) {
        self.set_u64(&path, value);
    }

    fn exists(&self, path: String) -> bool {
        self.exists(&path)
    }
}

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

// provided by stdlib
trait ReadStorage {
    fn get_str(&self, path: &str) -> Option<String>;
    fn get_u64(&self, path: &str) -> Option<u64>;
    fn exists(&self, path: &str) -> bool;
}

trait WriteStorage {
    fn set_str(&self, path: &str, value: &str);
    fn set_u64(&self, path: &str, value: u64);
}

trait ReadWriteStorage: ReadStorage + WriteStorage {}

impl ReadStorage for context::ViewStorage {
    fn get_str(&self, path: &str) -> Option<String> {
        self.get_str(path)
    }

    fn get_u64(&self, path: &str) -> Option<u64> {
        self.get_u64(path)
    }

    fn exists(&self, path: &str) -> bool {
        self.exists(path)
    }
}

impl ReadStorage for context::ProcStorage {
    fn get_str(&self, path: &str) -> Option<String> {
        self.get_str(path)
    }

    fn get_u64(&self, path: &str) -> Option<u64> {
        self.get_u64(path)
    }

    fn exists(&self, path: &str) -> bool {
        self.exists(path)
    }
}

impl WriteStorage for context::ProcStorage {
    fn set_str(&self, path: &str, value: &str) {
        self.set_str(path, value)
    }

    fn set_u64(&self, path: &str, value: u64) {
        self.set_u64(path, value)
    }
}

impl ReadWriteStorage for context::ProcStorage {}

trait ReadContext {
    fn read_storage(&self) -> impl ReadStorage;
}

trait WriteContext {
    fn write_storage(&self) -> impl WriteStorage;
}

trait ReadWriteContext: ReadContext + WriteContext {}

impl ReadContext for &context::ViewContext {
    fn read_storage(&self) -> impl ReadStorage {
        self.storage()
    }
}

impl ReadContext for &context::ProcContext {
    fn read_storage(&self) -> impl ReadStorage {
        self.storage()
    }
}

impl WriteContext for &context::ProcContext {
    fn write_storage(&self) -> impl WriteStorage {
        self.storage()
    }
}

impl ReadWriteContext for &context::ProcContext {}

trait Store {
    fn __set(&self, storage: impl WriteStorage, path: &str);
}

struct Map<K: ToString, V: Store> {
    _k: std::marker::PhantomData<K>,
    _v: std::marker::PhantomData<V>,
}

// #[storage]
struct FibValue {
    value: u64,
}

// generated
impl Store for FibValue {
    fn __set(&self, storage: impl WriteStorage, path: &str) {
        storage.set_u64(&[path, "value"].join("."), self.value);
    }
}

// generated
struct FibValueWrapper {
    pub prefix: String,
}

impl FibValueWrapper {
    pub fn value(&self, ctx: impl ReadContext) -> u64 {
        ctx.read_storage()
            .get_u64(&[&self.prefix, "value"].join("."))
            .unwrap()
    }

    pub fn set_value(&self, ctx: impl WriteContext, value: u64) {
        ctx.write_storage()
            .set_u64(&[&self.prefix, "value"].join("."), value)
    }
}

// #[root_storage]
struct FibStorage {
    cache: Map<String, FibValue>,
}

struct FibStorageCacheWrapper {
    pub prefix: String,
}

impl FibStorageCacheWrapper {
    pub fn get<K: ToString>(&self, ctx: impl ReadContext, key: K) -> Option<FibValueWrapper> {
        ctx.read_storage()
            .exists(&format!("{}.cache.{}.", &self.prefix, key.to_string()))
            .then_some(FibValueWrapper {
                prefix: [&self.prefix, "cache", &key.to_string()].join("."),
            })
    }

    pub fn set<K: ToString>(&self, ctx: impl WriteContext, key: K, value: FibValue) {
        value.__set(
            ctx.write_storage(),
            &[&self.prefix, "cache", &key.to_string()].join("."),
        )
    }
}

// generated
struct Storage;

impl Storage {
    pub fn cache() -> FibStorageCacheWrapper {
        FibStorageCacheWrapper {
            prefix: "fib".to_string(),
        }
    }
}

impl Fib {
    fn raw_fib(ctx: &ProcContext, n: u64) -> u64 {
        let cache = Storage::cache();
        if let Some(v) = cache.get(n).value(ctx.storage()) {
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
    fn fib(ctx: &ProcContext, n: u64) -> u64 {
        let storage = memory_storage::MemoryStorage::new();
        let _storage = ctx.storage();
        store_and_return_int(&storage, "fib".to_string(), Self::raw_fib(ctx, n))
    }
}

export!(Fib);
