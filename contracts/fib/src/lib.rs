macros::contract!(name = "fib");

use stdlib::{store_and_return_int, memory_storage};

// macros::import!(name = "sum", path = "../sum/wit/contract.wit");
mod sum {
    use wasm_wave::wasm::WasmValue as _;

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

    pub fn sum(args: SumArgs) -> SumReturn {
        let expr = [
            "sum(",
            &wasm_wave::to_string(&wasm_wave::value::Value::from(args)).unwrap(),
            ")",
        ]
        .join("");
        let ret = foreign::call(CONTRACT_ID, expr.as_str());
        wasm_wave::from_str::<wasm_wave::value::Value>(&SumReturn::wave_type(), &ret)
            .unwrap()
            .into()
    }
}

impl Fib {
    fn raw_fib(n: u64) -> u64 {
        match n {
            0 | 1 => n,
            _ => {
                sum::sum(sum::SumArgs {
                    x: Self::raw_fib(n - 1),
                    y: Self::raw_fib(n - 2),
                })
                .value
            }
        }
    }
}

impl Guest for Fib {
    fn fib(n: u64) -> u64 {
        let storage = memory_storage::MemoryStorage::new();
        store_and_return_int(&storage, "fib".to_string(), Self::raw_fib(n))
    }
}

export!(Fib);
