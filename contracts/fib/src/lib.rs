macros::contract!(name = "fib");

// macros::import!(name = "sum", path = "../sum/wit/contract.wit");
mod sum {
    use wasm_wave::wasm::WasmValue;

    use super::foreign;

    const CONTRACT_ID: &str = "sum";

    #[derive(Clone)]
    pub struct SumArgs {
        pub x: u64,
        pub y: u64,
    }

    impl From<SumArgs> for wasm_wave::value::Value {
        fn from(value: SumArgs) -> Self {
            wasm_wave::value::Value::make_record(
                &wasm_wave::value::Type::record(vec![
                    ("x".to_string(), wasm_wave::value::Type::U64),
                    ("y".to_string(), wasm_wave::value::Type::U64),
                ])
                .unwrap(),
                vec![
                    ("x", wasm_wave::value::Value::make_u64(value.x)),
                    ("y", wasm_wave::value::Value::make_u64(value.y)),
                ],
            )
            .unwrap()
        }
    }

    pub fn sum(args: SumArgs) -> u64 {
        let expr = format!(
            "sum({})",
            wasm_wave::to_string(&wasm_wave::value::Value::from(args)).unwrap(),
        );
        let result = foreign::call(CONTRACT_ID, expr.as_str());
        result.parse::<u64>().unwrap_or(0)
    }
}

impl Guest for Fib {
    fn fib(n: u64) -> u64 {
        match n {
            0 | 1 => n,
            _ => sum::sum(sum::SumArgs {
                x: Self::fib(n - 1),
                y: Self::fib(n - 2),
            }),
        }
    }
}

export!(Fib);
