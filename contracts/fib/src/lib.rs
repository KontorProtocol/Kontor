macros::contract!(name = "fib");

impl Guest for Fib {
    fn fib(n: u64) -> u64 {
        match n {
            0 | 1 => n,
            _ => {
                let expr = format!(
                    "sum({}, {})",
                    to_wave(&WaveValue::from(Self::fib(n - 1))).unwrap(),
                    to_wave(&WaveValue::from(Self::fib(n - 2))).unwrap()
                );
                let result = foreign::call("sum", expr.as_str());
                result.parse::<u64>().unwrap_or(0)
            }
        }
    }
}

export!(Fib);
