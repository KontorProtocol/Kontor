wit_bindgen::generate!({
    world: "contract",
    path: "wit",
    generate_all,
});

use kontor::built_in::foreign::*;
use wasm_wave::{to_string as to_wave, value::Value};

struct Contract;

impl Guest for Contract {
    fn fib(n: u64) -> u64 {
        let foreign = Foreign::new("sum");
        match n {
            0 | 1 => n,
            _ => {
                let expr = format!(
                    "sum({}, {})",
                    to_wave(&Value::from(Self::fib(n - 1))).unwrap(),
                    to_wave(&Value::from(Self::fib(n - 2))).unwrap()
                );
                let result = foreign.call(expr.as_str());
                result.parse::<u64>().unwrap_or(0)
            }
        }
    }
}

export!(Contract);
