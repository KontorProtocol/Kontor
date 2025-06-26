wit_bindgen::generate!({
    world: "contract",
    path: "wit",
    generate_all,
});

use kontor::built_in::foreign::*;

struct Contract;

impl Guest for Contract {
    fn fib(n: u64) -> u64 {
        let foreign = Foreign::new("sum");
        match n {
            0 | 1 => n,
            _ => {
                let expr = format!("sum({}, {})", Self::fib(n - 1), Self::fib(n - 2));
                let result = foreign.call(expr.as_str());
                result.parse::<u64>().unwrap_or(0)
            }
        }
    }
}

export!(Contract);
