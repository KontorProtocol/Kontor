wit_bindgen::generate!({
    path: "wit/world.wit",
});

use kontor::contract::stdlib::*;

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
    
    fn api_twice(address: u64, n: u64) -> u64 {
        let m = Monoid::new(address);
        Self::twice(m, n)
    }

    fn twice(m: Monoid, n: u64) -> u64 {
        m.mappend(n, n)
    }
}

export!(Contract);
