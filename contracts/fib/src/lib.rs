wit_bindgen::generate!({
    path: "wit/world.wit",
});

// use crate::kontor::contract::stdlib::Foreign;
use kontor::contract::stdlib::*;

struct Contract;

impl Guest for Contract {
    fn fib(n: u64) -> u64 {
        let foreign = Foreign::new("/Users/spora/opt/Kontor/contracts/target/wasm32-unknown-unknown/debug/sum.wasm");
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
