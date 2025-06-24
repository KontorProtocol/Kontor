wit_bindgen::generate!({
    path: "wit/world.wit",
});

// use crate::kontor::contract::stdlib::Foreign;
use kontor::contract::stdlib::*;

struct Contract;

impl Contract {
    fn fib_inner(foreign: &Foreign, n: u64) -> u64 {
        match n {
            0 | 1 => n,
            _ => {
                let args = format!("{}, {}", Self::fib_inner(foreign, n - 1), Self::fib_inner(foreign, n - 2));
                let result = foreign.call("sum", args.as_str());
                result.parse::<u64>().unwrap_or(0)
            }
        }
    }
}

impl Guest for Contract {
    fn fib(n: u64) -> u64 {
        let foreign = Foreign::new("/Users/spora/opt/Kontor/contracts/target/wasm32-unknown-unknown/debug/sum.wasm");
        Contract::fib_inner(&foreign, n)
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
