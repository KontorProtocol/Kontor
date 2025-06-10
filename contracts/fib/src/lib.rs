wit_bindgen::generate!({
    path: "wit/world.wit",
});

use kontor::contract::stdlib::*;
use kontor_macro::storage;

// Option 1: use storage macro on type definition to generate Guest storage interface
// generated guest storage implementation using low-level host provided storage functions
// Option 2: use storage macro on type definition to edit the contract's WIT
// adding a resource definition.
// Host will read and parse the wit and dynamically generate the resource
#[storage] // Option 1 currently implemented
struct ContractStorage {
    prop1: u64,
}

struct Contract;

impl Guest for Contract {
    fn fib(n: u64) -> u64 {
        let fibn = match n {
            0 | 1 => n,
            _ => {
                let m = Monoid::new(0);
                sum(m.mzero(), m.mappend(Self::fib(n - 1), Self::fib(n - 2)))
            }
        };
        // Option 1: generated storage struct
        let mut generated_storage = ContractStorage::new();
        generated_storage.set_prop1(fibn);
        assert_eq!(generated_storage.prop1(), fibn);
        // Option 2: host implemented storage resource
        let resource_storage = Storage::new();
        resource_storage.set_prop1(fibn);
        assert_eq!(resource_storage.prop1(), fibn);
        fibn
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
