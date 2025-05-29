wit_bindgen::generate!({
    path: "wit/world.wit",
});

struct Contract;

impl Guest for Contract {
    fn fib(n: u64) -> u64 {
        match n {
            0 | 1 => n,
            _ => {
                let m = Monoid::new(0);
                m.mappend(Self::fib(n - 1), Self::fib(n - 2))
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
