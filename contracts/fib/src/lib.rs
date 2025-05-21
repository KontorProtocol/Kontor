#[allow(warnings)]
mod bindings;

use bindings::Guest;
use bindings::Monoid;
struct Component;

impl Guest for Component {
    fn fib(n: u64) -> u64 {
        match n {
            0 | 1 => n,
            _ => {
                let m = Monoid::new(0);
                m.mappend(Self::fib(n - 1), Self::fib(n - 2))
            }
        }
    }
}

bindings::export!(Component with_types_in bindings);
