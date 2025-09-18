// This test MUST fail to compile - demonstrates prevention of resource double-use

use std::collections::HashMap;

// Simulate contract resource handling
struct MockBalance {
    amount: u64,
    consumed: bool,
}

impl MockBalance {
    fn consume(mut self) {
        self.consumed = true;
        // Resource is consumed and dropped
    }

    fn amount(&self) -> u64 {
        if self.consumed {
            panic!("Use after consume!");
        }
        self.amount
    }
}

fn main() {
    let balance = MockBalance { amount: 1000, consumed: false };

    // First use: consume the balance
    let amount1 = balance.amount();
    balance.consume(); // Balance is moved and consumed

    // This MUST fail: trying to use balance after consumption
    let amount2 = balance.amount();
    //            ^^^^^^^
    // ERROR: borrow of moved value

    // This demonstrates that linear types prevent double-use
    println!("Used balance twice: {} and {}", amount1, amount2);
}