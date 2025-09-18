// This test MUST fail to compile - demonstrates cross-contract type safety

// Simulate different contract contexts with different resource types

struct TokenABalance {
    amount: u64,
}

struct TokenBBalance {
    amount: u64,
}

// Function expecting TokenA balance
fn deposit_token_a(_balance: TokenABalance) {
    // Only accepts TokenA balances
}

// Function expecting TokenB balance
fn deposit_token_b(_balance: TokenBBalance) {
    // Only accepts TokenB balances
}

fn main() {
    let token_a_balance = TokenABalance { amount: 1000 };
    let token_b_balance = TokenBBalance { amount: 2000 };

    // This MUST fail: passing TokenB balance to TokenA function
    deposit_token_a(token_b_balance);
    //              ^^^^^^^^^^^^^^^^
    // ERROR: expected TokenABalance, found TokenBBalance

    // This MUST fail: passing TokenA balance to TokenB function
    deposit_token_b(token_a_balance);
    //              ^^^^^^^^^^^^^^^^
    // ERROR: expected TokenBBalance, found TokenABalance

    // This demonstrates that different token types cannot be mixed
}