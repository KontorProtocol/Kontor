// This test MUST fail to compile - demonstrates move semantics enforcement

use indexer::runtime::{ResourceManager, ContractAddress};
use indexer::runtime::balance;
use indexer::runtime::numerics;

fn use_balance(_balance: balance::BalanceData) {
    // Function that takes ownership of balance
}

fn main() {
    let mut manager = ResourceManager::new();

    let balance_data = balance::BalanceData::new(
        numerics::u64_to_integer(1000).unwrap(),
        ContractAddress { name: "token".to_string(), height: 1, tx_index: 0 },
        1
    );

    let resource = manager.push_with_owner(balance_data, 1).unwrap();

    // Get the balance (this borrows it)
    let balance = manager.get(&resource).unwrap();

    // This MUST fail: trying to move borrowed balance
    use_balance(*balance);
    //          ^^^^^^^^
    // ERROR: cannot move out of borrowed content

    // This MUST also fail: trying to use balance after move
    let _amount = balance.amount.clone();
    //            ^^^^^^^
    // ERROR: borrow of moved value

    // This demonstrates that resource borrowing prevents unauthorized moves
}