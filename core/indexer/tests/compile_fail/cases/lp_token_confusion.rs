// This test MUST fail to compile - demonstrates LP shares vs token type separation

use indexer::runtime::{ResourceManager, ContractAddress};
use indexer::runtime::balance;
use indexer::runtime::lp_balance;
use indexer::runtime::numerics;

fn token_operation(_balance: &balance::BalanceData) {
    // Function that expects a token Balance
}

fn lp_operation(_lp_balance: &lp_balance::LpBalanceData) {
    // Function that expects LP shares
}

fn main() {
    let mut manager = ResourceManager::new();

    // Create LP shares
    let lp_data = lp_balance::LpBalanceData::new(
        numerics::u64_to_integer(500).unwrap(),
        ContractAddress { name: "token_a".to_string(), height: 1, tx_index: 0 },
        ContractAddress { name: "token_b".to_string(), height: 2, tx_index: 0 },
        1
    );
    let lp_resource = manager.push_with_owner(lp_data, 1).unwrap();

    // Create token balance
    let balance_data = balance::BalanceData::new(
        numerics::u64_to_integer(1000).unwrap(),
        ContractAddress { name: "token".to_string(), height: 1, tx_index: 0 },
        1
    );
    let balance_resource = manager.push_with_owner(balance_data, 1).unwrap();

    // This MUST fail: passing LP shares where token Balance expected
    token_operation(manager.get(&lp_resource).unwrap());
    //              ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    // ERROR: expected &BalanceData, found &LpBalanceData

    // This MUST fail: passing token Balance where LP shares expected
    lp_operation(manager.get(&balance_resource).unwrap());
    //           ^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
    // ERROR: expected &LpBalanceData, found &BalanceData
}