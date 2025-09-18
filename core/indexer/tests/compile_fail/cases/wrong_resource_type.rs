// This test MUST fail to compile - demonstrates Resource<A> vs Resource<B> type safety

use indexer::runtime::{ResourceManager, ContractAddress};
use indexer::runtime::balance;
use indexer::runtime::lp_balance;
use indexer::runtime::numerics;

fn main() {
    let mut manager = ResourceManager::new();

    // Create a Balance resource
    let balance_data = balance::BalanceData::new(
        numerics::u64_to_integer(1000).unwrap(),
        ContractAddress { name: "token".to_string(), height: 1, tx_index: 0 },
        1
    );
    let balance_resource = manager.push_with_owner(balance_data, 1).unwrap();

    // Create an LpBalance resource
    let lp_data = lp_balance::LpBalanceData::new(
        numerics::u64_to_integer(500).unwrap(),
        ContractAddress { name: "token_a".to_string(), height: 1, tx_index: 0 },
        ContractAddress { name: "token_b".to_string(), height: 2, tx_index: 0 },
        1
    );
    let lp_resource = manager.push_with_owner(lp_data, 1).unwrap();

    // This MUST fail to compile: trying to pass Resource<LpBalance> where Resource<Balance> expected
    let _result: &balance::BalanceData = manager.get(&lp_resource).unwrap();
    //                                               ^^^^^^^^^^^
    // ERROR: expected Resource<BalanceData>, found Resource<LpBalanceData>
}