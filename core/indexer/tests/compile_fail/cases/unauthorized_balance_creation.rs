// This test MUST fail to compile - demonstrates prevention of unauthorized balance creation

use indexer::runtime::{ResourceManager, ContractAddress};
use indexer::runtime::balance;
use indexer::runtime::numerics;

fn main() {
    let mut manager = ResourceManager::new();

    // Attempt to create Balance without proper authorization
    let foreign_token = ContractAddress {
        name: "bitcoin".to_string(),
        height: 100, // Different contract
        tx_index: 0,
    };

    // This should be prevented by the type system or constructor validation
    // In the WIT system, only the token contract should be able to call Balance::new()

    // This MUST fail in a properly secured system:
    // Unauthorized creation of Balance for foreign token
    let unauthorized_balance = balance::BalanceData::new(
        numerics::u64_to_integer(1000000).unwrap(), // Forged amount
        foreign_token,
        1 // Created by contract 1, but claims to be for contract 100's token
    );

    // The type system should prevent this, or at minimum, HostBalance::new should reject it
    let _resource = manager.push_with_owner(unauthorized_balance, 1).unwrap();

    // In a truly secure system, there would be no way for contract 1 to create
    // a Balance that claims to be for contract 100's token
    // This test demonstrates the authorization gap that was fixed
}