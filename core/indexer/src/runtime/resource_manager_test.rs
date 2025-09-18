use super::*;

#[test]
fn test_resource_manager_basic_ownership() {
    let mut manager = ResourceManager::new();

    // Test ownership tracking with simple data
    let data = "test_balance_data".to_string();
    let global_handle = manager.create_global_handle(data, 1).unwrap();

    // Check basic ownership
    assert!(global_handle >= 1000); // Global handles start at 1000
    assert_eq!(manager.get_owner(global_handle), Some(1));
    assert!(manager.is_owned_by(global_handle, 1));
    assert!(!manager.is_owned_by(global_handle, 2));

    println!("✓ Resource creation and ownership tracking works");
}

#[test]
fn test_resource_ownership_transfer() {
    let mut manager = ResourceManager::new();

    let data = "transfer_test_data".to_string();
    let global_handle = manager.create_global_handle(data, 1).unwrap();

    // Test successful transfer from owner
    assert!(manager.transfer_ownership(global_handle, 1, 2).is_ok());
    assert_eq!(manager.get_owner(global_handle), Some(2));

    // Test unauthorized transfer (contract 1 trying to transfer from contract 2)
    let result = manager.transfer_ownership(global_handle, 1, 3);
    assert!(result.is_err());
    assert_eq!(manager.get_owner(global_handle), Some(2)); // Ownership unchanged

    println!("✓ Resource ownership transfer validation works");
}

#[test]
fn test_multiple_resources() {
    let mut manager = ResourceManager::new();

    // Create resources for different contracts
    let handle1 = manager.create_global_handle("data1".to_string(), 1).unwrap();
    let handle2 = manager.create_global_handle("data2".to_string(), 2).unwrap();
    let handle3 = manager.create_global_handle("data3".to_string(), 1).unwrap();

    // Verify each resource has correct ownership
    assert_eq!(manager.get_owner(handle1), Some(1));
    assert_eq!(manager.get_owner(handle2), Some(2));
    assert_eq!(manager.get_owner(handle3), Some(1));

    // Contract 1 can transfer its own resources
    assert!(manager.transfer_ownership(handle1, 1, 3).is_ok());
    assert!(manager.transfer_ownership(handle3, 1, 3).is_ok());

    // But cannot transfer contract 2's resource
    assert!(manager.transfer_ownership(handle2, 1, 3).is_err());

    // Final state
    assert_eq!(manager.get_owner(handle1), Some(3));
    assert_eq!(manager.get_owner(handle2), Some(2)); // Unchanged
    assert_eq!(manager.get_owner(handle3), Some(3));

    println!("✓ Multi-resource ownership management works");
}

#[test]
fn test_resource_manager_edge_cases() {
    let mut manager = ResourceManager::new();

    // Test transfer of non-existent handle
    let result = manager.transfer_ownership(999, 1, 2);
    assert!(result.is_err());
    assert!(result.unwrap_err().to_string().contains("not found"));

    // Test ownership queries for non-existent handle
    assert_eq!(manager.get_owner(999), None);
    assert!(!manager.is_owned_by(999, 1));

    println!("✓ ResourceManager handles edge cases correctly");
}

#[test]
fn test_global_handle_sequencing() {
    let mut manager = ResourceManager::new();

    // Create multiple global handles and verify they increment
    let handle1 = manager.create_global_handle("data1".to_string(), 1).unwrap();
    let handle2 = manager.create_global_handle("data2".to_string(), 2).unwrap();
    let handle3 = manager.create_global_handle("data3".to_string(), 3).unwrap();

    assert_eq!(handle1, 1000);
    assert_eq!(handle2, 1001);
    assert_eq!(handle3, 1002);

    // Verify each has correct ownership
    assert_eq!(manager.get_owner(handle1), Some(1));
    assert_eq!(manager.get_owner(handle2), Some(2));
    assert_eq!(manager.get_owner(handle3), Some(3));

    println!("✓ Global handle sequencing works correctly");
}

#[test]
fn test_balance_creation_with_ownership() {
    let mut manager = ResourceManager::new();

    // Create a balance using the same pattern as HostBalance::new
    let token_addr = ContractAddress {
        name: "test_token".to_string(),
        height: 1,
        tx_index: 0,
    };

    let balance_data = balance::BalanceData::new(
        numerics::u64_to_integer(1000).unwrap(),
        token_addr,
        42, // contract ID
    );

    // Push with ownership tracking
    let resource = manager.push_with_owner(balance_data, 42).unwrap();
    let handle = resource.rep();

    // Verify ownership is tracked correctly
    assert_eq!(manager.get_owner(handle), Some(42));
    assert!(manager.is_owned_by(handle, 42));

    // Verify we can access the balance data
    let balance = manager.get(&resource).unwrap();
    assert_eq!(balance.amount.r0, 1000);
    assert_eq!(balance.owner_contract, 42);
    assert_eq!(balance.token.name, "test_token");

    println!("✓ Balance creation with ownership tracking works");
}

#[test]
fn test_balance_split_ownership_validation() {
    let mut manager = ResourceManager::new();

    // Create a balance owned by contract 1
    let token_addr = ContractAddress {
        name: "split_test_token".to_string(),
        height: 1,
        tx_index: 0,
    };

    let balance_data = balance::BalanceData::new(
        numerics::u64_to_integer(1000).unwrap(),
        token_addr,
        1, // owned by contract 1
    );

    let resource = manager.push_with_owner(balance_data, 1).unwrap();

    // Test that we can access balance data correctly
    let balance = manager.get(&resource).unwrap();
    assert_eq!(balance.owner_contract, 1);
    assert_eq!(balance.amount.r0, 1000);

    // Test that splitting would require proper ownership validation
    // (The actual split logic is in HostBalance::split, which checks ownership)
    let handle = resource.rep();
    assert!(manager.is_owned_by(handle, 1)); // Contract 1 can split
    assert!(!manager.is_owned_by(handle, 2)); // Contract 2 cannot

    // Test deleting the resource (simulating consumption)
    let deleted_balance = manager.delete(resource).unwrap();
    assert_eq!(deleted_balance.amount.r0, 1000);

    // Verify ownership is removed after deletion
    assert_eq!(manager.get_owner(handle), None);

    println!("✓ Balance split ownership validation works");
}

#[test]
fn test_resource_manager_host_functions() {
    let mut manager = ResourceManager::new();

    // Test the create() function pattern
    let test_data = "balance_resource_data".to_string();
    let global_handle = manager.create_global_handle(test_data.clone(), 5).unwrap();

    // Verify the resource was created correctly
    assert!(global_handle >= 1000);
    assert_eq!(manager.get_owner(global_handle), Some(5));

    // Test the transfer() function pattern
    assert!(manager.transfer_ownership(global_handle, 5, 7).is_ok());
    assert_eq!(manager.get_owner(global_handle), Some(7));

    // Test unauthorized transfer (simulating what the host function checks)
    let unauthorized_result = manager.transfer_ownership(global_handle, 5, 8);
    assert!(unauthorized_result.is_err());
    assert!(unauthorized_result.unwrap_err().to_string().contains("owned by contract 7, not 5"));

    // Test the drop() function pattern
    manager.ownership.remove(&global_handle);
    assert_eq!(manager.get_owner(global_handle), None);

    println!("✓ Resource manager host function patterns work correctly");
}

// Integration tests for cross-contract resource transfers

#[test]
fn test_cross_contract_balance_transfer_simulation() {
    let mut manager = ResourceManager::new();

    // Simulate AMM contract (ID 1) withdrawing from token contract (ID 2)

    // 1. Token contract creates a balance for withdrawal
    let token_addr = ContractAddress {
        name: "test_token".to_string(),
        height: 1,
        tx_index: 0,
    };

    let balance_data = balance::BalanceData::new(
        numerics::u64_to_integer(1000).unwrap(),
        token_addr.clone(),
        2, // owned by token contract
    );

    let resource = manager.push_with_owner(balance_data, 2).unwrap();
    let handle = resource.rep();

    // 2. Token contract transfers ownership to AMM contract
    assert!(manager.transfer_ownership(handle, 2, 1).is_ok());
    assert_eq!(manager.get_owner(handle), Some(1));

    // 3. AMM contract can now use the balance
    let balance = manager.get(&resource).unwrap();
    assert_eq!(balance.owner_contract, 2); // Original owner in data
    assert_eq!(balance.amount.r0, 1000);

    // 4. AMM processes the balance (simulating deposit to pool)
    let consumed_balance = manager.delete(resource).unwrap();
    assert_eq!(consumed_balance.amount.r0, 1000);

    // 5. Verify resource is cleaned up
    assert_eq!(manager.get_owner(handle), None);

    println!("✓ Cross-contract balance transfer simulation works");
}

#[test]
fn test_multi_contract_resource_flow() {
    let mut manager = ResourceManager::new();

    // Simulate complex AMM flow: User → Token A → AMM → Token B → User

    // 1. Token A contract creates balance for user withdrawal
    let token_a_addr = ContractAddress {
        name: "token_a".to_string(),
        height: 1,
        tx_index: 0,
    };

    let balance_a = balance::BalanceData::new(
        numerics::u64_to_integer(500).unwrap(),
        token_a_addr.clone(),
        2, // token_a contract ID
    );

    let resource_a = manager.push_with_owner(balance_a, 2).unwrap();
    let handle_a = resource_a.rep();

    // 2. Transfer Token A balance to AMM for swap
    assert!(manager.transfer_ownership(handle_a, 2, 1).is_ok()); // token_a → AMM

    // 3. AMM processes swap, creates Token B balance
    let token_b_addr = ContractAddress {
        name: "token_b".to_string(),
        height: 1,
        tx_index: 1,
    };

    let balance_b = balance::BalanceData::new(
        numerics::u64_to_integer(450).unwrap(), // After swap fees
        token_b_addr.clone(),
        1, // created by AMM
    );

    let resource_b = manager.push_with_owner(balance_b, 1).unwrap();
    let handle_b = resource_b.rep();

    // 4. AMM transfers Token B balance to Token B contract for user deposit
    assert!(manager.transfer_ownership(handle_b, 1, 3).is_ok()); // AMM → token_b

    // 5. Verify final state
    assert_eq!(manager.get_owner(handle_a), Some(1)); // AMM owns input
    assert_eq!(manager.get_owner(handle_b), Some(3)); // Token B owns output

    // 6. Clean up resources
    let _consumed_a = manager.delete(resource_a).unwrap();
    let _consumed_b = manager.delete(resource_b).unwrap();

    assert_eq!(manager.get_owner(handle_a), None);
    assert_eq!(manager.get_owner(handle_b), None);

    println!("✓ Multi-contract resource flow (User → Token A → AMM → Token B → User) works");
}

#[test]
fn test_resource_transfer_security_enforcement() {
    let mut manager = ResourceManager::new();

    // Create resources owned by different contracts
    let balance_1 = balance::BalanceData::new(
        numerics::u64_to_integer(1000).unwrap(),
        ContractAddress { name: "token1".to_string(), height: 1, tx_index: 0 },
        1
    );
    let balance_2 = balance::BalanceData::new(
        numerics::u64_to_integer(2000).unwrap(),
        ContractAddress { name: "token2".to_string(), height: 1, tx_index: 1 },
        2
    );

    let resource_1 = manager.push_with_owner(balance_1, 1).unwrap();
    let resource_2 = manager.push_with_owner(balance_2, 2).unwrap();

    let handle_1 = resource_1.rep();
    let handle_2 = resource_2.rep();

    // Test security: Contract 1 cannot transfer Contract 2's resource
    let unauthorized_transfer = manager.transfer_ownership(handle_2, 1, 3);
    assert!(unauthorized_transfer.is_err());
    assert!(unauthorized_transfer.unwrap_err().to_string().contains("owned by contract 2, not 1"));

    // Test security: Contract 3 cannot transfer anyone's resources
    let no_permission_transfer = manager.transfer_ownership(handle_1, 3, 2);
    assert!(no_permission_transfer.is_err());

    // Verify resources remain with original owners
    assert_eq!(manager.get_owner(handle_1), Some(1));
    assert_eq!(manager.get_owner(handle_2), Some(2));

    // Test legitimate transfers work
    assert!(manager.transfer_ownership(handle_1, 1, 3).is_ok());
    assert_eq!(manager.get_owner(handle_1), Some(3));

    println!("✓ Resource transfer security enforcement works correctly");
}

#[test]
fn test_balance_split_simulation() {
    let mut manager = ResourceManager::new();

    // Simulate the full split operation flow

    // 1. AMM has a balance to split
    let original_amount = numerics::u64_to_integer(1000).unwrap();
    let split_amount = numerics::u64_to_integer(300).unwrap();

    let balance_data = balance::BalanceData::new(
        original_amount.clone(),
        ContractAddress { name: "token_a".to_string(), height: 1, tx_index: 0 },
        1 // AMM contract
    );

    let original_resource = manager.push_with_owner(balance_data, 1).unwrap();
    let original_handle = original_resource.rep();

    // 2. AMM transfers balance to token contract for splitting
    assert!(manager.transfer_ownership(original_handle, 1, 2).is_ok());

    // 3. Token contract splits and creates two new resources
    let split_data = balance::BalanceData::new(
        split_amount.clone(),
        ContractAddress { name: "token_a".to_string(), height: 1, tx_index: 0 },
        2 // token contract
    );
    let remainder_data = balance::BalanceData::new(
        numerics::sub_integer(original_amount, split_amount).unwrap(),
        ContractAddress { name: "token_a".to_string(), height: 1, tx_index: 0 },
        2 // token contract
    );

    let split_resource = manager.push_with_owner(split_data, 2).unwrap();
    let remainder_resource = manager.push_with_owner(remainder_data, 2).unwrap();

    let split_handle = split_resource.rep();
    let remainder_handle = remainder_resource.rep();

    // 4. Token contract transfers split results back to AMM
    assert!(manager.transfer_ownership(split_handle, 2, 1).is_ok());
    assert!(manager.transfer_ownership(remainder_handle, 2, 1).is_ok());

    // 5. Verify AMM receives both split resources
    assert_eq!(manager.get_owner(split_handle), Some(1));
    assert_eq!(manager.get_owner(remainder_handle), Some(1));

    // 6. AMM can access the split balances
    let split_balance = manager.get(&split_resource).unwrap();
    let remainder_balance = manager.get(&remainder_resource).unwrap();

    assert_eq!(split_balance.amount.r0, 300);
    assert_eq!(remainder_balance.amount.r0, 700);

    // 7. Original resource should be consumed by token contract
    // (We don't delete it here since in reality the token contract would have consumed it)

    println!("✓ Balance split simulation with resource transfers works");
}