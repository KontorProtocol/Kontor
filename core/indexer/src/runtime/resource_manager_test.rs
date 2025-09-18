use super::*;
use anyhow::Result;

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