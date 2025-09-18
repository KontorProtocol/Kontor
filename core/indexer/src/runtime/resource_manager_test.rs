use super::ResourceManager;
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