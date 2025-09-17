use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use wasm_wave::value::Value;
use anyhow::Result;

/// Unique resource handle
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct ResourceHandle {
    contract_id: i64,
    resource_id: u64,
}

impl ResourceHandle {
    pub fn new(contract_id: i64, resource_id: u64) -> Self {
        Self { contract_id, resource_id }
    }
}

/// Resource data stored in the manager
#[derive(Debug, Clone)]
pub struct ResourceData {
    pub resource_id: String,  // Changed from resource_type to match usage
    pub payload: Vec<u8>, // WAVE-encoded data
    pub owner: Option<i64>, // Contract ID that owns this resource
}

/// Manager for runtime resources across all contracts
#[derive(Debug, Clone)]
pub struct ResourceManager {
    resources: Arc<Mutex<HashMap<ResourceHandle, ResourceData>>>,
    next_id: Arc<Mutex<HashMap<i64, u64>>>, // Next resource ID per contract
}

impl ResourceManager {
    pub fn new() -> Self {
        Self {
            resources: Arc::new(Mutex::new(HashMap::new())),
            next_id: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Create a new resource and return its handle
    pub fn create_resource(
        &self,
        contract_id: i64,
        resource_type: String,
        payload: Vec<u8>,
    ) -> Result<ResourceHandle> {
        let mut next_id = self.next_id.lock().unwrap();
        let id = next_id.entry(contract_id).or_insert(1);
        let resource_id = *id;
        *id += 1;

        let handle = ResourceHandle::new(contract_id, resource_id);
        
        let mut resources = self.resources.lock().unwrap();
        resources.insert(handle, ResourceData {
            resource_id: resource_type,  // Using resource_id field name
            payload,
            owner: Some(contract_id),
        });

        Ok(handle)
    }

    /// Take ownership of a resource (consume it)
    pub fn take_resource(&self, handle: ResourceHandle) -> Result<ResourceData> {
        let mut resources = self.resources.lock().unwrap();
        resources.remove(&handle)
            .ok_or_else(|| anyhow::anyhow!("Resource not found or already consumed: {:?}", handle))
    }

    /// Get resource data without consuming (for inspection)
    pub fn peek_resource(&self, handle: ResourceHandle) -> Result<ResourceData> {
        let resources = self.resources.lock().unwrap();
        resources.get(&handle)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("Resource not found: {:?}", handle))
    }
    
    /// Create a resource using handle-based approach
    pub fn resource_create(
        &self,
        contract_id: i64,
        resource_type: String,
        payload: Vec<u8>,
    ) -> Result<i32> {
        let handle = self.create_resource(contract_id, resource_type, payload)?;
        Ok(handle.resource_id as i32)
    }
    
    /// Take a resource using handle-based approach
    pub fn resource_take(
        &self,
        contract_id: i64,
        handle: i32,
        resource_type: &str,
    ) -> Result<ResourceData> {
        let resource_handle = ResourceHandle::new(contract_id, handle as u64);
        self.take_resource(resource_handle)
    }
    
    /// Drop a resource
    pub fn resource_drop(&self, contract_id: i64, handle: i32) -> Result<()> {
        let resource_handle = ResourceHandle::new(contract_id, handle as u64);
        let mut resources = self.resources.lock().unwrap();
        resources.remove(&resource_handle)
            .ok_or_else(|| anyhow::anyhow!("Resource not found: {:?}", resource_handle))?;
        Ok(())
    }
    
    /// Transfer a resource between contracts
    pub fn resource_transfer(
        &self,
        from_contract: i64,
        to_contract: i64,
        handle: i32,
    ) -> Result<()> {
        let old_handle = ResourceHandle::new(from_contract, handle as u64);
        let mut resources = self.resources.lock().unwrap();
        
        let mut resource = resources.remove(&old_handle)
            .ok_or_else(|| anyhow::anyhow!("Resource not found: {:?}", old_handle))?;
        
        // Update owner
        resource.owner = Some(to_contract);
        
        // Create new handle for destination contract
        let mut next_id = self.next_id.lock().unwrap();
        let id = next_id.entry(to_contract).or_insert(1);
        let new_handle = ResourceHandle::new(to_contract, *id);
        *id += 1;
        
        resources.insert(new_handle, resource);
        Ok(())
    }

    /// Drop a resource explicitly
    pub fn drop_resource(&self, handle: ResourceHandle) -> Result<()> {
        let mut resources = self.resources.lock().unwrap();
        resources.remove(&handle);
        Ok(())
    }

    /// Transfer ownership of a resource to another contract
    pub fn transfer_resource(
        &self,
        handle: ResourceHandle,
        new_owner: i64,
    ) -> Result<()> {
        let mut resources = self.resources.lock().unwrap();
        let resource = resources.get_mut(&handle)
            .ok_or_else(|| anyhow::anyhow!("Resource not found: {:?}", handle))?;
        
        resource.owner = Some(new_owner);
        Ok(())
    }

    /// Check if a resource exists
    pub fn resource_exists(&self, handle: ResourceHandle) -> bool {
        let resources = self.resources.lock().unwrap();
        resources.contains_key(&handle)
    }

    /// Clean up all resources owned by a contract (e.g., on transaction completion)
    pub fn cleanup_contract_resources(&self, contract_id: i64) {
        let mut resources = self.resources.lock().unwrap();
        resources.retain(|handle, data| {
            !(handle.contract_id == contract_id || data.owner == Some(contract_id))
        });
    }
}

impl Default for ResourceManager {
    fn default() -> Self {
        Self::new()
    }
}

/// Host functions that contracts can call for resource management
pub mod host_functions {
    use super::*;
    
    /// Create a new resource
    pub fn resource_create(
        manager: &ResourceManager,
        contract_id: i64,
        resource_type: &str,
        payload: &[u8],
    ) -> Result<u64> {
        let handle = manager.create_resource(
            contract_id,
            resource_type.to_string(),
            payload.to_vec(),
        )?;
        Ok(handle.resource_id)
    }

    /// Take (consume) a resource
    pub fn resource_take(
        manager: &ResourceManager,
        contract_id: i64,
        resource_id: u64,
    ) -> Result<Vec<u8>> {
        let handle = ResourceHandle::new(contract_id, resource_id);
        let data = manager.take_resource(handle)?;
        Ok(data.payload)
    }

    /// Drop a resource
    pub fn resource_drop(
        manager: &ResourceManager,
        contract_id: i64,
        resource_id: u64,
    ) -> Result<()> {
        let handle = ResourceHandle::new(contract_id, resource_id);
        manager.drop_resource(handle)
    }

    /// Transfer a resource to another contract
    pub fn resource_transfer(
        manager: &ResourceManager,
        from_contract: i64,
        to_contract: i64,
        resource_id: u64,
    ) -> Result<()> {
        let handle = ResourceHandle::new(from_contract, resource_id);
        manager.transfer_resource(handle, to_contract)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_resource_lifecycle() {
        let manager = ResourceManager::new();
        
        // Create a resource
        let handle = manager.create_resource(
            1, // contract_id
            "Balance".to_string(),
            vec![1, 2, 3, 4], // dummy payload
        ).unwrap();
        
        assert!(manager.resource_exists(handle));
        
        // Take the resource
        let data = manager.take_resource(handle).unwrap();
        assert_eq!(data.payload, vec![1, 2, 3, 4]);
        
        // Resource should be consumed
        assert!(!manager.resource_exists(handle));
        
        // Taking again should fail
        assert!(manager.take_resource(handle).is_err());
    }

    #[test]
    fn test_resource_transfer() {
        let manager = ResourceManager::new();
        
        // Create a resource owned by contract 1
        let handle = manager.create_resource(
            1,
            "Token".to_string(),
            vec![5, 6, 7, 8],
        ).unwrap();
        
        // Transfer to contract 2
        manager.transfer_resource(handle, 2).unwrap();
        
        // Verify ownership changed
        let data = manager.peek_resource(handle).unwrap();
        assert_eq!(data.owner, Some(2));
    }
}