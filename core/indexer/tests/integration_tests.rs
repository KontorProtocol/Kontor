use anyhow::Result;
use std::collections::HashMap;

/// Mock runtime for testing cross-contract resource transfers
/// This simulates the key parts of the Runtime for testing purposes
#[derive(Debug)]
pub struct MockRuntime {
    /// Simulates the ResourceManager ownership tracking
    resource_ownership: HashMap<u32, i64>,
    /// Simulates resource data storage
    resource_data: HashMap<u32, String>,
    /// Next handle to assign
    next_handle: u32,
    /// Current contract context stack
    contract_stack: Vec<i64>,
}

impl MockRuntime {
    pub fn new() -> Self {
        Self {
            resource_ownership: HashMap::new(),
            resource_data: HashMap::new(),
            next_handle: 1000,
            contract_stack: vec![],
        }
    }

    /// Push a contract context (simulates entering a contract call)
    pub fn push_contract(&mut self, contract_id: i64) {
        self.contract_stack.push(contract_id);
    }

    /// Pop a contract context (simulates exiting a contract call)
    pub fn pop_contract(&mut self) -> Option<i64> {
        self.contract_stack.pop()
    }

    /// Get current contract (simulates stack.peek())
    pub fn current_contract(&self) -> Option<i64> {
        self.contract_stack.last().copied()
    }

    /// Simulate resource_manager::create
    pub fn create_resource(&mut self, resource_id: &str, data: &str) -> Result<u32> {
        let current_contract = self.current_contract()
            .ok_or_else(|| anyhow::anyhow!("No active contract"))?;

        let handle = self.next_handle;
        self.next_handle += 1;

        self.resource_ownership.insert(handle, current_contract);
        self.resource_data.insert(handle, format!("{}:{}", resource_id, data));

        Ok(handle)
    }

    /// Simulate resource_manager::transfer
    pub fn transfer_resource(&mut self, from_contract: i64, to_contract: i64, handle: u32) -> Result<()> {
        let current_contract = self.current_contract()
            .ok_or_else(|| anyhow::anyhow!("No active contract"))?;

        if current_contract != from_contract {
            return Err(anyhow::anyhow!(
                "Contract {} cannot transfer from contract {}",
                current_contract, from_contract
            ));
        }

        match self.resource_ownership.get(&handle) {
            Some(&owner) if owner == from_contract => {
                self.resource_ownership.insert(handle, to_contract);
                Ok(())
            }
            Some(&owner) => {
                Err(anyhow::anyhow!(
                    "Resource {} owned by contract {}, not {}",
                    handle, owner, from_contract
                ))
            }
            None => Err(anyhow::anyhow!("Resource handle {} not found", handle)),
        }
    }

    /// Simulate resource_manager::take
    pub fn take_resource(&mut self, resource_id: &str, handle: u32) -> Result<String> {
        let current_contract = self.current_contract()
            .ok_or_else(|| anyhow::anyhow!("No active contract"))?;

        match self.resource_ownership.get(&handle) {
            Some(&owner) if owner == current_contract => {
                let data = self.resource_data.remove(&handle)
                    .ok_or_else(|| anyhow::anyhow!("Resource data not found"))?;
                self.resource_ownership.remove(&handle);
                Ok(data)
            }
            Some(&owner) => {
                Err(anyhow::anyhow!(
                    "Cannot take resource {}: owned by contract {}, not {}",
                    resource_id, owner, current_contract
                ))
            }
            None => Err(anyhow::anyhow!("Resource handle {} not found", handle)),
        }
    }

    /// Simulate a cross-contract call
    pub fn call_contract(&mut self, target_contract: i64, function: &str, params: &[String]) -> Result<String> {
        // Simulate entering the target contract context
        self.push_contract(target_contract);

        let result = match function {
            "withdraw" => {
                // Simulate token contract withdraw
                let amount = params.get(0).unwrap_or(&"100".to_string()).clone();
                let handle = self.create_resource("balance", &format!("amount:{}", amount))?;
                Ok(format!("resource_handle_{}", handle))
            }
            "deposit" => {
                // Simulate token contract deposit
                if params.len() >= 2 {
                    let _recipient = &params[0];
                    let handle_str = &params[1];
                    if let Ok(handle) = handle_str.parse::<u32>() {
                        let _data = self.take_resource("balance", handle)?;
                        Ok("deposit_success".to_string())
                    } else {
                        Err(anyhow::anyhow!("Invalid handle format"))
                    }
                } else {
                    Err(anyhow::anyhow!("Insufficient parameters"))
                }
            }
            "split" => {
                // Simulate token contract split
                if params.len() >= 2 {
                    let handle_str = &params[0];
                    let amount_str = &params[1];
                    if let (Ok(handle), Ok(_amount)) = (handle_str.parse::<u32>(), amount_str.parse::<u64>()) {
                        let _data = self.take_resource("balance", handle)?;

                        // Create two new resources for split result
                        let split_handle = self.create_resource("balance", &format!("split_amount:{}", amount_str))?;
                        let remainder_handle = self.create_resource("balance", "remainder_amount")?;

                        Ok(format!("split_result:{},{}", split_handle, remainder_handle))
                    } else {
                        Err(anyhow::anyhow!("Invalid split parameters"))
                    }
                } else {
                    Err(anyhow::anyhow!("Insufficient parameters"))
                }
            }
            _ => Err(anyhow::anyhow!("Unknown function: {}", function)),
        };

        // Simulate exiting the target contract context
        self.pop_contract();
        result
    }

    /// Get resource ownership info for debugging
    pub fn get_resource_owner(&self, handle: u32) -> Option<i64> {
        self.resource_ownership.get(&handle).copied()
    }

    /// Get resource data for debugging
    pub fn get_resource_data(&self, handle: u32) -> Option<&String> {
        self.resource_data.get(&handle)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cross_contract_resource_transfer() {
        let mut runtime = MockRuntime::new();

        // Simulate AMM contract calling token contract
        runtime.push_contract(1); // AMM contract

        // Create a balance resource in AMM
        let balance_handle = runtime.create_resource("balance", "amount:1000:token_a").unwrap();
        assert_eq!(runtime.get_resource_owner(balance_handle), Some(1));

        // Transfer resource from AMM to token contract
        assert!(runtime.transfer_resource(1, 2, balance_handle).is_ok());
        assert_eq!(runtime.get_resource_owner(balance_handle), Some(2));

        // Token contract processes the resource
        runtime.push_contract(2); // Token contract
        let data = runtime.take_resource("balance", balance_handle).unwrap();
        assert_eq!(data, "balance:amount:1000:token_a");
        assert_eq!(runtime.get_resource_owner(balance_handle), None); // Resource consumed

        println!("✓ Cross-contract resource transfer flow works");
    }

    #[test]
    fn test_token_withdraw_flow() {
        let mut runtime = MockRuntime::new();

        // Simulate AMM calling token::withdraw
        runtime.push_contract(1); // AMM contract

        let response = runtime.call_contract(2, "withdraw", &["1000".to_string()]).unwrap();

        // Parse response to get resource handle
        assert!(response.starts_with("resource_handle_"));
        let handle_str = response.trim_start_matches("resource_handle_");
        let handle = handle_str.parse::<u32>().unwrap();

        // Verify the resource was created and owned by token contract
        assert_eq!(runtime.get_resource_owner(handle), Some(2));

        // Transfer ownership to AMM
        assert!(runtime.transfer_resource(2, 1, handle).is_ok());
        assert_eq!(runtime.get_resource_owner(handle), Some(1));

        // AMM takes the resource
        let balance_data = runtime.take_resource("balance", handle).unwrap();
        assert!(balance_data.contains("amount:1000"));

        println!("✓ Token withdraw → AMM flow works");
    }

    #[test]
    fn test_amm_deposit_flow() {
        let mut runtime = MockRuntime::new();

        // Simulate AMM calling token::deposit
        runtime.push_contract(1); // AMM contract

        // Create a balance in AMM
        let balance_handle = runtime.create_resource("balance", "amount:500:token_b").unwrap();
        assert_eq!(runtime.get_resource_owner(balance_handle), Some(1));

        // Call token deposit
        let response = runtime.call_contract(
            2,
            "deposit",
            &["user123".to_string(), balance_handle.to_string()]
        ).unwrap();

        assert_eq!(response, "deposit_success");

        // Verify resource was consumed by token contract
        assert_eq!(runtime.get_resource_owner(balance_handle), None);

        println!("✓ AMM → token deposit flow works");
    }

    #[test]
    fn test_balance_split_flow() {
        let mut runtime = MockRuntime::new();

        runtime.push_contract(1); // AMM contract

        // Create a balance to split
        let balance_handle = runtime.create_resource("balance", "amount:1000:token_a").unwrap();

        // Call token split
        let response = runtime.call_contract(
            2,
            "split",
            &[balance_handle.to_string(), "300".to_string()]
        ).unwrap();

        // Parse split result
        assert!(response.starts_with("split_result:"));
        let handles_str = response.trim_start_matches("split_result:");
        let handles: Vec<&str> = handles_str.split(',').collect();
        assert_eq!(handles.len(), 2);

        let split_handle = handles[0].parse::<u32>().unwrap();
        let remainder_handle = handles[1].parse::<u32>().unwrap();

        // Verify both resources are owned by token contract initially
        assert_eq!(runtime.get_resource_owner(split_handle), Some(2));
        assert_eq!(runtime.get_resource_owner(remainder_handle), Some(2));

        // Transfer them back to AMM
        assert!(runtime.transfer_resource(2, 1, split_handle).is_ok());
        assert!(runtime.transfer_resource(2, 1, remainder_handle).is_ok());

        // AMM takes ownership
        let split_data = runtime.take_resource("balance", split_handle).unwrap();
        let remainder_data = runtime.take_resource("balance", remainder_handle).unwrap();

        assert!(split_data.contains("split_amount:300"));
        assert!(remainder_data.contains("remainder_amount"));

        println!("✓ Balance split → transfer back flow works");
    }

    #[test]
    fn test_security_validation() {
        let mut runtime = MockRuntime::new();

        runtime.push_contract(1); // Contract 1
        let handle = runtime.create_resource("balance", "amount:100").unwrap();

        runtime.push_contract(2); // Contract 2

        // Contract 2 should not be able to transfer Contract 1's resource
        let result = runtime.transfer_resource(1, 2, handle);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("cannot transfer from contract 1"));

        // Contract 2 should not be able to take Contract 1's resource
        let result = runtime.take_resource("balance", handle);
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("owned by contract 1, not 2"));

        // Verify ownership unchanged
        assert_eq!(runtime.get_resource_owner(handle), Some(1));

        println!("✓ Security validation prevents unauthorized access");
    }

    #[test]
    fn test_end_to_end_amm_flow() {
        let mut runtime = MockRuntime::new();

        // 1. User withdraws tokens from token contracts
        runtime.push_contract(1); // AMM contract

        let token_a_response = runtime.call_contract(2, "withdraw", &["1000".to_string()]).unwrap();
        let token_b_response = runtime.call_contract(3, "withdraw", &["2000".to_string()]).unwrap();

        let handle_a = token_a_response.trim_start_matches("resource_handle_").parse::<u32>().unwrap();
        let handle_b = token_b_response.trim_start_matches("resource_handle_").parse::<u32>().unwrap();

        // 2. Transfer resources to AMM for liquidity provision
        assert!(runtime.transfer_resource(2, 1, handle_a).is_ok());
        assert!(runtime.transfer_resource(3, 1, handle_b).is_ok());

        // 3. AMM takes ownership of both balances
        let balance_a_data = runtime.take_resource("balance", handle_a).unwrap();
        let balance_b_data = runtime.take_resource("balance", handle_b).unwrap();

        assert!(balance_a_data.contains("amount:1000"));
        assert!(balance_b_data.contains("amount:2000"));

        // 4. AMM creates LP balance (simulated)
        let lp_handle = runtime.create_resource("lp_balance", "amount:1414:token_a:token_b").unwrap();
        assert_eq!(runtime.get_resource_owner(lp_handle), Some(1));

        // 5. Later: User withdraws liquidity
        let withdraw_response = runtime.call_contract(2, "withdraw", &["500".to_string()]).unwrap();
        let withdraw_handle = withdraw_response.trim_start_matches("resource_handle_").parse::<u32>().unwrap();

        assert_eq!(runtime.get_resource_owner(withdraw_handle), Some(2));

        println!("✓ End-to-end AMM flow: withdraw → add liquidity → withdraw works");
    }
}