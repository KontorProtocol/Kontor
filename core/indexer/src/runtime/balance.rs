use anyhow::Result;
use wasmtime::component::Resource;

use super::built_in::{
    foreign::ContractAddress,
    numbers::Integer,
};

/// Internal representation of a Balance resource
#[derive(Debug, Clone)]
pub struct BalanceData {
    pub amount: Integer,
    pub token: ContractAddress,
    pub owner_contract: i64,  // Which contract instance owns this resource
}

impl BalanceData {
    pub fn new(amount: Integer, token: ContractAddress, owner: i64) -> Self {
        Self {
            amount,
            token,
            owner_contract: owner,
        }
    }

    pub fn is_zero(&self) -> bool {
        // Check if all components of the Integer are zero
        self.amount.r0 == 0 
            && self.amount.r1 == 0 
            && self.amount.r2 == 0 
            && self.amount.r3 == 0
    }

    pub fn split(&self, split_amount: Integer) -> Result<(BalanceData, Option<BalanceData>)> {
        // Use the numbers module to perform the split
        use crate::runtime::numerics;
        use super::built_in::numbers::Ordering;
        
        // Check if split amount is greater than balance
        if numerics::cmp_integer(split_amount.clone(), self.amount.clone())? == Ordering::Greater {
            return Err(anyhow::anyhow!("Split amount exceeds balance"));
        }

        // Calculate remainder
        let remainder = numerics::sub_integer(self.amount.clone(), split_amount.clone())?;
        
        // Create split balance
        let split_balance = BalanceData::new(
            split_amount,
            self.token.clone(),
            self.owner_contract,
        );

        // Create remainder balance if non-zero
        let remainder_balance = if !Self::is_zero_integer(&remainder) {
            Some(BalanceData::new(
                remainder,
                self.token.clone(),
                self.owner_contract,
            ))
        } else {
            None
        };

        Ok((split_balance, remainder_balance))
    }

    fn is_zero_integer(i: &Integer) -> bool {
        i.r0 == 0 && i.r1 == 0 && i.r2 == 0 && i.r3 == 0
    }

    pub fn merge(first: BalanceData, second: BalanceData) -> Result<BalanceData> {
        // Verify both balances are for the same token
        if first.token.name != second.token.name 
            || first.token.height != second.token.height 
            || first.token.tx_index != second.token.tx_index {
            return Err(anyhow::anyhow!("Cannot merge balances from different tokens"));
        }

        // Verify both balances have the same owner
        if first.owner_contract != second.owner_contract {
            return Err(anyhow::anyhow!("Cannot merge balances with different owners"));
        }

        // Add the amounts
        use crate::runtime::numerics;
        let total = numerics::add_integer(first.amount.clone(), second.amount.clone())?;

        Ok(BalanceData::new(
            total,
            first.token,
            first.owner_contract,
        ))
    }
}