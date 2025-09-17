use anyhow::Result;

use super::built_in::{
    foreign::ContractAddress,
    numbers::Integer,
};

/// Internal representation of an LpBalance resource
#[derive(Debug, Clone)]
pub struct LpBalanceData {
    pub amount: Integer,
    pub token_a: ContractAddress,
    pub token_b: ContractAddress,
    pub owner_contract: i64,  // Which contract instance owns this resource
}

impl LpBalanceData {
    pub fn new(amount: Integer, token_a: ContractAddress, token_b: ContractAddress, owner: i64) -> Self {
        Self {
            amount,
            token_a,
            token_b,
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
}