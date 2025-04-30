use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub struct TokenBalance {
    pub value: u64,
    pub name: String,
}

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum WitnessData {
    Attach {
        output_index: u32,
        token_balance: TokenBalance,
    },
    Detach {
        output_index: u32,
        token_balance: TokenBalance,
    }

}
