use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum WitnessData {
    TokenBalance { value: u64, name: String },
}
