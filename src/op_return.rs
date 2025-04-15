use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum OpReturnData {
    Attach { output_index: u32 },
    Swap { destination: String },
}
