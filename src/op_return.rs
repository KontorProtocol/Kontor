use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum OpReturnData {
    A { o: u32 },     // attach
    S { d: Vec<u8> }, // swap
}
