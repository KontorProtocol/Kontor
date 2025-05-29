use bitcoin::XOnlyPublicKey;
use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum OpReturnData {
    A {
        #[serde(rename = "o")]
        output_index: u32,
    }, // attach
    S {
        #[serde(rename = "d")]
        destination: Vec<u8>,
    }, // swap
    D {
        #[serde(rename = "d")]
        destination: XOnlyPublicKey,
    }, // detach
}
