use crate::runtime::Runtime;
use crate::testlib_exports::*;

import!(
    name = "token",
    mod_name = "api",
    height = 0,
    tx_index = 0,
    path = "../native-contracts/token/wit",
    public = true,
);

pub fn address() -> ContractAddress {
    ContractAddress {
        name: "token".to_string(),
        height: 0,
        tx_index: 0,
    }
}
