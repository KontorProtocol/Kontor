use crate::runtime::Runtime;
use crate::testlib_exports::*;

import!(
    name = "registry",
    mod_name = "api",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/registry/wit",
    public = true,
);

pub fn address() -> ContractAddress {
    ContractAddress {
        name: "registry".to_string(),
        height: 0,
        tx_index: 0,
    }
}

