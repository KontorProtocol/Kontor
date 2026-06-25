use crate::runtime::Runtime;
use crate::testlib_exports::*;

import!(
    name = "system",
    mod_name = "api",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/system/wit",
    public = true,
);

pub fn address() -> ContractAddress {
    ContractAddress {
        name: "system".to_string(),
        height: 0,
        tx_index: 0,
    }
}
