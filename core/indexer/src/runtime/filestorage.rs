use crate::runtime::Runtime;
use crate::testlib_exports::*;

import!(
    name = "filestorage",
    mod_name = "api",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/filestorage/wit",
    public = true,
);

pub fn address() -> ContractAddress {
    ContractAddress {
        name: "filestorage".to_string(),
        height: 0,
        tx_index: 0,
    }
}
