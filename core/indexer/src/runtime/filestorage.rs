use crate::runtime::Runtime;
use crate::testlib_exports::*;

#[cfg(test)]
pub(crate) mod settlement_tests;
#[cfg(test)]
mod tests;

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
