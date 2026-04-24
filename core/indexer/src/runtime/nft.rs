use crate::runtime::Runtime;
use crate::testlib_exports::*;

import!(
    name = "nft",
    mod_name = "api",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/nft/wit",
    public = true,
);

pub fn address() -> ContractAddress {
    ContractAddress {
        name: "nft".to_string(),
        height: 0,
        tx_index: 0,
    }
}
