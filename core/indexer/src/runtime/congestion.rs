use crate::runtime::Runtime;
use crate::testlib_exports::*;

import!(
    name = "congestion",
    mod_name = "api",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/congestion/wit",
    public = true,
);

pub fn address() -> ContractAddress {
    ContractAddress {
        name: "congestion".to_string(),
        height: 0,
        tx_index: 0,
    }
}
