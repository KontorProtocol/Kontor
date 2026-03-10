use crate::runtime::Runtime;
use crate::testlib_exports::*;

import!(
    name = "staking",
    mod_name = "api",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/staking/wit",
    public = true,
);

pub fn address() -> ContractAddress {
    ContractAddress {
        name: "staking".to_string(),
        height: 0,
        tx_index: 0,
    }
}
