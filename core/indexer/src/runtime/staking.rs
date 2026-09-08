use crate::runtime::Runtime;
use crate::testlib_exports::*;

#[cfg(test)]
mod reward_tests;
#[cfg(test)]
mod slash_tests;
#[cfg(test)]
mod tests;

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
