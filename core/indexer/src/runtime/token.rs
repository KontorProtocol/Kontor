use crate::runtime::Runtime;
use crate::testlib_exports::*;

import!(
    name = "token",
    mod_name = "api",
    height = 0,
    tx_index = 0,
    path = "../contracts/token/wit",
    public = true,
);
