#![no_std]
contract!(name = "upgrade-fixture");

use stdlib::*;

#[derive(Clone, Default, StorageRoot)]
struct UpgradeFixtureStorage {
    pub version: u64,
}

impl Guest for UpgradeFixture {
    fn init(ctx: &ProcContext) -> Contract {
        // The qualification migration initializes state. Calling init again must
        // not reset the marker, and publishing these bytes alone does not set it.
        ctx.contract()
    }

    fn version(ctx: &ViewContext) -> u64 {
        ctx.model().version()
    }
}
