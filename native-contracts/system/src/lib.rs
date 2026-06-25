#![no_std]
contract!(name = "system");

use stdlib::*;

#[derive(Clone, Default, StorageRoot)]
struct SystemStorage {}

impl Guest for System {
    fn init(ctx: &ProcContext) -> Contract {
        SystemStorage::default().init(ctx);
        ctx.contract()
    }

    fn registered(_ctx: &ProcContext) {
        // The reactor does the actual proof verification and bls_keys DB
        // write in `Runtime::register_bls_key`. We call this host import
        // purely to charge the caller `Fuel::RegisterBlsKey` units — so
        // on-chain fuel accounting matches what the operation really
        // costs, even though the work happens outside the contract.
        // Traps on insufficient fuel.
        system::register_bls_key();
    }
}
