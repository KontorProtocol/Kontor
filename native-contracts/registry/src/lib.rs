#![no_std]
contract!(name = "registry");

use stdlib::*;

#[derive(Clone, Default, StorageRoot)]
struct RegistryStorage {}

impl Guest for Registry {
    fn init(ctx: &ProcContext) {
        RegistryStorage::default().init(ctx);
    }

    fn registered(_ctx: &CoreContext) {
        // The reactor does the actual proof verification and bls_keys DB
        // write in `Runtime::register_bls_key`. We call this host import
        // purely to charge the caller `Fuel::RegisterBlsKey` units — so
        // on-chain fuel accounting matches what the operation really
        // costs, even though the work happens outside the contract.
        // Traps on insufficient fuel.
        registry::register_bls_key();
    }
}
