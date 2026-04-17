#![no_std]
contract!(name = "registry");

use stdlib::*;

#[derive(Clone, Default, StorageRoot)]
struct RegistryStorage {}

impl Guest for Registry {
    fn init(ctx: &ProcContext) {
        RegistryStorage::default().init(ctx);
    }

    fn registered(_ctx: &CoreContext) {}
}
