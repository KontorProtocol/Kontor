use stdlib::*;

contract!(name = "proxy");

#[derive(Clone, StorageRoot, Default)]
struct ProxyStorage {
    contract_address: Option<ContractAddress>,
}

impl Guest for Proxy {
    fn fallback(ctx: &FallContext, expr: String) -> String {
        let _ctx = &ctx.view_context();
        if let Some(contract_address) = storage(_ctx).contract_address(_ctx) {
            foreign::call(ctx.signer(), &contract_address, &expr)
        } else {
            "".to_string()
        }
    }

    fn init(ctx: &ProcContext) {
        ProxyStorage::default().init(ctx)
    }

    fn get_contract_address(ctx: &ViewContext) -> Option<ContractAddress> {
        storage(ctx).contract_address(ctx)
    }

    fn set_contract_address(ctx: &ProcContext, contract_address: ContractAddress) {
        storage(ctx).set_contract_address(ctx, Some(contract_address));
    }
}
