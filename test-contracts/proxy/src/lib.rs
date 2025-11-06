use stdlib::*;

contract!(name = "proxy");

#[derive(Clone, StorageRoot, Default)]
struct ProxyStorage {
    contract_address: Option<ContractAddress>,
}

impl Guest for Proxy {
    fn fallback(ctx: &FallContext, expr: String) -> String {
        let ctx_ = &ctx.view_context();
        if let Some(contract_address) = ctx_.model().contract_address() {
            foreign::call(ctx.signer(), &contract_address, &expr)
        } else {
            "".to_string()
        }
    }

    fn init(ctx: &ProcContext) {
        ProxyStorage::default().init(ctx)
    }

    fn get_contract_address(ctx: &ViewContext) -> Option<ContractAddress> {
        ctx.model().contract_address()
    }

    fn set_contract_address(ctx: &ProcContext, contract_address: ContractAddress) {
        ctx.model().set_contract_address(Some(contract_address));
    }
}
