#![allow(dead_code)]

macros::contract!(name = "proxy");

#[derive(Clone, Storage)]
struct ProxyStorage {
    contract_address: ContractAddress,
}

impl Guest for Proxy {
    fn fallback(ctx: &FallContext, expr: String) -> String {
        let _ctx = &ctx.view_context();
        let contract_address = storage(_ctx).contract_address(_ctx).load(_ctx);
        foreign::call(&contract_address, ctx.signer().as_ref(), &expr)
    }

    fn init(ctx: &ProcContext) {
        ProxyStorage {
            contract_address: ContractAddress {
                name: "fib".to_string(),
                height: 0,
                tx_index: 0,
            },
        }
        .init(ctx)
    }

    fn get_contract_address(ctx: &ViewContext) -> ContractAddress {
        storage(ctx).contract_address(ctx).load(ctx)
    }

    fn set_contract_address(ctx: &ProcContext, contract_address: ContractAddress) {
        storage(ctx).set_contract_address(ctx, contract_address);
    }
}

 
