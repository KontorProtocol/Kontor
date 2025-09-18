use stdlib::*;

contract!(name = "proxy");

#[derive(Clone, Default, Storage)]
struct StoredContractAddress {
    name: String,
    height: i64,
    tx_index: i32,
}

#[derive(Clone, Default, StorageRoot)]
struct ProxyStorage {
    contract_address: StoredContractAddress,
}

impl Guest for Proxy {
    fn fallback(ctx: &FallContext, expr: String) -> String {
        let _ctx = &ctx.view_context();
        let stored = storage(_ctx).contract_address(_ctx);
        let contract_address = ContractAddress {
            name: stored.name(_ctx),
            height: stored.height(_ctx),
            tx_index: stored.tx_index(_ctx) as i64,
        };
        foreign::call(ctx.signer(), &contract_address, &expr)
    }

    fn init(ctx: &ProcContext) {
        ProxyStorage {
            contract_address: StoredContractAddress {
                name: "fib".to_string(),
                height: 0,
                tx_index: 0,
            },
        }
        .init(ctx)
    }

    fn get_contract_address(ctx: &ViewContext) -> ContractAddress {
        let stored = storage(ctx).contract_address(ctx);
        ContractAddress {
            name: stored.name(ctx),
            height: stored.height(ctx),
            tx_index: stored.tx_index(ctx) as i64,
        }
    }

    fn set_contract_address(ctx: &ProcContext, contract_address: ContractAddress) {
        storage(ctx).set_contract_address(ctx, StoredContractAddress {
            name: contract_address.name,
            height: contract_address.height,
            tx_index: contract_address.tx_index as i32,
        });
    }
}
