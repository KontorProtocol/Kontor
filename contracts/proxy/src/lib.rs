use stdlib::*;

contract!(name = "proxy");

// Import needed modules
use kontor::built_in::foreign;

#[derive(Clone, Default)]
struct StoredContractAddress {
    name: String,
    height: i64,
    tx_index: i64,
}

#[derive(Clone, Default)]
struct ProxyStorage {
    contract_address: StoredContractAddress,
}

// Manual storage implementation
fn storage<C>(_ctx: &C) -> ProxyStorage {
    ProxyStorage::default()
}

impl ProxyStorage {
    fn init(&self, ctx: &impl WriteContext) {
        self.contract_address.store(ctx, "contract_address");
    }

    fn contract_address(&self, ctx: &impl ReadContext) -> StoredContractAddress {
        StoredContractAddress::retrieve(ctx, "contract_address").unwrap_or_default()
    }

    fn set_contract_address(&self, ctx: &impl WriteContext, addr: StoredContractAddress) {
        addr.store(ctx, "contract_address");
    }
}

impl StoredContractAddress {
    fn store(&self, ctx: &impl WriteContext, base_path: &str) {
        ctx.__set_str(&format!("{}.name", base_path), &self.name);
        ctx.__set_s64(&format!("{}.height", base_path), self.height);
        ctx.__set_s64(&format!("{}.tx_index", base_path), self.tx_index);
    }

    fn retrieve(ctx: &impl ReadContext, base_path: &str) -> Option<Self> {
        Some(StoredContractAddress {
            name: ctx.__get_str(&format!("{}.name", base_path))?,
            height: ctx.__get_s64(&format!("{}.height", base_path))?,
            tx_index: ctx.__get_s64(&format!("{}.tx_index", base_path))?,
        })
    }
}

impl Guest for Proxy {
    fn fallback(ctx: &FallContext, expr: String) -> String {
        let view_ctx = &ctx.view_context();
        let stored = storage(view_ctx).contract_address(view_ctx);
        let contract_address = ContractAddress {
            name: stored.name,
            height: stored.height,
            tx_index: stored.tx_index,
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
            name: stored.name,
            height: stored.height,
            tx_index: stored.tx_index,
        }
    }

    fn set_contract_address(ctx: &ProcContext, contract_address: ContractAddress) {
        storage(ctx).set_contract_address(ctx, StoredContractAddress {
            name: contract_address.name,
            height: contract_address.height,
            tx_index: contract_address.tx_index,
        });
    }
}
