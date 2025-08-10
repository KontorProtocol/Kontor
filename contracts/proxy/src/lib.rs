#![allow(dead_code)]

macros::contract!(name = "proxy");

#[derive(Clone)]
struct ProxyStorage {
    contract_address: foreign::ContractAddress,
}

impl Store for ProxyStorage {
    fn __set(&self, ctx: &impl WriteContext, base_path: DotPathBuf) {
        self.contract_address
            .__set(ctx, base_path.push("contract_address"))
    }
}

// generated
impl ProxyStorage {
    pub fn init(&self, ctx: &impl WriteContext) {
        self.__set(ctx, DotPathBuf::new())
    }
}

struct Storage;

impl Storage {
    pub fn contract_address(ctx: &impl ReadContext) -> foreign::ContractAddress {
        let base_path = DotPathBuf::new().push("contract_address");
        foreign::ContractAddress {
            name: ctx.read_storage().get_str(&base_path.push("name")).unwrap(),
            height: ctx
                .read_storage()
                .get_s64(&base_path.push("height"))
                .unwrap(),
            tx_index: ctx
                .read_storage()
                .get_s64(&base_path.push("tx_index"))
                .unwrap(),
        }
    }

    pub fn set_contract_address(ctx: &impl WriteContext, contract_address: ContractAddress) {
        contract_address.__set(ctx, DotPathBuf::new().push("contract_address"));
    }
}

impl Guest for Proxy {
    fn fallback(ctx: &FallContext, expr: String) -> String {
        foreign::call(
            &Storage::contract_address(&ctx.view_context()),
            ctx.signer().as_ref(),
            &expr,
        )
    }

    fn init(ctx: &ProcContext) {
        ProxyStorage {
            contract_address: foreign::ContractAddress {
                name: "fib".to_string(),
                height: 0,
                tx_index: 0,
            },
        }
        .init(ctx)
    }

    fn get_contract_address(ctx: &ViewContext) -> ContractAddress {
        Storage::contract_address(ctx)
    }

    fn set_contract_address(ctx: &ProcContext, contract_address: foreign::ContractAddress) {
        Storage::set_contract_address(ctx, contract_address);
    }
}

export!(Proxy);
