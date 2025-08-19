#![allow(dead_code)]

macros::contract!(name = "token");

#[derive(Clone, Store, Wrapper, Root, Default)]
struct TokenStorage {
    // TODO would prefer a larger type than u64, but wit lacks support
    //      would be very nice to not need a complex type for balances
    pub ledger: Map<String, u64>,
}

impl Token {}

impl Guest for Token {
    fn init(ctx: &ProcContext) {
        TokenStorage::default().init(ctx);
    }

    fn mint(ctx: &ProcContext, n: u64) {
        let to = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();

        ledger.set(ctx, to, n);
    }

    fn transfer(ctx: &ProcContext, to: String, n: u64) {
        let from = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();

        let funds = match ledger.get(ctx, from.clone()) {
            Some(v) => v,
            None => panic!("from account doesn't exist"), // TODO never gets here
        };

        if funds < n {
            panic!("insufficient funds");
        }

        ledger.set(ctx, from, funds - n);
        ledger.set(ctx, to, n);
    }

    fn balance(ctx: &ViewContext, acc: String) -> Option<u64> {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, acc)
    }
}

 
