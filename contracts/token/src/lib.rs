#![allow(dead_code)]

macros::contract!(name = "token");

#[derive(Storage)]
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

        let balance = ledger.get(ctx, to.clone()).unwrap_or_default();
        ledger.set(ctx, to, balance + n);
    }

    fn transfer(ctx: &ProcContext, to: String, n: u64) {
        let from = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();

        let from_balance = ledger.get(ctx, from.clone()).unwrap_or_default();
        let to_balance = ledger.get(ctx, to.clone()).unwrap_or_default();

        if from_balance < n {
            // TODO implement panic or find a different way to revert
            panic!("insufficient funds");
        }

        ledger.set(ctx, from, from_balance - n);
        ledger.set(ctx, to, to_balance + n);
    }

    fn balance(ctx: &ViewContext, acc: String) -> Option<u64> {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, acc)
    }
}
