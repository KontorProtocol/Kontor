use stdlib::*;

contract!(name = "token");

#[derive(Clone, Store, Wrapper, Root)]
struct TokenStorage {
    pub ledger: Map<String, u64>,
}

impl Guest for Token {
    fn init(ctx: &ProcContext) {
        TokenStorage {
            ledger: Map::default(),
        }
        .init(ctx);
    }

    fn mint(ctx: &ProcContext, n: u64) {
        let to = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();

        let balance = ledger.get(ctx, to.clone()).unwrap_or_default();
        ledger.set(ctx, to, balance + n);
    }

    fn transfer(ctx: &ProcContext, to: String, n: u64) -> Result<(), Error> {
        let from = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();

        let from_balance = ledger.get(ctx, from.clone()).unwrap_or_default();
        let to_balance = ledger.get(ctx, to.clone()).unwrap_or_default();

        if from_balance < n {
            return Err(Error::Message("insufficient funds".to_string()));
        }

        ledger.set(ctx, from, from_balance - n);
        ledger.set(ctx, to, to_balance + n);
        Ok(())
    }

    fn balance(ctx: &ViewContext, acc: String) -> Option<u64> {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, acc)
    }
}
