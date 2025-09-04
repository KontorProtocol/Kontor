use crate::numbers::IntegerWrapper;
use stdlib::*;

contract!(name = "token");

#[derive(Clone, Default, Store, Wrapper, Root)]
struct TokenStorage {
    pub ledger: Map<String, Integer>,
}

// TODO move into macro?
impl Default for Integer {
    fn default() -> Self {
        Self {
            value: "0".to_string(),
        }
    }
}

impl Guest for Token {
    fn init(ctx: &ProcContext) {
        TokenStorage::default().init(ctx);
    }

    fn mint(ctx: &ProcContext, n: Integer) {
        let to = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();

        let balance = ledger
            .get(ctx, &to)
            .map(|v| v.load(ctx))
            .unwrap_or_default();
        ledger.set(ctx, to, numbers::add(&balance, &n));
    }

    fn transfer(ctx: &ProcContext, to: String, n: Integer) -> Result<(), Error> {
        let from = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();

        let from_balance = ledger
            .get(ctx, &from)
            .map(|v| v.load(ctx))
            .unwrap_or_default();
        let to_balance = ledger
            .get(ctx, &to)
            .map(|v| v.load(ctx))
            .unwrap_or_default();

        if from_balance < n {
            return Err(Error::Message("insufficient funds".to_string()));
        }

        ledger.set(ctx, from, from_balance - n);
        ledger.set(ctx, to, to_balance + n);
        Ok(())
    }

    fn balance(ctx: &ViewContext, acc: String) -> Option<Integer> {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, acc.clone()).map(|v| v.load(ctx))
    }
}
