use stdlib::*;

contract!(name = "token");

#[derive(Clone, Default, StorageRoot)]
struct TokenStorage {
    pub ledger: Map<String, Integer>,
}

impl Guest for Token {
    fn init(ctx: &ProcContext) {
        TokenStorage::default().init(ctx);
    }

    fn mint(ctx: &ProcContext, n: Integer) {
        let to = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();

        let balance = ledger.get(ctx, &to).unwrap_or_default();
        ledger.set(ctx, to, balance + n);
    }

    fn transfer(ctx: &ProcContext, to: String, n: Integer) -> Result<(), Error> {
        let from = ctx.signer().to_string();
        let ledger = storage(ctx).ledger();

        let from_balance = ledger.get(ctx, &from).unwrap_or_default();
        let to_balance = ledger.get(ctx, &to).unwrap_or_default();

        if from_balance < n {
            return Err(Error::Message("insufficient funds".to_string()));
        }

        ledger.set(ctx, from, from_balance - n);
        ledger.set(ctx, to, to_balance + n);
        Ok(())
    }

    fn balance(ctx: &ViewContext, acc: String) -> Option<Integer> {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, acc)
    }

    fn balance_log10(ctx: &ViewContext, acc: String) -> Option<Decimal> {
        let ledger = storage(ctx).ledger();
        ledger.get(ctx, acc).map(|i| numbers::log10(&i.into()))
    }
}
