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
        let ledger = ctx.model().ledger();

        let balance = ledger.get(&to).unwrap_or_default();
        ledger.set(to, balance + n);
    }

    fn mint_checked(ctx: &ProcContext, n: Integer) -> Result<(), Error> {
        let to = ctx.signer().to_string();
        let ledger = ctx.model().ledger();

        let balance = ledger.get(&to).unwrap_or_default();
        ledger.set(to, balance.add(n)?);
        Ok(())
    }

    fn transfer(ctx: &ProcContext, to: String, n: Integer) -> Result<(), Error> {
        let from = ctx.signer().to_string();
        let ledger = ctx.model().ledger();

        let from_balance = ledger.get(&from).unwrap_or_default();
        let to_balance = ledger.get(&to).unwrap_or_default();

        if from_balance < n {
            return Err(Error::Message("insufficient funds".to_string()));
        }

        ledger.set(from, from_balance - n);
        ledger.set(to, to_balance + n);
        Ok(())
    }

    fn balance(ctx: &ViewContext, acc: String) -> Option<Integer> {
        ctx.model().ledger().get(acc)
    }

    fn balance_log10(ctx: &ViewContext, acc: String) -> Result<Option<Decimal>, Error> {
        ctx.model()
            .ledger()
            .get(acc)
            .map(|i| Decimal::from(i).log10())
            .transpose()
    }
}
