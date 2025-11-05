use stdlib::*;

contract!(name = "token");

#[derive(Clone, Default, StorageRoot)]
struct TokenStorage {
    pub admin: Option<String>,
    pub ledger: Map<String, Decimal>,
    pub total_supply: Decimal,
}

fn mint(model: &TokenStorageWriteModel, to: String, n: Decimal) {
    let ledger = model.ledger();
    let balance = ledger.get(&to).unwrap_or_default();
    ledger.set(to, balance + n);
    model.set_total_supply(model.total_supply() + n);
}

impl Guest for Token {
    fn init(ctx: &ProcContext) {
        TokenStorage::default().init(ctx);
    }

    fn issuance(ctx: &CoreContext, to: String) {
        mint(&ctx.proc_context().model(), to, 10.into());
    }

    fn mint(ctx: &ProcContext, n: Decimal) {
        mint(&ctx.model(), ctx.signer().to_string(), n);
    }

    fn transfer(ctx: &ProcContext, to: String, n: Decimal) -> Result<(), Error> {
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

    fn balance(ctx: &ViewContext, acc: String) -> Option<Decimal> {
        ctx.model().ledger().get(acc)
    }

    fn balances(ctx: &ViewContext) -> Vec<Balance> {
        ctx.model()
            .ledger()
            .keys()
            .map(|k| Balance {
                value: ctx.model().ledger().get(&k).unwrap_or_default(),
                key: k,
            })
            .collect()
    }

    fn total_supply(ctx: &ViewContext) -> Decimal {
        ctx.model().total_supply()
    }
}
