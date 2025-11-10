use stdlib::*;

contract!(name = "token");

const BURNER: &str = "burn";

#[derive(Clone, Default, StorageRoot)]
struct TokenStorage {
    pub ledger: Map<String, Decimal>,
    pub total_supply: Decimal,
}

fn mint(model: &TokenStorageWriteModel, to: String, n: Decimal) {
    let ledger = model.ledger();
    let balance = ledger.get(&to).unwrap_or_default();
    ledger.set(to, balance + n);
    model.update_total_supply(|t| t + n);
}

impl Guest for Token {
    fn init(ctx: &ProcContext) {
        TokenStorage::default().init(ctx);
    }

    fn issuance(ctx: &CoreContext, n: Decimal) {
        mint(
            &ctx.proc_context().model(),
            ctx.signer_proc_context().signer().to_string(),
            n,
        );
    }

    fn hold(ctx: &CoreContext, n: Decimal) -> Result<(), Error> {
        Self::transfer(
            &ctx.signer_proc_context(),
            ctx.proc_context().signer().to_string(),
            n,
        )
    }

    fn burn_and_release(ctx: &CoreContext, n: Decimal) -> Result<(), Error> {
        let core = ctx.proc_context();
        Self::burn(&core, n)?;
        Self::transfer(
            &core,
            ctx.signer_proc_context().signer().to_string(),
            core.model()
                .ledger()
                .get(core.signer().to_string())
                .unwrap_or_default(),
        )
    }

    fn mint(ctx: &ProcContext, n: Decimal) {
        mint(&ctx.model(), ctx.signer().to_string(), n);
    }

    fn burn(ctx: &ProcContext, n: Decimal) -> Result<(), Error> {
        Self::transfer(ctx, BURNER.to_string(), n)?;
        ctx.model().update_total_supply(|t| t - n);
        Ok(())
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
            .filter_map(|k| {
                if [BURNER.to_string()].contains(&k) {
                    None
                } else {
                    Some(Balance {
                        value: ctx.model().ledger().get(&k).unwrap_or_default(),
                        key: k,
                    })
                }
            })
            .collect()
    }

    fn total_supply(ctx: &ViewContext) -> Decimal {
        ctx.model().total_supply()
    }
}
