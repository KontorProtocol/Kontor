use stdlib::*;

contract!(name = "token");

const BURNER: &str = "burn";

#[derive(Clone, Default, StorageRoot)]
struct TokenStorage {
    pub ledger: Map<String, Decimal>,
    pub total_supply: Decimal,
}

fn assert_gt_zero(n: Decimal) -> Result<(), Error> {
    if n <= 0.into() {
        return Err(Error::Message("Amount must be positive".to_string()));
    }

    Ok(())
}

fn mint(model: &TokenStorageWriteModel, to: String, n: Decimal) -> Result<(), Error> {
    assert_gt_zero(n)?;
    if n > 1000.into() {
        return Err(Error::Message("Amount exceeds limit".to_string()));
    }
    let ledger = model.ledger();
    let balance = ledger.get(&to).unwrap_or_default();
    ledger.set(to, balance.add(n)?);
    model.try_update_total_supply(|t| t.add(n))?;
    Ok(())
}

impl Guest for Token {
    fn init(ctx: &ProcContext) {
        TokenStorage::default().init(ctx);
    }

    fn issuance(ctx: &CoreContext, n: Decimal) -> Result<(), Error> {
        mint(
            &ctx.proc_context().model(),
            ctx.signer_proc_context().signer().to_string(),
            n,
        )
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
        let balance = core
            .model()
            .ledger()
            .get(core.signer().to_string())
            .unwrap_or_default();
        if balance > 0.into() {
            Self::transfer(
                &core,
                ctx.signer_proc_context().signer().to_string(),
                balance,
            )?;
        }
        Ok(())
    }

    fn mint(ctx: &ProcContext, n: Decimal) -> Result<(), Error> {
        mint(&ctx.model(), ctx.signer().to_string(), n)
    }

    fn burn(ctx: &ProcContext, n: Decimal) -> Result<(), Error> {
        Self::transfer(ctx, BURNER.to_string(), n)?;
        ctx.model().try_update_total_supply(|t| t.sub(n))?;
        Ok(())
    }

    fn transfer(ctx: &ProcContext, to: String, n: Decimal) -> Result<(), Error> {
        assert_gt_zero(n)?;
        let from = ctx.signer().to_string();
        let ledger = ctx.model().ledger();

        let from_balance = ledger.get(&from).unwrap_or_default();
        let to_balance = ledger.get(&to).unwrap_or_default();

        if from_balance < n {
            return Err(Error::Message("insufficient funds".to_string()));
        }

        ledger.set(from, from_balance.sub(n)?);
        ledger.set(to, to_balance.add(n)?);
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
                if [BURNER.to_string(), "core".to_string()].contains(&k) {
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
