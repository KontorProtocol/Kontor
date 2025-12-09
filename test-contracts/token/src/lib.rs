#![no_std]
contract!(name = "token");

use stdlib::*;

const BURNER: &str = "burn";

#[derive(Clone, Default, StorageRoot)]
struct TokenStorage {
    pub ledger: Map<String, Integer>,
    pub total_supply: Integer,
}

fn assert_gt_zero(n: Integer) -> Result<(), Error> {
    if n <= 0.into() {
        return Err(Error::Message("Amount must be positive".to_string()));
    }

    Ok(())
}

fn mint(model: &TokenStorageWriteModel, to: String, n: Integer) -> Result<(), Error> {
    assert_gt_zero(n)?;
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

    fn mint(ctx: &ProcContext, n: Integer) -> Result<(), Error> {
        mint(&ctx.model(), ctx.signer().to_string(), n)
    }

    fn burn(ctx: &ProcContext, n: Integer) -> Result<(), Error> {
        Self::transfer(ctx, BURNER.to_string(), n)?;
        ctx.model().try_update_total_supply(|t| t.sub(n))?;
        Ok(())
    }

    fn transfer(ctx: &ProcContext, to: String, n: Integer) -> Result<(), Error> {
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

    fn balance(ctx: &ViewContext, acc: String) -> Option<Integer> {
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

    fn total_supply(ctx: &ViewContext) -> Integer {
        ctx.model().total_supply()
    }
}
