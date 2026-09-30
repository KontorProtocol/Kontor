#![no_std]
contract!(name = "test-token");

use context::HolderRef;
use core::ops::Bound;
use stdlib::*;

const MAX_BALANCES_LIMIT: u64 = 100;

import!(
    name = "token",
    mod_name = "native_token",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/token/wit",
);

#[derive(Clone, Default, StorageRoot)]
struct TokenStorage {
    pub ledger: Map<Holder, Integer>,
    pub total_supply: Integer,
}

fn assert_gt_zero(n: Integer) -> Result<(), Error> {
    if n <= 0.into() {
        return Err(Error::Message("Amount must be positive".to_string()));
    }

    Ok(())
}

fn mint(
    model: &TokenStorageWriteModel<context::ProcStorage>,
    to: Holder,
    n: Integer,
) -> Result<(), Error> {
    assert_gt_zero(n)?;
    let ledger = model.ledger();
    let balance = ledger.get(&to).unwrap_or_default();
    ledger.set(&to, balance.add(n)?);
    model.try_update_total_supply(|t| t.add(n))?;
    Ok(())
}

impl Guest for TestToken {
    fn init(ctx: &ProcContext) -> Contract {
        TokenStorage::default().init(ctx);
        ctx.contract()
    }

    fn mint(ctx: &ProcContext, n: Integer) -> Result<(), Error> {
        let to: Holder = (&ctx.signer()).into();
        mint(&ctx.model(), to, n)
    }

    fn burn(ctx: &ProcContext, n: Integer) -> Result<(), Error> {
        Self::transfer(ctx, BURNER().to_string(), n)?;
        ctx.model().try_update_total_supply(|t| t.sub(n))?;
        Ok(())
    }

    fn transfer(ctx: &ProcContext, to: String, n: Integer) -> Result<(), Error> {
        assert_gt_zero(n)?;
        let from: Holder = (&ctx.signer()).into();
        let to: Holder = to.parse().expect("invalid holder");
        let ledger = ctx.model().ledger();

        let from_balance = ledger.get(&from).unwrap_or_default();
        let to_balance = ledger.get(&to).unwrap_or_default();

        if from_balance < n {
            return Err(Error::Message("insufficient funds".to_string()));
        }

        ledger.set(&from, from_balance.sub(n)?);
        ledger.set(&to, to_balance.add(n)?);
        Ok(())
    }

    fn balance(ctx: &ViewContext, acc: String) -> Option<Integer> {
        let holder: Holder = acc.parse().ok()?;
        ctx.model().ledger().get(&holder)
    }

    fn count_balances(ctx: &ViewContext, max: u32) -> Result<u64, Error> {
        Self::balances(ctx)
            .iter()
            .take(max as usize)
            .try_fold(0, |count, balance| {
                balance?;
                Ok(count + 1)
            })
    }

    fn count_native_balances(_ctx: &ViewContext, max: u32) -> Result<u64, Error> {
        native_token::balances()
            .iter()
            .take(max as usize)
            .try_fold(0, |count, balance| {
                balance?;
                Ok(count + 1)
            })
    }

    fn balances(ctx: &ViewContext, pagination: CursorRequest) -> Result<BalancePage, Error> {
        let CursorRequest { after, limit } = pagination;
        let limit = limit.unwrap_or(MAX_BALANCES_LIMIT);
        let after = after
            .map(|cursor| cursor.parse::<Holder>())
            .transpose()
            .map_err(Error::Message)?;
        let limit = limit.min(MAX_BALANCES_LIMIT) as usize;
        if limit == 0 {
            return Ok(BalancePage {
                items: Vec::new(),
                next: None,
            });
        }
        let bounds = (
            after.map(Bound::Excluded).unwrap_or(Bound::Unbounded),
            Bound::Unbounded,
        );
        // Only fixed system accounts are filtered, so the lookahead remains bounded.
        let mut rows: Vec<_> = ctx
            .model()
            .ledger()
            .range(bounds)
            .entries()
            .filter(|(acc, _)| acc.as_ref() != HolderRef::Burner)
            .take(limit + 1)
            .collect();
        let next = if rows.len() > limit {
            rows.pop();
            rows.last().map(|(acc, _)| acc.to_string())
        } else {
            None
        };
        let items = rows
            .into_iter()
            .map(|(acc, amt)| Balance {
                key: acc.to_string(),
                value: amt,
            })
            .collect();
        Ok(BalancePage { items, next })
    }

    fn total_supply(ctx: &ViewContext) -> Integer {
        ctx.model().total_supply()
    }
}
