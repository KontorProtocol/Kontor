#![no_std]
contract!(name = "decimal-token");

use core::ops::Bound;
use stdlib::*;

const MAX_BALANCES_LIMIT: u64 = 100;

#[derive(Clone, Default, StorageRoot)]
struct TokenStorage {
    pub ledger: Map<Holder, Decimal>,
    pub total_supply: Decimal,
}

fn utxo_holder(out_point: context::OutPoint) -> Holder {
    Holder::from_ref(&HolderRef::Utxo(out_point)).unwrap()
}

fn assert_gt_zero(n: Decimal) -> Result<(), Error> {
    if n <= 0u64.try_into()? {
        return Err(Error::Message("Amount must be positive".to_string()));
    }
    Ok(())
}

fn mint(
    model: &TokenStorageWriteModel<context::ProcStorage>,
    dst: Holder,
    amt: Decimal,
) -> Result<Mint, Error> {
    assert_gt_zero(amt)?;
    let ledger = model.ledger();
    let new_amt = ledger.get(&dst).unwrap_or_default().add(amt)?;
    ledger.set(&dst, new_amt);
    model.try_update_total_supply(|t| t.add(amt))?;
    Ok(Mint {
        dst: dst.into(),
        amt: new_amt,
    })
}

fn transfer(ctx: &ProcContext, src: Holder, dst: Holder, amt: Decimal) -> Result<Transfer, Error> {
    assert_gt_zero(amt)?;
    let ledger = ctx.model().ledger();

    let src_amt = ledger.get(&src).unwrap_or_default();
    let dst_amt = ledger.get(&dst).unwrap_or_default();

    if src_amt < amt {
        return Err(Error::Message("insufficient funds".to_string()));
    }

    // No storage-deposit floor check: that is the native token's privilege (the
    // `deposit` host fn is native-only). A user token bounds nothing here.
    ledger.set(&src, src_amt.sub(amt)?);
    ledger.set(&dst, dst_amt.add(amt)?);
    Ok(Transfer {
        src: src.into(),
        dst: dst.into(),
        amt,
    })
}

impl Guest for DecimalToken {
    fn init(ctx: &ProcContext) -> Contract {
        TokenStorage::default().init(ctx);
        ctx.contract()
    }

    fn mint(ctx: &ProcContext, amt: Decimal) -> Result<Mint, Error> {
        // Uncapped — decimal-token is a test fixture; tests mint large amounts and rely on
        // the total-supply add to surface overflow.
        mint(&ctx.model(), ctx.signer().into(), amt)
    }

    fn burn(ctx: &ProcContext, amt: Decimal) -> Result<Burn, Error> {
        transfer(ctx, ctx.signer().into(), BURNER(), amt)?;
        ctx.model().try_update_total_supply(|t| t.sub(amt))?;
        Ok(Burn {
            src: ctx.signer().into(),
            amt,
        })
    }

    fn transfer(ctx: &ProcContext, dst: HolderRef, amt: Decimal) -> Result<Transfer, Error> {
        transfer(ctx, ctx.signer().into(), dst.try_into()?, amt)
    }

    fn attach(ctx: &ProcContext, vout: u32, amt: Decimal) -> Result<Transfer, Error> {
        let out_point = context::OutPoint {
            txid: ctx.transaction().id(),
            vout,
        };
        transfer(ctx, ctx.signer().into(), utxo_holder(out_point), amt)
    }

    fn detach(ctx: &ProcContext) -> Result<Transfer, Error> {
        let src = utxo_holder(ctx.transaction().out_point());
        let amt = ctx
            .model()
            .ledger()
            .get(&src)
            .ok_or(Error::Message("Source has no balance".to_string()))?;
        transfer(ctx, src, ctx.payer(), amt)
    }

    fn balance(ctx: &ViewContext, acc: HolderRef) -> Option<Decimal> {
        let holder: Holder = acc.try_into().ok()?;
        ctx.model().ledger().get(&holder)
    }

    fn balances(
        ctx: &ViewContext,
        after: Option<String>,
        limit: u64,
    ) -> Result<BalancePage, Error> {
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
            .filter(|(acc, _)| !matches!(acc.as_ref(), HolderRef::Burner | HolderRef::Core))
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
                acc: acc.as_ref(),
                amt,
            })
            .collect();
        Ok(BalancePage { items, next })
    }

    fn total_supply(ctx: &ViewContext) -> Decimal {
        ctx.model().total_supply()
    }
}
