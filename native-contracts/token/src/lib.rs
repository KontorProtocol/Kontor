#![no_std]
contract!(name = "token");

use context::{Holder, HolderRef};
use stdlib::*;

fn burner() -> Holder {
    Holder::from_ref(&HolderRef::Burner).unwrap()
}

#[derive(Clone, Default, StorageRoot)]
struct TokenStorage {
    pub ledger: Map<Holder, Decimal>,
    pub total_supply: Decimal,
}

fn make_utxo_holder(txid: String, vout: u64) -> Holder {
    Holder::from_ref(&HolderRef::Utxo(format!("{}:{}", txid, vout))).unwrap()
}

fn assert_gt_zero(n: Decimal) -> Result<(), Error> {
    if n <= 0u64.try_into().unwrap() {
        return Err(Error::Message("Amount must be positive".to_string()));
    }

    Ok(())
}

fn mint(model: &TokenStorageWriteModel, dst: Holder, amt: Decimal) -> Result<Mint, Error> {
    assert_gt_zero(amt)?;
    if amt > 1000u64.try_into().unwrap() {
        return Err(Error::Message("Amount exceeds limit".to_string()));
    }
    let ledger = model.ledger();
    let new_amt = ledger.get(&dst).unwrap_or_default().add(amt)?;
    ledger.set(dst.clone(), new_amt);
    model.try_update_total_supply(|t| t.add(amt))?;
    Ok(Mint {
        dst: dst.to_string(),
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

    ledger.set(src.clone(), src_amt.sub(amt)?);
    ledger.set(dst.clone(), dst_amt.add(amt)?);
    Ok(Transfer {
        src: src.to_string(),
        dst: dst.to_string(),
        amt,
    })
}

impl Guest for Token {
    fn init(ctx: &ProcContext) {
        TokenStorage::default().init(ctx);
    }

    fn issuance(ctx: &CoreContext, amt: Decimal) -> Result<Mint, Error> {
        let dst: Holder = (&ctx.signer_proc_context().signer()).into();
        mint(&ctx.proc_context().model(), dst, amt)
    }

    fn issue_to(ctx: &CoreContext, dst: String, amt: Decimal) -> Result<Mint, Error> {
        let dst: Holder = dst.parse().expect("invalid holder");
        mint(&ctx.proc_context().model(), dst, amt)
    }

    fn hold(ctx: &CoreContext, amt: Decimal) -> Result<Transfer, Error> {
        let core_holder: Holder = (&ctx.proc_context().signer()).into();
        transfer(
            &ctx.signer_proc_context(),
            core_holder,
            (&ctx.signer_proc_context().signer()).into(),
            amt,
        )
    }

    fn release(ctx: &CoreContext, burn_amt: Decimal) -> Result<Burn, Error> {
        let core = ctx.proc_context();
        let burn = Self::burn(&core, burn_amt)?;
        let core_holder: Holder = (&core.signer()).into();
        let amt = core.model().ledger().get(&core_holder).unwrap_or_default();
        if amt > 0u64.try_into().unwrap() {
            let signer_holder: Holder = (&ctx.signer_proc_context().signer()).into();
            transfer(&core, core_holder, signer_holder, amt)?;
        }
        Ok(Burn {
            src: ctx.signer_proc_context().signer().to_string(),
            ..burn
        })
    }

    fn mint(ctx: &ProcContext, amt: Decimal) -> Result<Mint, Error> {
        let dst: Holder = (&ctx.signer()).into();
        mint(&ctx.model(), dst, amt)
    }

    fn burn(ctx: &ProcContext, amt: Decimal) -> Result<Burn, Error> {
        let src: Holder = (&ctx.signer()).into();
        let dst = burner();
        transfer(ctx, src, dst, amt)?;
        ctx.model().try_update_total_supply(|t| t.sub(amt))?;
        Ok(Burn {
            src: ctx.signer().to_string(),
            amt,
        })
    }

    fn transfer(ctx: &ProcContext, dst: String, amt: Decimal) -> Result<Transfer, Error> {
        let src: Holder = (&ctx.signer()).into();
        let dst: Holder = dst.parse().expect("invalid holder");
        transfer(ctx, src, dst, amt)
    }

    fn attach(ctx: &ProcContext, vout: u64, amt: Decimal) -> Result<Transfer, Error> {
        let src: Holder = (&ctx.signer()).into();
        let dst = make_utxo_holder(ctx.transaction().id(), vout);
        transfer(ctx, src, dst, amt)
    }

    fn detach(ctx: &ProcContext) -> Result<Transfer, Error> {
        let out_point = ctx.transaction().out_point();
        let src = make_utxo_holder(out_point.txid, out_point.vout);
        let amt = ctx
            .model()
            .ledger()
            .get(&src)
            .ok_or(Error::Message("Source has no balance".to_string()))?;
        let dst: Holder =
            if let Some(context::OpReturnData::PubKey(dst)) = ctx.transaction().op_return_data() {
                dst.parse().expect("invalid holder")
            } else {
                (&ctx.signer()).into()
            };
        transfer(ctx, src, dst, amt)
    }

    fn balance(ctx: &ViewContext, acc: String) -> Option<Decimal> {
        ctx.model().ledger().get(acc)
    }

    fn balances(ctx: &ViewContext) -> Vec<Balance> {
        let burner_key = burner().to_string();
        ctx.model()
            .ledger()
            .keys::<String>()
            .filter_map(|acc| {
                if acc == burner_key || acc == "core" {
                    None
                } else {
                    Some(Balance {
                        amt: ctx.model().ledger().get(&acc).unwrap_or_default(),
                        acc,
                    })
                }
            })
            .collect()
    }

    fn total_supply(ctx: &ViewContext) -> Decimal {
        ctx.model().total_supply()
    }
}
