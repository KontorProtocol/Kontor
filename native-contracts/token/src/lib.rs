#![no_std]
contract!(name = "token");

use stdlib::*;

const BURNER: &str = "burn";

#[derive(Clone, Default, StorageRoot)]
struct TokenStorage {
    pub ledger: Map<String, Decimal>,
    pub total_supply: Decimal,
}

fn make_utxo_id(txid: String, vout: u64) -> String {
    format!("{}:{}", txid, vout)
}

fn assert_gt_zero(n: Decimal) -> Result<(), Error> {
    if n <= 0.into() {
        return Err(Error::Message("Amount must be positive".to_string()));
    }

    Ok(())
}

fn mint(model: &TokenStorageWriteModel, dst: String, amt: Decimal) -> Result<Mint, Error> {
    assert_gt_zero(amt)?;
    if amt > 1000.into() {
        return Err(Error::Message("Amount exceeds limit".to_string()));
    }
    let ledger = model.ledger();
    let new_amt = ledger.get(&dst).unwrap_or_default().add(amt)?;
    ledger.set(dst.clone(), new_amt);
    model.try_update_total_supply(|t| t.add(amt))?;
    Ok(Mint { dst, amt: new_amt })
}

fn transfer(ctx: &ProcContext, src: String, dst: String, amt: Decimal) -> Result<Transfer, Error> {
    assert_gt_zero(amt)?;
    let ledger = ctx.model().ledger();

    let src_amt = ledger.get(&src).unwrap_or_default();
    let dst_amt = ledger.get(&dst).unwrap_or_default();

    if src_amt < amt {
        return Err(Error::Message("insufficient funds".to_string()));
    }

    ledger.set(src.clone(), src_amt.sub(amt)?);
    ledger.set(dst.clone(), dst_amt.add(amt)?);
    Ok(Transfer { src, dst, amt })
}

fn signer_account(signer: &context::Signer) -> String {
    signer
        .signer_id()
        .map(|id| id.to_string())
        .unwrap_or_else(|| signer.to_string())
}

impl Guest for Token {
    fn init(ctx: &ProcContext) {
        TokenStorage::default().init(ctx);
    }

    fn issuance(ctx: &CoreContext, amt: Decimal) -> Result<Mint, Error> {
        let signer = ctx.signer_proc_context().signer();
        mint(
            &ctx.proc_context().model(),
            signer_account(&signer),
            amt,
        )
    }

    fn hold(ctx: &CoreContext, amt: Decimal) -> Result<Transfer, Error> {
        let signer = ctx.proc_context().signer();
        Self::transfer(
            &ctx.signer_proc_context(),
            signer_account(&signer),
            amt,
        )
    }

    fn release(ctx: &CoreContext, burn_amt: Decimal) -> Result<Burn, Error> {
        let core = ctx.proc_context();
        let burn = Self::burn(&core, burn_amt)?;
        let core_signer = core.signer();
        let amt = core
            .model()
            .ledger()
            .get(signer_account(&core_signer))
            .unwrap_or_default();
        if amt > 0.into() {
            let signer = ctx.signer_proc_context().signer();
            Self::transfer(&core, signer_account(&signer), amt)?;
        }
        let signer = ctx.signer_proc_context().signer();
        Ok(Burn {
            src: signer_account(&signer),
            ..burn
        })
    }

    fn mint(ctx: &ProcContext, amt: Decimal) -> Result<Mint, Error> {
        let signer = ctx.signer();
        mint(&ctx.model(), signer_account(&signer), amt)
    }

    fn burn(ctx: &ProcContext, amt: Decimal) -> Result<Burn, Error> {
        let transfer = Self::transfer(ctx, BURNER.to_string(), amt)?;
        ctx.model().try_update_total_supply(|t| t.sub(amt))?;
        Ok(Burn {
            src: transfer.src,
            amt: transfer.amt,
        })
    }

    fn transfer(ctx: &ProcContext, dst: String, amt: Decimal) -> Result<Transfer, Error> {
        let signer = ctx.signer();
        let src = signer_account(&signer);
        transfer(ctx, src, dst, amt)
    }

    fn attach(ctx: &ProcContext, vout: u64, amt: Decimal) -> Result<Transfer, Error> {
        let dst = make_utxo_id(ctx.transaction().id(), vout);
        Self::transfer(ctx, dst, amt)
    }

    fn detach(ctx: &ProcContext) -> Result<Transfer, Error> {
        let out_point = ctx.transaction().out_point();
        let src = make_utxo_id(out_point.txid, out_point.vout);
        let amt = ctx
            .model()
            .ledger()
            .get(&src)
            .ok_or(Error::Message("Source has no balance".to_string()))?;
        let dst =
            if let Some(context::OpReturnData::PubKey(dst)) = ctx.transaction().op_return_data() {
                dst
            } else {
                let signer = ctx.signer();
                signer_account(&signer)
            };
        transfer(ctx, src, dst, amt)
    }

    fn balance(ctx: &ViewContext, acc: String) -> Option<Decimal> {
        ctx.model().ledger().get(acc)
    }

    fn balances(ctx: &ViewContext) -> Vec<Balance> {
        ctx.model()
            .ledger()
            .keys()
            .filter_map(|acc| {
                if [BURNER.to_string(), "core".to_string()].contains(&acc) {
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
