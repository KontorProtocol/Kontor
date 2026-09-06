#![no_std]
contract!(name = "token");

use stdlib::*;

// The dev faucet cap does not apply to genesis issuance or scheduled emissions.
const DEV_MINT_CAP: u64 = 1000;

#[derive(Clone, Default, StorageRoot)]
struct TokenStorage {
    pub ledger: Map<Holder, Decimal>,
    pub total_supply: Decimal,
    /// Whether the public dev/test `mint` is permitted. Set once at `init` from
    /// the chain `network()` — on for signet/testnet/regtest (faucet), off on
    /// mainnet (issuance there is restricted to privileged protocol paths).
    pub dev_mint_enabled: bool,
    pub last_emission_height: Option<u64>,
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

    // Storage-deposit FLOOR: a holder's storage deposit (footprint × D) is a LOCKED
    // reserve — every debit must leave the balance at or above it. The gas hold is a
    // debit too, so this also up-front-authorizes an op's storage growth. The host
    // returns 0 for non-signer/system holders (core/burner/utxo).
    let remaining = src_amt.sub(amt)?;
    if remaining < deposit::storage_floor(&src) {
        return Err(Error::Message("storage deposit floor exceeded".to_string()));
    }

    ledger.set(&src, remaining);
    ledger.set(&dst, dst_amt.add(amt)?);
    Ok(Transfer {
        src: src.into(),
        dst: dst.into(),
        amt,
    })
}

impl Guest for Token {
    fn init(ctx: &ProcContext) -> Contract {
        TokenStorage::default().init(ctx);
        // Public dev mint is a dev/test affordance — enabled on every network
        // except mainnet, where minting requires a privileged protocol path.
        // Self-conditioning via the `network()` built-in; no genesis wiring.
        ctx.model()
            .set_dev_mint_enabled(!ctx.network().is_mainnet());
        ctx.contract()
    }

    fn mint_emission(ctx: &CoreContext, eligible: bool) -> Result<Emission, Error> {
        let proc = ctx.proc_context();
        let model = proc.model();
        let height = proc.block_height();
        if model
            .last_emission_height()
            .is_some_and(|last| height <= last)
        {
            return Err(Error::Message(
                "emission height already processed".to_string(),
            ));
        }
        let zero: Decimal = 0u64.try_into()?;
        // Operation order is consensus-visible: supply * 5% / 52,560, then * 10%.
        let scheduled_total = model
            .total_supply()
            .mul(5u64.try_into()?)?
            .div(100u64.try_into()?)?
            .div(52_560u64.try_into()?)?;
        let ordering = scheduled_total.div(10u64.try_into()?)?;
        let ordering_minted = if eligible { ordering } else { zero };
        if ordering_minted > zero {
            mint(&model, HolderRef::OrderingPool.try_into()?, ordering_minted)?;
        }
        model.set_last_emission_height(Some(height));
        Ok(Emission {
            scheduled_total,
            ordering_minted,
            storage_unminted: scheduled_total.sub(ordering)?,
        })
    }

    fn transfer_ordering_reward(
        ctx: &CoreContext,
        dst: HolderRef,
        amt: Decimal,
    ) -> Result<Transfer, Error> {
        let dst: Holder = dst.try_into()?;
        if dst.as_ref() == HolderRef::OrderingPool {
            return Err(Error::Message(
                "reward destination is the ordering pool".to_string(),
            ));
        }
        transfer(
            &ctx.proc_context(),
            HolderRef::OrderingPool.try_into()?,
            dst,
            amt,
        )
    }

    fn last_emission_height(ctx: &ViewContext) -> Option<u64> {
        ctx.model().last_emission_height()
    }

    fn issuance(ctx: &CoreContext, amt: Decimal) -> Result<Mint, Error> {
        mint(
            &ctx.proc_context().model(),
            ctx.signer_proc_context().signer().into(),
            amt,
        )
    }

    fn issue_to(ctx: &CoreContext, dst: HolderRef, amt: Decimal) -> Result<Mint, Error> {
        mint(&ctx.proc_context().model(), dst.try_into()?, amt)
    }

    fn hold(ctx: &CoreContext, amt: Decimal) -> Result<Transfer, Error> {
        transfer(
            &ctx.signer_proc_context(),
            ctx.signer_proc_context().signer().into(),
            CORE(),
            amt,
        )
    }

    /// Release the gas escrow: burn the execution slice (CORE → BURNER) and refund
    /// the rest (CORE → payer). The storage-deposit RESERVATION is part of "the
    /// rest" — only execution burns — so it rides this refund. Runs OUTSIDE the op
    /// savepoint (always, even on a reverted op: gas is paid for the attempt).
    fn release(ctx: &CoreContext, burn_amt: Decimal) -> Result<Burn, Error> {
        let proc = ctx.proc_context();
        let burn = Self::burn(&proc, burn_amt)?;
        let remaining = proc.model().ledger().get(&CORE()).unwrap_or_default();
        if remaining > 0u64.try_into()? {
            transfer(
                &proc,
                CORE(),
                ctx.signer_proc_context().signer().into(),
                remaining,
            )?;
        }
        Ok(Burn {
            src: ctx.signer_proc_context().signer().into(),
            ..burn
        })
    }

    fn mint(ctx: &ProcContext, amt: Decimal) -> Result<Mint, Error> {
        // Public mint is a dev/test affordance only — off on mainnet (the flag is
        // set from `network()` at `init`). Scheduled emissions have a separate
        // core-only entry point.
        if !ctx.model().dev_mint_enabled() {
            return Err(Error::Message(
                "public mint is disabled on this network".to_string(),
            ));
        }
        if amt > DEV_MINT_CAP.try_into()? {
            return Err(Error::Message("Amount exceeds dev mint limit".to_string()));
        }
        mint(&ctx.model(), ctx.signer().into(), amt)
    }

    fn dev_mint_enabled(ctx: &ViewContext) -> bool {
        ctx.model().dev_mint_enabled()
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
        // Recipient = `ctx.payer()`. The reactor's Sponsor mechanism
        // determines the payer per the override rules:
        //   - Direct + cross-input Sponsor (swap path): payer = sponsor's
        //     signer (the buyer) → asset detaches to the buyer.
        //   - Direct + no Sponsor (revoke path): payer = signer of this
        //     input (the seller, who pre-signed the escrow leaf) → asset
        //     returns to the seller.
        // `ctx.payer()` is a Holder (not a Signer) by design — we can
        // credit it but not spend on its behalf.
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

    /// A holder's storage-deposit floor (footprint × D), token-denominated. Public,
    /// cross-contract-callable surface over the native-only `deposit.storage-floor`
    /// host fn — the same value the debit check enforces. 0 for holders with no
    /// deposited rows. `ctx` is unused (the floor is host-global, not contract state).
    /// Resolve the holder-ref to a `Holder` (the one canonical signer-id resolution,
    /// same path as `balance`) before reading — `storage_floor` takes a resolved holder.
    fn floor(_ctx: &ViewContext, acc: HolderRef) -> Decimal {
        match Holder::try_from(acc) {
            Ok(holder) => deposit::storage_floor(&holder),
            Err(_) => Decimal::default(),
        }
    }

    fn balances(ctx: &ViewContext) -> Vec<Balance> {
        ctx.model()
            .ledger()
            .keys()
            .filter_map(|acc| {
                let acc_ref = acc.as_ref();
                if acc_ref == HolderRef::Burner || acc_ref == HolderRef::Core {
                    None
                } else {
                    Some(Balance {
                        amt: ctx.model().ledger().get(&acc).unwrap_or_default(),
                        acc: acc_ref,
                    })
                }
            })
            .collect()
    }

    fn total_supply(ctx: &ViewContext) -> Decimal {
        ctx.model().total_supply()
    }
}
