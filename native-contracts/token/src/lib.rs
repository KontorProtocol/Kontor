#![no_std]
contract!(name = "token");

use stdlib::*;

/// Per-call cap on the *public, unprivileged* `mint` — a dev/test affordance
/// (signet/testnet/regtest funding). It does NOT apply to the privileged
/// core-context `issuance`/`issue_to` path that protocol emissions (and genesis
/// stake issuance) use.
const DEV_MINT_CAP: u64 = 1000;

#[derive(Clone, Default, StorageRoot)]
struct TokenStorage {
    pub ledger: Map<Holder, Decimal>,
    pub total_supply: Decimal,
    /// Whether the public dev/test `mint` is permitted. Set once at `init` from
    /// the chain `network()` — on for signet/testnet/regtest (faucet), off on
    /// mainnet (the only KOR mint path there is protocol emissions via
    /// `issuance`).
    pub dev_mint_enabled: bool,
    /// Storage-deposit footprint: total live bytes each holder occupies across
    /// all contracts (the host reports the per-op net delta via `settle`). Backs
    /// the floor `balance >= footprint * D`. A whole byte count, held as `Decimal`
    /// so the floor compares in the ledger's numeric domain without conversion.
    /// Appended LAST so the interned field ids of the existing fields stay fixed
    /// (positional dict-refs — see `golden_field_names_are_interned_in_contract_state`).
    pub footprint: Map<Holder, Decimal>,
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

/// The storage-deposit rate `D` — token per live byte. Fixed at 1 for now; the
/// economics layer will most likely make this dynamic (a function of total
/// state). Kept as a multiplier so the floor structure (`footprint * D`) is
/// already in place when `D` changes.
fn storage_deposit_rate() -> Result<Decimal, Error> {
    1u64.try_into()
}

/// Apply a signed byte delta to a holder's footprint, clamping at zero. A correct
/// net never frees more than exists, but the `delete_matching_paths` gap (see the
/// host `FootprintGauge`) can transiently over-subtract — never let footprint go
/// negative.
fn apply_footprint_delta(current: Decimal, delta: i64) -> Result<Decimal, Error> {
    if delta >= 0 {
        current.add((delta as u64).try_into()?)
    } else {
        let magnitude: Decimal = delta.unsigned_abs().try_into()?;
        if current <= magnitude {
            Ok(0u64.try_into()?)
        } else {
            current.sub(magnitude)
        }
    }
}

fn mint(model: &TokenStorageWriteModel, dst: Holder, amt: Decimal) -> Result<Mint, Error> {
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

    ledger.set(&src, src_amt.sub(amt)?);
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
        // except mainnet, where the only KOR mint path is protocol emissions.
        // Self-conditioning via the `network()` built-in; no genesis wiring.
        ctx.model()
            .set_dev_mint_enabled(!ctx.network().is_mainnet());
        ctx.contract()
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

    fn release(ctx: &CoreContext, burn_amt: Decimal) -> Result<Burn, Error> {
        let proc_context = ctx.proc_context();
        let burn = Self::burn(&proc_context, burn_amt)?;
        let amt = proc_context
            .model()
            .ledger()
            .get(&CORE())
            .unwrap_or_default();
        if amt > 0u64.try_into()? {
            transfer(
                &proc_context,
                CORE(),
                ctx.signer_proc_context().signer().into(),
                amt,
            )?;
        }
        Ok(Burn {
            src: ctx.signer_proc_context().signer().into(),
            ..burn
        })
    }

    fn settle(ctx: &CoreContext, footprint_delta: i64, pending_credit: Decimal) -> Result<(), Error> {
        let proc_context = ctx.proc_context();
        let model = proc_context.model();
        // Payer = the op's payer (the host wraps it as the core signer), same as
        // hold/release. Footprint, gas, and the floor all land on this one holder.
        let payer: Holder = ctx.signer_proc_context().signer().into();

        let footprint = model.footprint();
        let new_footprint = apply_footprint_delta(footprint.get(&payer).unwrap_or_default(), footprint_delta)?;
        footprint.set(&payer, new_footprint);

        // Floor: the payer's balance — plus the gas refund they're about to
        // receive (`pending_credit`), since this runs before `release` — must
        // cover the deposit on every live byte they now occupy. On violation the
        // caller reverts the op (rolling back this footprint write with it).
        let balance = model.ledger().get(&payer).unwrap_or_default();
        let floor = new_footprint.mul(storage_deposit_rate()?)?;
        if balance.add(pending_credit)? < floor {
            return Err(Error::Message(
                "storage deposit floor exceeded".to_string(),
            ));
        }
        Ok(())
    }

    fn mint(ctx: &ProcContext, amt: Decimal) -> Result<Mint, Error> {
        // Public mint is a dev/test affordance only — off on mainnet (the flag is
        // set from `network()` at `init`). Protocol emissions mint via the
        // privileged `issuance`/`issue_to` core path, uncapped and always on.
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
