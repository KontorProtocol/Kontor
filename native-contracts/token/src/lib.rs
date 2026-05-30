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
    /// Whether the public dev/test `mint` is permitted. Seeded `true` at `init`
    /// so signet/testnet/regtest funding keeps working; mainnet genesis flips it
    /// off via the core-context `set_dev_mint(false)` (the only KOR mint path on
    /// mainnet is protocol emissions via `issuance`).
    pub dev_mint_enabled: bool,
    /// Annual service-emission rate μ₀ in basis points (spec `econ.mu0` = 5%).
    pub mu0_bps: u64,
    /// Ordering-emission share χ in basis points (spec `econ.chi` = 10%); the
    /// remaining `(10000 − χ)` funds storage.
    pub chi_bps: u64,
    /// Blocks per year B — the per-block emission denominator (≈ 52,560).
    pub blocks_per_year: u64,
}

/// Basis-points denominator for fractional params.
const BPS_DENOM: u64 = 10_000;
/// Default μ₀ = 5% annual inflation. Source: `specs/params.typ` `econ.mu0`.
const DEFAULT_MU0_BPS: u64 = 500;
/// Default χ = 10% ordering share. Source: `specs/params.typ` `econ.chi`.
const DEFAULT_CHI_BPS: u64 = 1_000;
/// Default B = blocks/year (~10-minute blocks).
const DEFAULT_BLOCKS_PER_YEAR: u64 = 52_560;

fn utxo_holder(out_point: context::OutPoint) -> Holder {
    Holder::from_ref(&HolderRef::Utxo(out_point)).unwrap()
}

fn assert_gt_zero(n: Decimal) -> Result<(), Error> {
    if n <= 0u64.try_into()? {
        return Err(Error::Message("Amount must be positive".to_string()));
    }

    Ok(())
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
        let model = ctx.model();
        // Public dev mint is on by default (signet/testnet/regtest); mainnet
        // genesis disables it via `set_dev_mint(false)`.
        model.set_dev_mint_enabled(true);
        model.set_mu0_bps(DEFAULT_MU0_BPS);
        model.set_chi_bps(DEFAULT_CHI_BPS);
        model.set_blocks_per_year(DEFAULT_BLOCKS_PER_YEAR);
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

    fn mint(ctx: &ProcContext, amt: Decimal) -> Result<Mint, Error> {
        // Public mint is a dev/test affordance only — disabled on mainnet (see
        // `set_dev_mint`). Protocol emissions mint via the privileged
        // `issuance`/`issue_to` core-context path, which is uncapped and always on.
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

    /// Core-context (reactor/admin) toggle for the public dev mint. Mainnet
    /// genesis calls `set_dev_mint(false)`; signet/testnet/regtest leave it on.
    fn set_dev_mint(ctx: &CoreContext, enabled: bool) -> Result<(), Error> {
        ctx.proc_context().model().set_dev_mint_enabled(enabled);
        Ok(())
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

    /// Mint one block's gross service emission `ε = total_supply · μ₀ / B` into
    /// the protocol pool (`CORE`), and report the storage/ordering split
    /// (`ordering = ε·χ`, `storage = ε − ordering`). The reactor calls this at
    /// block-end; distribution of the pooled emission to storers/orderers is
    /// handled by the storage/ordering reward paths. Core-context only.
    fn mint_emission(ctx: &CoreContext) -> Result<EmissionResult, Error> {
        let model = ctx.proc_context().model();
        let zero: Decimal = 0u64.try_into()?;
        let denom: Decimal = BPS_DENOM.try_into()?;
        let mu0: Decimal = model.mu0_bps().try_into()?;
        let b: Decimal = model.blocks_per_year().try_into()?;

        let total = model.total_supply().mul(mu0)?.div(denom)?.div(b)?;
        if total <= zero {
            return Ok(EmissionResult {
                total: zero,
                storage: zero,
                ordering: zero,
            });
        }

        let chi: Decimal = model.chi_bps().try_into()?;
        let ordering = total.mul(chi)?.div(denom)?;
        let storage = total.sub(ordering)?;

        mint(&model, CORE(), total)?;
        Ok(EmissionResult {
            total,
            storage,
            ordering,
        })
    }

    /// Core-context (reactor/admin) setter for the emission parameters.
    fn set_emission_params(
        ctx: &CoreContext,
        mu0_bps: u64,
        chi_bps: u64,
        blocks_per_year: u64,
    ) -> Result<(), Error> {
        if chi_bps > BPS_DENOM {
            return Err(Error::Message("chi_bps must be <= 10000".to_string()));
        }
        if blocks_per_year == 0 {
            return Err(Error::Message("blocks_per_year must be > 0".to_string()));
        }
        let model = ctx.proc_context().model();
        model.set_mu0_bps(mu0_bps);
        model.set_chi_bps(chi_bps);
        model.set_blocks_per_year(blocks_per_year);
        Ok(())
    }

    fn emission_params(ctx: &ViewContext) -> EmissionParams {
        let model = ctx.model();
        EmissionParams {
            mu0_bps: model.mu0_bps(),
            chi_bps: model.chi_bps(),
            blocks_per_year: model.blocks_per_year(),
        }
    }
}
