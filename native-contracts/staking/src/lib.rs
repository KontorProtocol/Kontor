#![no_std]
contract!(name = "staking");

use stdlib::*;

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../token/wit"
);

const ACTIVATION_DELAY: u64 = 12; // 2 * FINALITY_WINDOW (6)
const MAX_STAKE: u64 = 1_000_000_000; // Cap to fit in u64 voting power

#[derive(Clone, Default, Storage)]
struct ValidatorEntry {
    pub stake: Decimal,
    pub status: u64, // 0=inactive, 1=active, 2=pending_join, 3=pending_exit
    pub activation_height: u64,
    pub deactivation_height: u64,
    pub ed25519_pubkey: Vec<u8>,
}

#[derive(Clone, Default, StorageRoot)]
struct StakingStorage {
    pub min_stake: Decimal,
    pub validators: Map<Holder, ValidatorEntry>,
    pub active_count: u64,
    pub total_active_stake: Decimal,
    /// Storage-slash multiplier (spec `λ_slash`). A failed storage challenge
    /// slashes `λ_slash · k_f` of the node's pooled stake.
    pub lambda_slash: u64,
    /// Burn share of a slash, in basis points (spec `τ_slash`, 0–10000). The
    /// remaining `(10000 − τ_slash_bps)` is returned to the caller to
    /// redistribute to the file's other nodes.
    pub tau_slash_bps: u64,
}

/// Basis-points denominator for fractional params (e.g. `τ_slash`).
const BPS_DENOM: u64 = 10_000;

/// Default `λ_slash` (storage-slash multiplier). Source: `specs/v1-parameters`.
const DEFAULT_LAMBDA_SLASH: u64 = 30;
/// Default `τ_slash` = 50% burn share. Source: `specs/params.typ` `econ.tauSlash`.
const DEFAULT_TAU_SLASH_BPS: u64 = 5_000;

#[allow(dead_code)]
const STATUS_INACTIVE: u64 = 0;
const STATUS_ACTIVE: u64 = 1;
const STATUS_PENDING_JOIN: u64 = 2;
const STATUS_PENDING_EXIT: u64 = 3;

fn status_to_enum(status: u64) -> ValidatorStatus {
    match status {
        STATUS_ACTIVE => ValidatorStatus::Active,
        STATUS_PENDING_JOIN => ValidatorStatus::PendingJoin,
        STATUS_PENDING_EXIT => ValidatorStatus::PendingExit,
        _ => ValidatorStatus::Inactive,
    }
}

fn make_validator_info(x_only_pubkey: &Holder, entry: &ValidatorEntryModel) -> ValidatorInfo {
    ValidatorInfo {
        x_only_pubkey: x_only_pubkey.to_string(),
        stake: entry.stake(),
        status: status_to_enum(entry.status()),
        activation_height: entry.activation_height(),
        deactivation_height: entry.deactivation_height(),
        ed25519_pubkey: entry.ed25519_pubkey(),
    }
}

impl Guest for Staking {
    fn init(ctx: &ProcContext) -> Contract {
        let storage = StakingStorage::default();
        storage.init(ctx);
        let model = ctx.model();
        model.set_min_stake(1u64.try_into().unwrap());
        model.set_lambda_slash(DEFAULT_LAMBDA_SLASH);
        model.set_tau_slash_bps(DEFAULT_TAU_SLASH_BPS);
        ctx.contract()
    }

    fn register_validator(
        ctx: &ProcContext,
        ed25519_pubkey: Vec<u8>,
        stake_amount: Decimal,
    ) -> Result<ValidatorInfo, Error> {
        if ed25519_pubkey.len() != 32 {
            return Err(Error::Message(
                "expected 32-byte ed25519 pubkey".to_string(),
            ));
        }

        let model = ctx.model();
        let holder: Holder = (&ctx.signer()).into();

        if let Some(existing) = model.validators().get(&holder)
            && existing.status() != STATUS_INACTIVE
        {
            return Err(Error::Message("already registered".to_string()));
        }

        if stake_amount < model.min_stake() {
            return Err(Error::Message("stake below minimum".to_string()));
        }
        if stake_amount > MAX_STAKE.try_into().unwrap() {
            return Err(Error::Message("stake exceeds maximum".to_string()));
        }

        // Reject duplicate ed25519 keys — two validators with the same
        // consensus key would cause conflicts in Malachite.
        let keys: Vec<Holder> = model.validators().keys().collect();
        for key in keys {
            if let Some(entry) = model.validators().get(&key)
                && key != holder
                && entry.ed25519_pubkey() == ed25519_pubkey
                && entry.status() != STATUS_INACTIVE
            {
                return Err(Error::Message(
                    "ed25519 pubkey already registered by another validator".to_string(),
                ));
            }
        }

        // Effects before interactions (CEI pattern)
        let activation_height = ctx.block_height() + ACTIVATION_DELAY;
        model.validators().set(
            &holder,
            ValidatorEntry {
                stake: stake_amount,
                status: STATUS_PENDING_JOIN,
                activation_height,
                deactivation_height: 0,
                ed25519_pubkey: ed25519_pubkey.clone(),
            },
        );

        token::transfer(
            ctx.signer(),
            ctx.contract_signer().as_holder().as_ref(),
            stake_amount,
        )?;

        Ok(ValidatorInfo {
            x_only_pubkey: holder.to_string(),
            stake: stake_amount,
            status: ValidatorStatus::PendingJoin,
            activation_height,
            deactivation_height: 0,
            ed25519_pubkey,
        })
    }

    fn add_stake(ctx: &ProcContext, amount: Decimal) -> Result<ValidatorInfo, Error> {
        let model = ctx.model();
        let holder: Holder = (&ctx.signer()).into();

        let entry = model
            .validators()
            .get(&holder)
            .ok_or(Error::Message("not registered".to_string()))?;

        if amount <= 0u64.try_into().unwrap() {
            return Err(Error::Message("amount must be positive".to_string()));
        }

        let status = entry.status();
        if status == STATUS_INACTIVE || status == STATUS_PENDING_EXIT {
            return Err(Error::Message(
                "cannot add stake while inactive or pending exit".to_string(),
            ));
        }

        let new_stake = entry.stake().add(amount)?;
        if new_stake > MAX_STAKE.try_into().unwrap() {
            return Err(Error::Message(
                "total stake would exceed maximum".to_string(),
            ));
        }

        // Effects before interactions (CEI pattern)
        entry.set_stake(new_stake);
        if status == STATUS_ACTIVE {
            model.try_update_total_active_stake(|s| s.add(amount))?;
        }

        token::transfer(
            ctx.signer(),
            ctx.contract_signer().as_holder().as_ref(),
            amount,
        )?;

        Ok(make_validator_info(&holder, &entry))
    }

    fn begin_unstake(ctx: &ProcContext) -> Result<ValidatorInfo, Error> {
        let model = ctx.model();
        let holder: Holder = (&ctx.signer()).into();

        let entry = model
            .validators()
            .get(&holder)
            .ok_or(Error::Message("not registered".to_string()))?;

        match entry.status() {
            STATUS_ACTIVE => {
                entry.set_status(STATUS_PENDING_EXIT);
                let deactivation_height = ctx.block_height() + ACTIVATION_DELAY;
                entry.set_deactivation_height(deactivation_height);
            }
            // Not yet activated — go straight to inactive and return tokens
            STATUS_PENDING_JOIN => {
                let stake = entry.stake();
                entry.set_stake(0u64.try_into().unwrap());
                entry.set_status(STATUS_INACTIVE);
                token::transfer(ctx.contract_signer(), holder.as_ref(), stake)?;
            }
            _ => return Err(Error::Message("invalid status for unstaking".to_string())),
        }

        Ok(make_validator_info(&holder, &entry))
    }

    fn set_genesis_set(ctx: &CoreContext, validators: Vec<ActiveValidatorInfo>) {
        let model = ctx.proc_context().model();
        if model.active_count() > 0 {
            return;
        }
        for v in &validators {
            assert!(
                v.ed25519_pubkey.len() == 32,
                "expected 32-byte ed25519 pubkey in genesis set"
            );
        }
        // Reject duplicate ed25519 keys in genesis set
        assert!(
            validators
                .iter()
                .map(|v| &v.ed25519_pubkey)
                .collect::<alloc::collections::BTreeSet<_>>()
                .len()
                == validators.len(),
            "duplicate ed25519 pubkey in genesis set"
        );
        let staking_ref = ctx.proc_context().contract_signer().as_holder().as_ref();
        for v in &validators {
            token::issue_to(ctx.core_signer(), staking_ref.clone(), v.stake)
                .expect("Failed to mint genesis stake");
            let holder: Holder = v
                .x_only_pubkey
                .parse()
                .expect("invalid holder in genesis set");
            model.validators().set(
                &holder,
                ValidatorEntry {
                    stake: v.stake,
                    status: STATUS_ACTIVE,
                    activation_height: 0,
                    deactivation_height: 0,
                    ed25519_pubkey: v.ed25519_pubkey.clone(),
                },
            );
            model
                .try_update_total_active_stake(|s| s.add(v.stake))
                .expect("Failed to update total active stake");
        }
        model.set_active_count(validators.len() as u64);
    }

    fn process_pending_validators(
        ctx: &CoreContext,
        block_height: u64,
    ) -> Result<ValidatorSetChange, Error> {
        let model = ctx.proc_context().model();

        let mut activated = 0u64;
        let mut deactivated = 0u64;

        let keys: Vec<Holder> = model.validators().keys().collect();
        for key in keys {
            if let Some(entry) = model.validators().get(&key) {
                match entry.status() {
                    STATUS_PENDING_JOIN if block_height >= entry.activation_height() => {
                        entry.set_status(STATUS_ACTIVE);
                        model.try_update_total_active_stake(|s| s.add(entry.stake()))?;
                        model.update_active_count(|c| c + 1);
                        activated += 1;
                    }
                    STATUS_PENDING_EXIT if block_height >= entry.deactivation_height() => {
                        let stake = entry.stake();
                        entry.set_stake(0u64.try_into().unwrap());
                        entry.set_status(STATUS_INACTIVE);
                        model.try_update_total_active_stake(|s| s.sub(stake))?;
                        model.update_active_count(|c| c - 1);
                        token::transfer(ctx.proc_context().contract_signer(), key, stake)?;
                        deactivated += 1;
                    }
                    _ => {}
                }
            }
        }

        Ok(ValidatorSetChange {
            activated,
            deactivated,
        })
    }

    fn get_active_set(ctx: &ViewContext) -> Vec<ActiveValidatorInfo> {
        ctx.model()
            .validators()
            .keys()
            .filter_map(|key| {
                let entry = ctx.model().validators().get(&key)?;
                if entry.status() == STATUS_ACTIVE || entry.status() == STATUS_PENDING_EXIT {
                    Some(ActiveValidatorInfo {
                        x_only_pubkey: key.to_string(),
                        stake: entry.stake(),
                        ed25519_pubkey: entry.ed25519_pubkey(),
                    })
                } else {
                    None
                }
            })
            .collect()
    }

    fn get_validator(ctx: &ViewContext, x_only_pubkey: String) -> Option<ValidatorInfo> {
        let holder: Holder = x_only_pubkey.parse().ok()?;
        let entry = ctx.model().validators().get(&holder)?;
        Some(make_validator_info(&holder, &entry))
    }

    fn get_staking_info(ctx: &ViewContext) -> StakingInfo {
        let model = ctx.model();
        StakingInfo {
            active_count: model.active_count(),
            total_stake: model.total_active_stake(),
        }
    }

    fn get_active_count(ctx: &ViewContext) -> u64 {
        ctx.model().active_count()
    }

    /// Slash a node's pooled stake by `amount` (saturating at the node's
    /// balance, per the spec's `reduce_stake`). The `τ_slash` share is burned
    /// from the contract's escrowed stake; the remainder is reported back to the
    /// caller (the reactor) to redistribute to the file's other nodes. The node
    /// is not removed from the validator set here — the caller handles role
    /// unwinding. Core-context only (reactor-orchestrated).
    fn slash(
        ctx: &CoreContext,
        x_only_pubkey: String,
        amount: Decimal,
    ) -> Result<SlashResult, Error> {
        let model = ctx.proc_context().model();
        let holder: Holder = x_only_pubkey
            .parse()
            .map_err(|_| Error::Message("invalid x_only_pubkey".to_string()))?;
        let entry = model
            .validators()
            .get(&holder)
            .ok_or(Error::Message("not registered".to_string()))?;

        let zero: Decimal = 0u64.try_into()?;
        let stake = entry.stake();
        // Saturating reduction: deduct min(amount, stake); shortfall not carried.
        let actual = if amount > stake { stake } else { amount };
        if actual <= zero {
            return Ok(SlashResult {
                slashed: zero,
                burned: zero,
                redistributable: zero,
            });
        }

        entry.set_stake(stake.sub(actual)?);
        if entry.status() == STATUS_ACTIVE {
            model.try_update_total_active_stake(|s| s.sub(actual))?;
        }

        // Burn the τ_slash share from the contract's escrowed stake.
        let tau_bps: Decimal = model.tau_slash_bps().try_into()?;
        let denom: Decimal = BPS_DENOM.try_into()?;
        let burned = actual.mul(tau_bps)?.div(denom)?;
        if burned > zero {
            token::burn(ctx.proc_context().contract_signer(), burned)?;
        }
        let redistributable = actual.sub(burned)?;

        Ok(SlashResult {
            slashed: actual,
            burned,
            redistributable,
        })
    }

    /// Core-context (reactor/admin) setter for the slashing parameters.
    fn set_slash_params(
        ctx: &CoreContext,
        lambda_slash: u64,
        tau_slash_bps: u64,
    ) -> Result<(), Error> {
        if tau_slash_bps > BPS_DENOM {
            return Err(Error::Message(
                "tau_slash_bps must be <= 10000".to_string(),
            ));
        }
        let model = ctx.proc_context().model();
        model.set_lambda_slash(lambda_slash);
        model.set_tau_slash_bps(tau_slash_bps);
        Ok(())
    }

    fn get_slash_params(ctx: &ViewContext) -> SlashParams {
        let model = ctx.model();
        SlashParams {
            lambda_slash: model.lambda_slash(),
            tau_slash_bps: model.tau_slash_bps(),
        }
    }

    /// Redistribute `amount` (the `(1 − τ_slash)` remainder of a slash, already
    /// held by the contract as escrowed stake) equally across `recipients` by
    /// crediting their pooled stake. Core-context only; the reactor supplies the
    /// file's other nodes. Conservation is exact regardless of `Decimal` rounding:
    /// the first `n−1` (in sorted order) each get `amount / n` and the last
    /// absorbs the remainder. Recipients are processed in sorted order for
    /// cross-indexer determinism.
    fn distribute_slash(
        ctx: &CoreContext,
        recipients: Vec<String>,
        amount: Decimal,
    ) -> Result<(), Error> {
        let model = ctx.proc_context().model();
        let zero: Decimal = 0u64.try_into()?;
        if amount <= zero {
            return Ok(());
        }
        if recipients.is_empty() {
            return Err(Error::Message(
                "no recipients for slash redistribution".to_string(),
            ));
        }

        let mut sorted = recipients;
        sorted.sort();
        let n = sorted.len();
        let n_dec: Decimal = (n as u64).try_into()?;
        let per = amount.div(n_dec)?;
        let head_total = per.mul(((n - 1) as u64).try_into()?)?;
        let last_share = amount.sub(head_total)?; // absorbs the rounding remainder

        for (i, pk) in sorted.iter().enumerate() {
            let credit = if i + 1 == n { last_share } else { per };
            let holder: Holder = pk
                .parse()
                .map_err(|_| Error::Message("invalid x_only_pubkey".to_string()))?;
            let entry = model.validators().get(&holder).ok_or(Error::Message(
                "slash recipient not registered".to_string(),
            ))?;
            entry.set_stake(entry.stake().add(credit)?);
            if entry.status() == STATUS_ACTIVE {
                model.try_update_total_active_stake(|s| s.add(credit))?;
            }
        }
        Ok(())
    }
}
