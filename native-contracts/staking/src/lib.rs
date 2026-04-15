#![no_std]
contract!(name = "staking");

use context::Holder;
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
}

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
    fn init(ctx: &ProcContext) {
        let storage = StakingStorage::default();
        storage.init(ctx);
        let model = ctx.model();
        model.set_min_stake(1u64.try_into().unwrap());
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
        let keys: Vec<String> = model.validators().keys().collect();
        for key in keys {
            if let Some(entry) = model.validators().get(&key)
                && key != holder.to_string()
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
            holder.clone(),
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
            &ctx.contract_signer().to_string(),
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

        token::transfer(ctx.signer(), &ctx.contract_signer().to_string(), amount)?;

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
                token::transfer(ctx.contract_signer(), &holder.to_string(), stake)?;
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
        let staking_address = ctx.proc_context().contract_signer().to_string();
        for v in &validators {
            token::issue_to(ctx.core_signer(), &staking_address, v.stake)
                .expect("Failed to mint genesis stake");
            let holder: Holder = v.x_only_pubkey.parse().expect("invalid holder in genesis set");
            model.validators().set(
                holder,
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

        let keys: Vec<String> = model.validators().keys().collect();
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
                        token::transfer(
                            ctx.proc_context().contract_signer(),
                            &key,
                            stake,
                        )?;
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
            .keys::<String>()
            .filter_map(|key| {
                let entry = ctx.model().validators().get(&key)?;
                if entry.status() == STATUS_ACTIVE || entry.status() == STATUS_PENDING_EXIT {
                    Some(ActiveValidatorInfo {
                        x_only_pubkey: key,
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
        let entry = ctx.model().validators().get(&x_only_pubkey)?;
        let holder: Holder = x_only_pubkey.parse().expect("invalid holder");
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
}
