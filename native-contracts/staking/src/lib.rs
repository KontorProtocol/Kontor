#![no_std]
contract!(name = "staking");

use stdlib::*;

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../token/wit"
);

const DEFAULT_EPOCH_LENGTH: u64 = 10;

#[derive(Clone, Default, Storage)]
struct ValidatorEntry {
    pub stake: Decimal,
    pub status: u64, // 0=inactive, 1=active, 2=pending_join, 3=pending_exit
    pub joined_epoch: u64,
    pub ed25519_pubkey: Vec<u8>,
}

#[derive(Clone, Default, StorageRoot)]
struct StakingStorage {
    pub current_epoch: u64,
    pub epoch_length: u64,
    pub next_epoch_height: u64,
    pub min_stake: Decimal,
    pub validators: Map<String, ValidatorEntry>,
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

fn make_validator_info(pubkey: String, entry: &ValidatorEntryModel) -> ValidatorInfo {
    ValidatorInfo {
        x_only_pubkey: pubkey,
        stake: entry.stake(),
        status: status_to_enum(entry.status()),
        joined_epoch: entry.joined_epoch(),
        ed25519_pubkey: entry.ed25519_pubkey(),
    }
}

impl Guest for Staking {
    fn init(ctx: &ProcContext) {
        let storage = StakingStorage::default();
        storage.init(ctx);
        let model = ctx.model();
        model.set_epoch_length(DEFAULT_EPOCH_LENGTH);
        model.set_next_epoch_height(DEFAULT_EPOCH_LENGTH);
        model.set_min_stake(1.into());
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
        let signer_key = ctx.signer().to_string();

        if let Some(existing) = model.validators().get(&signer_key) {
            if existing.status() != STATUS_INACTIVE {
                return Err(Error::Message("already registered".to_string()));
            }
            if existing.stake() > 0.into() {
                return Err(Error::Message(
                    "withdraw existing stake before re-registering".to_string(),
                ));
            }
        }

        if stake_amount < model.min_stake() {
            return Err(Error::Message("stake below minimum".to_string()));
        }

        token::transfer(
            ctx.signer(),
            &ctx.contract_signer().to_string(),
            stake_amount,
        )?;

        model.validators().set(
            signer_key.clone(),
            ValidatorEntry {
                stake: stake_amount,
                status: STATUS_PENDING_JOIN,
                joined_epoch: 0,
                ed25519_pubkey: ed25519_pubkey.clone(),
            },
        );

        Ok(ValidatorInfo {
            x_only_pubkey: signer_key,
            stake: stake_amount,
            status: ValidatorStatus::PendingJoin,
            joined_epoch: 0,
            ed25519_pubkey,
        })
    }

    fn add_stake(ctx: &ProcContext, amount: Decimal) -> Result<ValidatorInfo, Error> {
        let model = ctx.model();
        let signer_key = ctx.signer().to_string();

        let entry = model
            .validators()
            .get(&signer_key)
            .ok_or(Error::Message("not registered".to_string()))?;

        if amount <= 0.into() {
            return Err(Error::Message("amount must be positive".to_string()));
        }

        let status = entry.status();
        if status == STATUS_INACTIVE || status == STATUS_PENDING_EXIT {
            return Err(Error::Message(
                "cannot add stake while inactive or pending exit".to_string(),
            ));
        }

        token::transfer(ctx.signer(), &ctx.contract_signer().to_string(), amount)?;

        let new_stake = entry.stake().add(amount)?;
        entry.set_stake(new_stake);

        if status == STATUS_ACTIVE {
            model.try_update_total_active_stake(|s| s.add(amount))?;
        }

        Ok(make_validator_info(signer_key, &entry))
    }

    fn begin_unstake(ctx: &ProcContext) -> Result<ValidatorInfo, Error> {
        let model = ctx.model();
        let signer_key = ctx.signer().to_string();

        let entry = model
            .validators()
            .get(&signer_key)
            .ok_or(Error::Message("not registered".to_string()))?;

        match entry.status() {
            STATUS_ACTIVE => {
                entry.set_status(STATUS_PENDING_EXIT);
            }
            // Not yet activated — go straight to inactive
            STATUS_PENDING_JOIN => {
                entry.set_status(STATUS_INACTIVE);
            }
            _ => return Err(Error::Message("invalid status for unstaking".to_string())),
        }

        Ok(make_validator_info(signer_key, &entry))
    }

    fn withdraw_stake(ctx: &ProcContext) -> Result<ValidatorInfo, Error> {
        let model = ctx.model();
        let signer_key = ctx.signer().to_string();

        let entry = model
            .validators()
            .get(&signer_key)
            .ok_or(Error::Message("not registered".to_string()))?;

        if entry.status() != STATUS_INACTIVE {
            return Err(Error::Message(
                "validator must be inactive to withdraw".to_string(),
            ));
        }

        let stake = entry.stake();
        if stake <= 0.into() {
            return Err(Error::Message("no stake to withdraw".to_string()));
        }

        token::transfer(ctx.contract_signer(), &signer_key, stake)?;

        entry.set_stake(0.into());

        Ok(ValidatorInfo {
            x_only_pubkey: signer_key,
            stake: 0.into(),
            status: ValidatorStatus::Inactive,
            joined_epoch: entry.joined_epoch(),
            ed25519_pubkey: entry.ed25519_pubkey(),
        })
    }

    fn transition_epoch(
        ctx: &CoreContext,
        block_height: u64,
    ) -> Result<EpochTransitionResult, Error> {
        let model = ctx.proc_context().model();

        if block_height < model.next_epoch_height() {
            return Ok(EpochTransitionResult {
                new_epoch: model.current_epoch(),
                activated: 0,
                deactivated: 0,
            });
        }

        let mut activated = 0u64;
        let mut deactivated = 0u64;

        let keys: Vec<String> = model.validators().keys().collect();
        for key in keys {
            if let Some(entry) = model.validators().get(&key) {
                match entry.status() {
                    STATUS_PENDING_JOIN => {
                        entry.set_status(STATUS_ACTIVE);
                        entry.set_joined_epoch(model.current_epoch() + 1);
                        model.try_update_total_active_stake(|s| s.add(entry.stake()))?;
                        model.update_active_count(|c| c + 1);
                        activated += 1;
                    }
                    STATUS_PENDING_EXIT => {
                        entry.set_status(STATUS_INACTIVE);
                        model.try_update_total_active_stake(|s| s.sub(entry.stake()))?;
                        model.update_active_count(|c| c - 1);
                        deactivated += 1;
                    }
                    _ => {}
                }
            }
        }

        let new_epoch = model.current_epoch() + 1;
        model.set_current_epoch(new_epoch);
        model.set_next_epoch_height(block_height + model.epoch_length());

        Ok(EpochTransitionResult {
            new_epoch,
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
        Some(make_validator_info(x_only_pubkey, &entry))
    }

    fn get_epoch_info(ctx: &ViewContext) -> EpochInfo {
        let model = ctx.model();
        EpochInfo {
            epoch: model.current_epoch(),
            next_epoch_height: model.next_epoch_height(),
            active_count: model.active_count(),
            total_stake: model.total_active_stake(),
        }
    }

    fn get_active_count(ctx: &ViewContext) -> u64 {
        ctx.model().active_count()
    }
}
