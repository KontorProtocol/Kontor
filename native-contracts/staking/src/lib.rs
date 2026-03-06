#![no_std]
contract!(name = "staking");

use stdlib::*;

const DEFAULT_EPOCH_LENGTH: u64 = 10;

#[derive(Clone, Default, Storage)]
struct ValidatorEntry {
    pub stake: Decimal,
    pub status: u64, // 0=inactive, 1=active, 2=pending_join, 3=pending_exit
    pub joined_epoch: u64,
    pub ed25519_pubkey: Vec<u8>,
}

#[derive(Clone, Default, Storage)]
struct ActiveEntry {
    pub stake: Decimal,
    pub ed25519_pubkey: Vec<u8>,
}

#[derive(Clone, Default, StorageRoot)]
struct StakingStorage {
    pub current_epoch: u64,
    pub epoch_length: u64,
    pub next_epoch_height: u64,
    pub min_stake: Decimal,
    pub validators: Map<String, ValidatorEntry>,
    pub active_set: Map<String, ActiveEntry>,
    pub active_count: u64,
    pub total_active_stake: Decimal,
    pub pending_joins: Map<String, bool>,
    pub pending_exits: Map<String, bool>,
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
        _ctx: &ProcContext,
        _ed25519_pubkey: Vec<u8>,
        _stake_amount: Decimal,
    ) -> Result<ValidatorInfo, Error> {
        Err(Error::Message("not yet implemented".to_string()))
    }

    fn add_stake(_ctx: &ProcContext, _amount: Decimal) -> Result<ValidatorInfo, Error> {
        Err(Error::Message("not yet implemented".to_string()))
    }

    fn begin_unstake(_ctx: &ProcContext) -> Result<ValidatorInfo, Error> {
        Err(Error::Message("not yet implemented".to_string()))
    }

    fn withdraw_stake(_ctx: &ProcContext) -> Result<ValidatorInfo, Error> {
        Err(Error::Message("not yet implemented".to_string()))
    }

    fn transition_epoch(
        _ctx: &CoreContext,
        _block_height: u64,
    ) -> Result<EpochTransitionResult, Error> {
        Err(Error::Message("not yet implemented".to_string()))
    }

    fn get_active_set(ctx: &ViewContext) -> Vec<ActiveValidatorInfo> {
        ctx.model()
            .active_set()
            .keys()
            .filter_map(|key| {
                let entry = ctx.model().active_set().get(&key)?;
                Some(ActiveValidatorInfo {
                    x_only_pubkey: key,
                    stake: entry.stake(),
                    ed25519_pubkey: entry.ed25519_pubkey(),
                })
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
