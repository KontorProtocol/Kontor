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

// `status` and `ed25519_pubkey` are indexed so the per-block status sweep and the
// register-time duplicate-key check are prefix reads of a bucket, not full scans of
// every validator. `status` partitions by lifecycle (the `ValidatorStatus` enum —
// a storage enum, so it buckets by its discriminant); `ed25519_pubkey` partitions
// by consensus key (a bucket holds the ≤1 validators sharing a key — enough to
// enforce uniqueness without scanning).
#[derive(Clone, Storage, Indexed)]
struct ValidatorEntry {
    pub stake: Decimal,
    #[index]
    pub status: ValidatorStatus,
    pub activation_height: u64,
    pub deactivation_height: u64,
    #[index]
    pub ed25519_pubkey: Vec<u8>,
}

#[derive(Clone, Default, StorageRoot)]
struct StakingStorage {
    pub min_stake: Decimal,
    pub validators: IndexedMap<Holder, ValidatorEntry>,
    pub total_active_stake: Decimal,
}

/// The consensus-set size = ACTIVE ∪ PENDING_EXIT (an exiting validator still
/// validates until its deactivation height — the same union `get_active_set`
/// returns). The framework maintains each status bucket's count, so this is two
/// O(1) reads of those counts — no hand-maintained `active_count` to keep in sync.
fn active_set_size<M: ValidatorEntryIndex<Holder>>(validators: &M) -> u64 {
    validators.count_status(ValidatorStatus::Active)
        + validators.count_status(ValidatorStatus::PendingExit)
}

fn make_validator_info(x_only_pubkey: &Holder, entry: &ValidatorEntryModel) -> ValidatorInfo {
    ValidatorInfo {
        x_only_pubkey: x_only_pubkey.to_string(),
        stake: entry.stake(),
        status: entry.status().load(),
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
            && existing.status().load() != ValidatorStatus::Inactive
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
        // consensus key would cause conflicts in Malachite. The `ed25519_pubkey`
        // index scopes this to the (≤1) holders already in that key's bucket,
        // not every validator.
        let dup = model
            .validators()
            .where_ed25519_pubkey(ed25519_pubkey.clone())
            .any(|key| {
                key != holder
                    && model
                        .validators()
                        .get(&key)
                        .is_some_and(|entry| entry.status().load() != ValidatorStatus::Inactive)
            });
        if dup {
            return Err(Error::Message(
                "ed25519 pubkey already registered by another validator".to_string(),
            ));
        }

        // Effects before interactions (CEI pattern)
        let activation_height = ctx.block_height() + ACTIVATION_DELAY;
        model.validators().set(
            &holder,
            ValidatorEntry {
                stake: stake_amount,
                status: ValidatorStatus::PendingJoin,
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

        let status = entry.status().load();
        if status == ValidatorStatus::Inactive || status == ValidatorStatus::PendingExit {
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
        if status == ValidatorStatus::Active {
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

        match entry.status().load() {
            ValidatorStatus::Active => {
                entry.set_status(ValidatorStatus::PendingExit);
                let deactivation_height = ctx.block_height() + ACTIVATION_DELAY;
                entry.set_deactivation_height(deactivation_height);
            }
            // Not yet activated — go straight to inactive and return tokens
            ValidatorStatus::PendingJoin => {
                let stake = entry.stake();
                entry.set_stake(0u64.try_into().unwrap());
                entry.set_status(ValidatorStatus::Inactive);
                token::transfer(ctx.contract_signer(), holder.as_ref(), stake)?;
            }
            _ => return Err(Error::Message("invalid status for unstaking".to_string())),
        }

        Ok(make_validator_info(&holder, &entry))
    }

    fn set_genesis_set(ctx: &CoreContext, validators: Vec<ActiveValidatorInfo>) {
        let model = ctx.proc_context().model();
        if active_set_size(&model.validators()) > 0 {
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
                    status: ValidatorStatus::Active,
                    activation_height: 0,
                    deactivation_height: 0,
                    ed25519_pubkey: v.ed25519_pubkey.clone(),
                },
            );
            model
                .try_update_total_active_stake(|s| s.add(v.stake))
                .expect("Failed to update total active stake");
        }
        // No `active_count` to set — the `status` index's ACTIVE bucket count is
        // maintained by these `set`s and read back via `active_set_size`.
    }

    fn process_pending_validators(
        ctx: &CoreContext,
        block_height: u64,
    ) -> Result<ValidatorSetChange, Error> {
        let model = ctx.proc_context().model();

        let mut activated = 0u64;
        let mut deactivated = 0u64;

        // Only pending validators can change state this block — read their two
        // status buckets instead of scanning every validator. Collect the keys
        // first: activating/deactivating moves the member out of the bucket, so
        // iterating it live would mutate mid-scan.
        let pending_join: Vec<Holder> = model
            .validators()
            .where_status(ValidatorStatus::PendingJoin)
            .collect();
        let pending_exit: Vec<Holder> = model
            .validators()
            .where_status(ValidatorStatus::PendingExit)
            .collect();

        // `set_status` reconciles the `status` index in place, so the ACTIVE/
        // PENDING_EXIT bucket counts `active_set_size` reads stay correct with no
        // manual counter update here.
        for key in pending_join {
            if let Some(entry) = model.validators().get(&key)
                && block_height >= entry.activation_height()
            {
                entry.set_status(ValidatorStatus::Active);
                model.try_update_total_active_stake(|s| s.add(entry.stake()))?;
                activated += 1;
            }
        }
        for key in pending_exit {
            if let Some(entry) = model.validators().get(&key)
                && block_height >= entry.deactivation_height()
            {
                let stake = entry.stake();
                entry.set_stake(0u64.try_into().unwrap());
                entry.set_status(ValidatorStatus::Inactive);
                model.try_update_total_active_stake(|s| s.sub(stake))?;
                token::transfer(ctx.proc_context().contract_signer(), key, stake)?;
                deactivated += 1;
            }
        }

        Ok(ValidatorSetChange {
            activated,
            deactivated,
        })
    }

    fn get_active_set(ctx: &ViewContext) -> Vec<ActiveValidatorInfo> {
        let validators = ctx.model().validators();
        // The consensus set is ACTIVE ∪ PENDING_EXIT (exiting validators still
        // validate until their deactivation height) — two index buckets, not a
        // scan-and-filter over every validator.
        let mut set: Vec<ActiveValidatorInfo> = validators
            .where_status(ValidatorStatus::Active)
            .chain(validators.where_status(ValidatorStatus::PendingExit))
            .filter_map(|key| {
                let entry = validators.get(&key)?;
                Some(ActiveValidatorInfo {
                    x_only_pubkey: key.to_string(),
                    stake: entry.stake(),
                    ed25519_pubkey: entry.ed25519_pubkey(),
                })
            })
            .collect();
        // Re-merge the two buckets into one holder-ordered set so the order the
        // consumer (`ValidatorSet`, which preserves insertion order) sees is
        // identical to the old full-scan order, independent of status.
        set.sort_by(|a, b| a.x_only_pubkey.cmp(&b.x_only_pubkey));
        set
    }

    fn get_validator(ctx: &ViewContext, x_only_pubkey: String) -> Option<ValidatorInfo> {
        let holder: Holder = x_only_pubkey.parse().ok()?;
        let entry = ctx.model().validators().get(&holder)?;
        Some(make_validator_info(&holder, &entry))
    }

    fn get_staking_info(ctx: &ViewContext) -> StakingInfo {
        let model = ctx.model();
        StakingInfo {
            active_count: active_set_size(&model.validators()),
            total_stake: model.total_active_stake(),
        }
    }

    fn get_active_count(ctx: &ViewContext) -> u64 {
        active_set_size(&ctx.model().validators())
    }
}
