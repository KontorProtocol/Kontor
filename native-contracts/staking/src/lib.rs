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
const MAX_STAKE: u64 = 1_000_000_000;
// Malachite's default thresholds multiply observed voting power by three.
const MAX_TOTAL_STAKE: u64 = u64::MAX / 3;

// `status` and `ed25519_pubkey` are indexed so the per-block status sweep and the
// register-time duplicate-key check are prefix reads of a bucket, not full scans of
// every validator. `status` partitions by lifecycle (the `ValidatorStatus` enum —
// a storage enum, so it buckets by its discriminant); `ed25519_pubkey` partitions
// by consensus key (a bucket holds the ≤1 validators sharing a key — enough to
// enforce uniqueness without scanning).
//
// The `status` index COVERS `(stake, ed25519_pubkey)` so `get_active_set` reads the
// whole consensus set index-only (`.iter()`, no per-validator `get`). TRADE-OFF: `stake`
// is HOT (rewritten by `add_stake`/`process_pending`/exit), so its covering leaf is
// re-written on every stake change — a net win only if active-set reads dominate stake
// mutations. `ed25519_pubkey` is cold. (Both struct-level so the index ids stay
// status=0, ed25519_pubkey=1.)
#[derive(Clone, Storage)]
#[index(status, by = status, include = (stake, ed25519_pubkey))]
#[index(ed25519_pubkey, by = ed25519_pubkey)]
struct ValidatorEntry {
    pub stake: Decimal,
    pub status: ValidatorStatus,
    pub activation_height: u64,
    pub deactivation_height: u64,
    pub ed25519_pubkey: Vec<u8>,
}

#[derive(Clone, Default, StorageRoot)]
struct StakingStorage {
    pub min_stake: Decimal,
    pub validators: Map<Holder, ValidatorEntry>,
    pub total_active_stake: Decimal,
    pub last_reward_height: Option<u64>,
    pub genesis_initialized: bool,
}

/// The consensus-set size = ACTIVE ∪ PENDING_EXIT (an exiting validator still
/// validates until its deactivation height — the same union `get_active_set`
/// returns). The framework maintains each status bucket's count, so this is two
/// O(1) reads of those counts — no hand-maintained `active_count` to keep in sync.
fn active_set_size<M: ValidatorEntryIndex<Holder>>(validators: &M) -> u64 {
    validators.status(ValidatorStatus::Active).len()
        + validators.status(ValidatorStatus::PendingExit).len()
}

fn checked_total_stake(total: Decimal, additional: Decimal) -> Result<Decimal, Error> {
    let total = total.add(additional)?;
    if total > MAX_TOTAL_STAKE.try_into()? {
        return Err(Error::Message(
            "total stake exceeds voting power limit".to_string(),
        ));
    }
    Ok(total)
}

fn ensure_stake_capacity(ctx: &ProcContext, additional: Decimal) -> Result<(), Error> {
    let model = ctx.model();
    let mut total = checked_total_stake(model.total_active_stake(), additional)?;
    // Reserve pending joins now, so activation cannot halt a later block.
    // Full Decimal stakes conservatively bound the sum of truncated voting powers.
    for (_, entry) in model
        .validators()
        .status(ValidatorStatus::PendingJoin)
        .iter()
    {
        total = checked_total_stake(total, entry.stake)?;
    }
    Ok(())
}

fn make_validator_info(
    x_only_pubkey: &Holder,
    entry: &ValidatorEntryModel<context::ViewStorage>,
) -> ValidatorInfo {
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
    fn has_reward_recipients(ctx: &ViewContext) -> bool {
        !ctx.model()
            .validators()
            .status(ValidatorStatus::Active)
            .is_empty()
    }

    fn last_reward_height(ctx: &ViewContext) -> Option<u64> {
        ctx.model().last_reward_height()
    }

    fn distribute_ordering_reward(ctx: &CoreContext, amount: Decimal) -> Result<Decimal, Error> {
        let proc = ctx.proc_context();
        let model = proc.model();
        let height = proc.block_height();
        if model
            .last_reward_height()
            .is_some_and(|last| height <= last)
        {
            return Err(Error::Message(
                "reward height already processed".to_string(),
            ));
        }
        let zero: Decimal = 0u64.try_into()?;
        if amount < zero {
            return Err(Error::Message("negative ordering reward".to_string()));
        }
        if amount == zero {
            model.set_last_reward_height(Some(height));
            return Ok(zero);
        }
        ensure_stake_capacity(&proc, amount)?;
        // Snapshot before stake writes change the covering index. Holder-string order
        // pins which recipient absorbs the rounding remainder.
        let mut recipients: Vec<_> = model
            .validators()
            .status(ValidatorStatus::Active)
            .iter()
            .map(|(holder, entry)| (holder.to_string(), holder, entry.stake))
            .collect();
        recipients.sort_by(|a, b| a.0.cmp(&b.0));
        let mut total = zero;
        for (_, _, stake) in &recipients {
            if *stake <= zero {
                return Err(Error::Message("nonpositive reward stake".to_string()));
            }
            total = total.add(*stake)?;
        }
        if total == zero {
            return Err(Error::Message(
                "ordering reward has no recipients".to_string(),
            ));
        }
        let mut credited = zero;
        for (index, (_, holder, stake)) in recipients.iter().enumerate() {
            let remaining = amount.sub(credited)?;
            let share = if index + 1 == recipients.len() {
                remaining
            } else {
                // Decimal division can round up; never allocate more than remains.
                amount.mul(*stake)?.div(total)?.min(remaining)
            };
            let entry = model
                .validators()
                .get(holder)
                .ok_or(Error::Message("missing reward recipient".to_string()))?;
            entry.set_stake(stake.add(share)?);
            credited = credited.add(share)?;
        }
        model.try_update_total_active_stake(|stake| checked_total_stake(stake, credited))?;
        model.set_last_reward_height(Some(height));
        token::transfer_ordering_reward(
            ctx.core_signer(),
            proc.contract_signer().as_holder().as_ref(),
            credited,
        )?;
        Ok(credited)
    }

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
        ensure_stake_capacity(ctx, stake_amount)?;

        // Reject duplicate ed25519 keys — two validators with the same
        // consensus key would cause conflicts in Malachite. The `ed25519_pubkey`
        // index scopes this to the (≤1) holders already in that key's bucket,
        // not every validator.
        let dup = model
            .validators()
            .ed25519_pubkey(ed25519_pubkey.clone())
            .keys()
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
        ensure_stake_capacity(ctx, amount)?;

        // Effects before interactions (CEI pattern)
        entry.set_stake(new_stake);
        if status == ValidatorStatus::Active {
            model.try_update_total_active_stake(|s| checked_total_stake(s, amount))?;
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
        if model.genesis_initialized() {
            return;
        }
        let mut genesis_stake = 0u64.try_into().unwrap();
        for v in &validators {
            assert!(
                v.ed25519_pubkey.len() == 32,
                "expected 32-byte ed25519 pubkey in genesis set"
            );
            assert!(
                v.stake > 0u64.try_into().unwrap(),
                "genesis stake must be positive"
            );
            genesis_stake = checked_total_stake(genesis_stake, v.stake)
                .expect("genesis stake exceeds voting power limit");
        }
        ensure_stake_capacity(&ctx.proc_context(), genesis_stake)
            .expect("genesis stake exceeds voting power limit");
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
                .try_update_total_active_stake(|s| checked_total_stake(s, v.stake))
                .expect("Failed to update total active stake");
        }
        // No `active_count` to set — the `status` index's ACTIVE bucket count is
        // maintained by these `set`s and read back via `active_set_size`.
        model.set_genesis_initialized(true);
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
            .status(ValidatorStatus::PendingJoin)
            .keys()
            .collect();
        let pending_exit: Vec<Holder> = model
            .validators()
            .status(ValidatorStatus::PendingExit)
            .keys()
            .collect();

        // `set_status` reconciles the `status` index in place, so the ACTIVE/
        // PENDING_EXIT bucket counts `active_set_size` reads stay correct with no
        // manual counter update here.
        for key in pending_join {
            if let Some(entry) = model.validators().get(&key)
                && block_height >= entry.activation_height()
            {
                model.try_update_total_active_stake(|s| checked_total_stake(s, entry.stake()))?;
                entry.set_status(ValidatorStatus::Active);
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
        // COVERING read: the `status` index carries each validator's `stake` +
        // `ed25519_pubkey` in its leaf, so `.iter()` yields them directly — no
        // per-validator `get()`.
        let mut set: Vec<ActiveValidatorInfo> = validators
            .status(ValidatorStatus::Active)
            .iter()
            .chain(validators.status(ValidatorStatus::PendingExit).iter())
            .map(|(key, v)| ActiveValidatorInfo {
                x_only_pubkey: key.to_string(),
                stake: v.stake,
                ed25519_pubkey: v.ed25519_pubkey,
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
