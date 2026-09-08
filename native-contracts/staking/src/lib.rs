#![no_std]
contract!(name = "staking");

use context::{HolderRef, Signer};
use stdlib::*;

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../token/wit"
);

import!(
    name = "filestorage",
    height = 0,
    tx_index = 0,
    path = "../filestorage/wit"
);

const ACTIVATION_DELAY: u64 = 12; // 2 * FINALITY_WINDOW (6)
// One challenge window plus the existing two-finality-window lifecycle margin.
// Outstanding storage obligations can extend this minimum indefinitely.
const WITHDRAWAL_DELAY: u64 = 2016 + ACTIVATION_DELAY;
const MAX_STAKE: u64 = 1_000_000_000;
// Consensus voting power truncates to whole KOR; smaller bonds can only back storage.
const MIN_VOTING_STAKE: u64 = 1;
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
struct StakeAccount {
    pub stake: Decimal,
    pub status: ValidatorStatus,
    pub activation_height: u64,
    pub deactivation_height: u64,
    pub withdrawal_height: Option<u64>,
    pub ed25519_pubkey: Vec<u8>,
}

fn make_stake_info(entry: &StakeAccountModel<context::ViewStorage>) -> StakeInfo {
    StakeInfo {
        stake: entry.stake(),
        withdrawal_height: entry.withdrawal_height(),
    }
}

#[derive(Clone, Default, StorageRoot)]
struct StakingStorage {
    pub min_stake: Decimal,
    pub accounts: Map<Holder, StakeAccount>,
    pub total_active_stake: Decimal,
    pub last_reward_height: Option<u64>,
    pub genesis_initialized: bool,
}

/// The consensus-set size = ACTIVE ∪ PENDING_EXIT (an exiting validator still
/// validates until its deactivation height — the same union `get_active_set`
/// returns). The framework maintains each status bucket's count, so this is two
/// O(1) reads of those counts — no hand-maintained `active_count` to keep in sync.
fn active_set_size<M: StakeAccountIndex<Holder>>(validators: &M) -> u64 {
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
    for (_, entry) in model.accounts().status(ValidatorStatus::PendingJoin).iter() {
        total = checked_total_stake(total, entry.stake)?;
    }
    Ok(())
}

fn make_validator_info(
    x_only_pubkey: &Holder,
    entry: &StakeAccountModel<context::ViewStorage>,
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

fn ensure_no_storage_obligations(signer: &Signer) -> Result<(), Error> {
    let HolderRef::SignerId(id) = signer.into() else {
        return Err(Error::Message("expected signer identity".to_string()));
    };
    if filestorage::has_storage_obligations(id) {
        return Err(Error::Message("unresolved storage obligations".to_string()));
    }
    Ok(())
}

fn ensure_no_bond_cleanup(signer: &Signer) -> Result<(), Error> {
    if let HolderRef::SignerId(id) = signer.into()
        && filestorage::is_bond_cleanup_pending(id)
    {
        return Err(Error::Message("bond cleanup pending".to_string()));
    }
    Ok(())
}

impl Guest for Staking {
    fn slash(ctx: &CoreContext, node_id: u64, amount: Decimal) -> Result<SlashResult, Error> {
        if amount < Decimal::default() {
            return Err(Error::Message("negative penalty".to_string()));
        }
        let proc = ctx.proc_context();
        let model = proc.model();
        let holder: Holder = HolderRef::SignerId(node_id).try_into()?;
        let entry = model
            .accounts()
            .get(&holder)
            .ok_or(Error::Message("missing bonded account".to_string()))?;
        let burned = amount.min(entry.stake());
        let remaining = entry.stake().sub(burned)?;
        let below_voting_unit = remaining < MIN_VOTING_STAKE.try_into()?;
        if matches!(
            entry.status().load(),
            ValidatorStatus::Active | ValidatorStatus::PendingExit
        ) {
            let removed = if below_voting_unit {
                entry.stake()
            } else {
                burned
            };
            model.try_update_total_active_stake(|total| total.sub(removed))?;
        }
        entry.set_stake(remaining);
        if below_voting_unit {
            entry.set_status(ValidatorStatus::Inactive);
            entry.set_deactivation_height(proc.block_height());
        }
        if remaining == Decimal::default() {
            entry.set_withdrawal_height(None);
        }
        if burned > Decimal::default() {
            token::burn(proc.contract_signer(), burned)?;
        }
        Ok(SlashResult { burned, remaining })
    }

    fn has_reward_recipients(ctx: &ViewContext) -> bool {
        !ctx.model()
            .accounts()
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
            .accounts()
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
                .accounts()
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
        model.set_min_stake(MIN_VOTING_STAKE.try_into().unwrap());
        ctx.contract()
    }

    fn register_validator(
        ctx: &ProcContext,
        ed25519_pubkey: Vec<u8>,
        stake_amount: Decimal,
    ) -> Result<ValidatorInfo, Error> {
        ensure_no_bond_cleanup(&ctx.signer())?;
        if ed25519_pubkey.len() != 32 {
            return Err(Error::Message(
                "expected 32-byte ed25519 pubkey".to_string(),
            ));
        }

        let model = ctx.model();
        let holder: Holder = (&ctx.signer()).into();

        if let Some(existing) = model.accounts().get(&holder)
            && existing.status().load() != ValidatorStatus::Inactive
        {
            return Err(Error::Message("already registered".to_string()));
        }

        let existing = model.accounts().get(&holder);
        if existing
            .as_ref()
            .is_some_and(|entry| entry.withdrawal_height().is_some())
        {
            return Err(Error::Message("withdrawal already requested".to_string()));
        }
        let zero = 0u64.try_into().unwrap();
        if stake_amount < zero {
            return Err(Error::Message("negative stake amount".to_string()));
        }
        let stake = existing
            .map(|entry| entry.stake())
            .unwrap_or(zero)
            .add(stake_amount)?;
        if stake < model.min_stake() {
            return Err(Error::Message("stake below minimum".to_string()));
        }
        if stake > MAX_STAKE.try_into().unwrap() {
            return Err(Error::Message("stake exceeds maximum".to_string()));
        }
        ensure_stake_capacity(ctx, stake)?;

        // Reject duplicate ed25519 keys — two validators with the same
        // consensus key would cause conflicts in Malachite. The `ed25519_pubkey`
        // index scopes this to the (≤1) holders already in that key's bucket,
        // not every validator.
        let dup = model
            .accounts()
            .ed25519_pubkey(ed25519_pubkey.clone())
            .keys()
            .any(|key| {
                key != holder
                    && model
                        .accounts()
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
        model.accounts().set(
            &holder,
            StakeAccount {
                stake,
                status: ValidatorStatus::PendingJoin,
                activation_height,
                deactivation_height: 0,
                withdrawal_height: None,
                ed25519_pubkey: ed25519_pubkey.clone(),
            },
        );

        if stake_amount > zero {
            token::transfer(
                ctx.signer(),
                ctx.contract_signer().as_holder().as_ref(),
                stake_amount,
            )?;
        }

        Ok(ValidatorInfo {
            x_only_pubkey: holder.to_string(),
            stake,
            status: ValidatorStatus::PendingJoin,
            activation_height,
            deactivation_height: 0,
            ed25519_pubkey,
        })
    }

    fn add_stake(ctx: &ProcContext, amount: Decimal) -> Result<StakeInfo, Error> {
        ensure_no_bond_cleanup(&ctx.signer())?;
        if amount <= 0u64.try_into().unwrap() {
            return Err(Error::Message("amount must be positive".to_string()));
        }
        let model = ctx.model();
        let holder: Holder = (&ctx.signer()).into();
        let entry = model.accounts().get(&holder);
        let status = entry
            .as_ref()
            .map(|entry| entry.status().load())
            .unwrap_or(ValidatorStatus::Inactive);
        if entry
            .as_ref()
            .is_some_and(|entry| entry.withdrawal_height().is_some())
        {
            return Err(Error::Message("withdrawal already requested".to_string()));
        }
        let stake = entry
            .as_ref()
            .map(|entry| entry.stake())
            .unwrap_or(0u64.try_into().unwrap())
            .add(amount)?;
        // Consensus arithmetic limits apply only when the bond backs voting power.
        if status != ValidatorStatus::Inactive {
            if stake > MAX_STAKE.try_into().unwrap() {
                return Err(Error::Message(
                    "total stake would exceed maximum".to_string(),
                ));
            }
            ensure_stake_capacity(ctx, amount)?;
        }
        if let Some(entry) = entry {
            entry.set_stake(stake);
        } else {
            model.accounts().set(
                &holder,
                StakeAccount {
                    stake,
                    status: ValidatorStatus::Inactive,
                    activation_height: 0,
                    deactivation_height: 0,
                    withdrawal_height: None,
                    ed25519_pubkey: Vec::new(),
                },
            );
        }
        if matches!(
            status,
            ValidatorStatus::Active | ValidatorStatus::PendingExit
        ) {
            model.try_update_total_active_stake(|total| checked_total_stake(total, amount))?;
        }
        token::transfer(
            ctx.signer(),
            ctx.contract_signer().as_holder().as_ref(),
            amount,
        )?;
        Ok(StakeInfo {
            stake,
            withdrawal_height: None,
        })
    }

    fn leave_validation(ctx: &ProcContext) -> Result<ValidatorInfo, Error> {
        let holder: Holder = (&ctx.signer()).into();
        let entry = ctx
            .model()
            .accounts()
            .get(&holder)
            .ok_or(Error::Message("not registered".to_string()))?;
        match entry.status().load() {
            ValidatorStatus::Active => {
                let height = ctx
                    .block_height()
                    .checked_add(ACTIVATION_DELAY)
                    .ok_or(Error::Message("deactivation height overflow".to_string()))?;
                entry.set_status(ValidatorStatus::PendingExit);
                entry.set_deactivation_height(height);
            }
            ValidatorStatus::PendingJoin => entry.set_status(ValidatorStatus::Inactive),
            _ => {
                return Err(Error::Message(
                    "invalid status for validator exit".to_string(),
                ));
            }
        }
        Ok(make_validator_info(&holder, &entry))
    }

    fn begin_unstake(ctx: &ProcContext) -> Result<StakeInfo, Error> {
        let holder: Holder = (&ctx.signer()).into();
        let entry = ctx
            .model()
            .accounts()
            .get(&holder)
            .ok_or(Error::Message("no bonded stake".to_string()))?;
        if entry.status().load() != ValidatorStatus::Inactive {
            return Err(Error::Message(
                "leave validation before unstaking".to_string(),
            ));
        }
        if entry.withdrawal_height().is_some() {
            return Err(Error::Message("withdrawal already requested".to_string()));
        }
        if entry.stake() <= 0u64.try_into().unwrap() {
            return Err(Error::Message("no bonded stake".to_string()));
        }
        let height = ctx
            .block_height()
            .checked_add(WITHDRAWAL_DELAY)
            .ok_or(Error::Message("withdrawal height overflow".to_string()))?;
        entry.set_withdrawal_height(Some(height));
        Ok(make_stake_info(&entry))
    }

    fn withdraw_stake(ctx: &ProcContext) -> Result<StakeInfo, Error> {
        let holder: Holder = (&ctx.signer()).into();
        let entry = ctx
            .model()
            .accounts()
            .get(&holder)
            .ok_or(Error::Message("no bonded stake".to_string()))?;
        let height = entry
            .withdrawal_height()
            .ok_or(Error::Message("withdrawal not requested".to_string()))?;
        if ctx.block_height() < height {
            return Err(Error::Message(
                "withdrawal delay has not elapsed".to_string(),
            ));
        }
        ensure_no_storage_obligations(&ctx.signer())?;
        let stake = entry.stake();
        entry.set_stake(0u64.try_into().unwrap());
        entry.set_withdrawal_height(None);
        token::transfer(ctx.contract_signer(), holder.as_ref(), stake)?;
        Ok(make_stake_info(&entry))
    }

    fn get_stake(ctx: &ViewContext, holder: String) -> Option<StakeInfo> {
        let holder: Holder = holder.parse().ok()?;
        let entry = ctx.model().accounts().get(&holder)?;
        Some(make_stake_info(&entry))
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
                v.stake >= MIN_VOTING_STAKE.try_into().unwrap(),
                "genesis stake must provide positive voting power"
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
            model.accounts().set(
                &holder,
                StakeAccount {
                    stake: v.stake,
                    status: ValidatorStatus::Active,
                    activation_height: 0,
                    deactivation_height: 0,
                    withdrawal_height: None,
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
            .accounts()
            .status(ValidatorStatus::PendingJoin)
            .keys()
            .collect();
        let pending_exit: Vec<Holder> = model
            .accounts()
            .status(ValidatorStatus::PendingExit)
            .keys()
            .collect();

        // `set_status` reconciles the `status` index in place, so the ACTIVE/
        // PENDING_EXIT bucket counts `active_set_size` reads stay correct with no
        // manual counter update here.
        for key in pending_join {
            if let Some(entry) = model.accounts().get(&key)
                && block_height >= entry.activation_height()
            {
                model.try_update_total_active_stake(|s| checked_total_stake(s, entry.stake()))?;
                entry.set_status(ValidatorStatus::Active);
                activated += 1;
            }
        }
        for key in pending_exit {
            if let Some(entry) = model.accounts().get(&key)
                && block_height >= entry.deactivation_height()
            {
                let stake = entry.stake();
                entry.set_status(ValidatorStatus::Inactive);
                model.try_update_total_active_stake(|s| s.sub(stake))?;
                deactivated += 1;
            }
        }

        Ok(ValidatorSetChange {
            activated,
            deactivated,
        })
    }

    fn get_active_set(ctx: &ViewContext) -> Vec<ActiveValidatorInfo> {
        let validators = ctx.model().accounts();
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
        let entry = ctx.model().accounts().get(&holder)?;
        if entry.ed25519_pubkey().is_empty() {
            return None;
        }
        Some(make_validator_info(&holder, &entry))
    }

    fn get_staking_info(ctx: &ViewContext) -> StakingInfo {
        let model = ctx.model();
        StakingInfo {
            active_count: active_set_size(&model.accounts()),
            total_stake: model.total_active_stake(),
        }
    }

    fn get_active_count(ctx: &ViewContext) -> u64 {
        active_set_size(&ctx.model().accounts())
    }
}
