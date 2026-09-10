use core::ops::Bound;

use super::rewards::WeightChange;
use super::*;

pub(super) fn begin_removal(
    model: &ProtocolStateWriteModel<context::ProcStorage>,
    agreement_id: &str,
    node_id: u64,
) -> Result<(), Error> {
    let id = agreement_id.to_string();
    let old = model.reward_weights().get(&id).unwrap_or_default();
    let count = model
        .memberships()
        .by_agreement_active(id.clone(), true)
        .len();
    let agreement = model
        .agreements()
        .get(&id)
        .expect("membership agreement exists");
    let new = if agreement.active() {
        rewards::per_host(agreement.storage_weight(), count - 1)?
    } else {
        Integer::default()
    };
    // The common small-replica case fits a fixed amount of work per cleanup
    // step. Larger files use the staged path without imposing a membership cap.
    if count <= 8 {
        model
            .memberships()
            .get(&(id.clone(), node_id))
            .expect("membership exists")
            .set_active(false);
        rewards::membership_changed(model, &id, None, Some(node_id))?;
        release_unused_reservation(model, &id, node_id)?;
        return Ok(());
    }
    model.set_reward_reweight(Some(RewardReweight {
        agreement_id: id,
        node_id,
        per_host: new,
        increase: rewards::sub(new, old)?,
        ..RewardReweight::default()
    }));
    Ok(())
}

pub(super) fn step(model: &ProtocolStateWriteModel<context::ProcStorage>) -> Result<bool, Error> {
    let Some(entry) = model.reward_reweight() else {
        return Ok(false);
    };
    let job = entry.load();
    if job.phase.applied_at().is_some() {
        if let Some(node_id) = model.reward_reweight_deltas().keys().next() {
            rewards::settle(model, node_id)?;
        } else {
            model.set_reward_reweight(None);
        }
        return Ok(true);
    }
    let RewardReweightPhase::Preparing(mut preparation) = job.phase else {
        unreachable!("applied jobs are folded above");
    };
    let lower = preparation
        .cursor
        .map(Bound::Excluded)
        .unwrap_or(Bound::Unbounded);
    let next = model
        .memberships()
        .reward_members(job.agreement_id.clone(), true)
        .range((lower, Bound::Unbounded))
        .keys()
        .next();
    if let Some((_, node_id)) = next {
        preparation.cursor = Some(node_id);
        if node_id != job.node_id {
            model.reward_reweight_deltas().set(&node_id, job.increase);
            if !model.bond_cleanup_pending().get(&node_id).unwrap_or(false) {
                preparation.eligible_increase = preparation.eligible_increase.add(job.increase)?;
            }
        }
        entry.set_phase(RewardReweightPhase::Preparing(preparation));
    } else {
        let old = model
            .reward_weights()
            .get(&job.agreement_id)
            .unwrap_or_default();
        rewards::change_weight(model, job.node_id, old, Integer::default())?;
        model.set_reward_weight(model.reward_weight().add(preparation.eligible_increase)?);
        model.reward_weights().set(&job.agreement_id, job.per_host);
        model
            .memberships()
            .get(&(job.agreement_id.clone(), job.node_id))
            .expect("cleanup membership exists")
            .set_active(false);
        release_unused_reservation(model, &job.agreement_id, job.node_id)?;
        entry.set_phase(RewardReweightPhase::Applied(model.reward_index()));
    }
    Ok(true)
}

pub(super) fn ensure_unlocked(
    model: &ProtocolStateWriteModel<context::ProcStorage>,
    agreement_id: &str,
) -> Result<(), Error> {
    if model
        .reward_reweight()
        .is_some_and(|job| job.agreement_id() == agreement_id)
    {
        return Err(Error::Message(
            "agreement reward cleanup in progress".into(),
        ));
    }
    Ok(())
}

pub(super) fn applied_weight_change<S: ReadStorage + 'static>(
    model: &ProtocolStateModel<S>,
    node_id: u64,
) -> Option<WeightChange> {
    let effective_index = model.reward_reweight()?.phase().load().applied_at()?;
    let increase = model.reward_reweight_deltas().get(&node_id)?;
    Some(WeightChange {
        effective_index,
        increase,
    })
}

pub(super) fn exclude_prepared_increase(
    model: &ProtocolStateWriteModel<context::ProcStorage>,
    node_id: u64,
) -> Result<(), Error> {
    // A host can exhaust after being visited by preparation but before the new
    // shares take effect. Remove its prepared increase from that future total too.
    if let Some(job) = model.reward_reweight()
        && let RewardReweightPhase::Preparing(mut preparation) = job.phase().load()
        && let Some(delta) = model.reward_reweight_deltas().get(&node_id)
    {
        preparation.eligible_increase = rewards::sub(preparation.eligible_increase, delta)?;
        job.set_phase(RewardReweightPhase::Preparing(preparation));
    }
    Ok(())
}
