use super::*;

const WEIGHT_SCALE: Integer = Integer::from_u128(10u128.pow(18));
const INDEX_SCALE: Integer = Integer::from_u128(10u128.pow(36));

pub(super) fn sub(a: Integer, b: Integer) -> Result<Integer, Error> {
    let value = a.sub(b)?;
    if value < Integer::default() {
        return Err(Error::Validation("negative reward accounting value".into()));
    }
    Ok(value)
}

pub(super) struct WeightChange {
    pub effective_index: Integer,
    pub increase: Integer,
}

enum Earnings {
    Accruing,
    Stopped,
}

impl RewardAccount {
    fn accrue_to(&mut self, index: Integer) -> Result<(), Error> {
        let (units, remainder) = self.share_weight.checked_mul_add_div_rem(
            sub(index, self.settled_index)?,
            self.fractional_remainder,
            INDEX_SCALE,
        )?;
        self.claimable_units = self.claimable_units.add(units)?;
        self.fractional_remainder = remainder;
        self.settled_index = index;
        Ok(())
    }

    fn settle_at(
        mut self,
        index: Integer,
        earnings: Earnings,
        change: Option<WeightChange>,
    ) -> Result<Self, Error> {
        match earnings {
            Earnings::Accruing => {
                if let Some(change) = change {
                    self.accrue_to(change.effective_index)?;
                    self.share_weight = self.share_weight.add(change.increase)?;
                }
                self.accrue_to(index)?;
            }
            Earnings::Stopped => {
                // Exhaustion already settled the account. Keep its membership
                // weights current for removal without earning past that cutoff.
                if let Some(change) = change {
                    self.share_weight = self.share_weight.add(change.increase)?;
                }
                self.settled_index = index;
            }
        }
        Ok(self)
    }
}

struct Settlement {
    account: RewardAccount,
    needs_write: bool,
    consumed_weight_change: bool,
}

impl Settlement {
    fn write(
        self,
        model: &ProtocolStateWriteModel<context::ProcStorage>,
        node_id: u64,
    ) -> RewardAccount {
        if self.needs_write {
            model.reward_accounts().set(&node_id, self.account.clone());
        }
        if self.consumed_weight_change {
            model.reward_reweight_deltas().remove(&node_id);
        }
        self.account
    }
}

fn read_settlement<S: ReadStorage + 'static>(
    model: &ProtocolStateModel<S>,
    node_id: u64,
) -> Result<Settlement, Error> {
    let entry = model.reward_accounts().get(&node_id);
    let change = cleanup::applied_weight_change(model, node_id);
    let consumed_weight_change = change.is_some();
    let needs_write = entry.is_some() || consumed_weight_change;
    let earnings = if model.bond_cleanup_pending().get(&node_id).unwrap_or(false) {
        Earnings::Stopped
    } else {
        Earnings::Accruing
    };
    let account = entry
        .map(|entry| entry.load())
        .unwrap_or_default()
        .settle_at(model.reward_index(), earnings, change)?;
    Ok(Settlement {
        account,
        needs_write,
        consumed_weight_change,
    })
}

pub(super) fn settle(
    model: &ProtocolStateWriteModel<context::ProcStorage>,
    node_id: u64,
) -> Result<RewardAccount, Error> {
    Ok(read_settlement(model, node_id)?.write(model, node_id))
}

pub(super) fn take_claimable(
    model: &ProtocolStateWriteModel<context::ProcStorage>,
    node_id: u64,
) -> Result<Decimal, Error> {
    let mut settlement = read_settlement(model, node_id)?;
    let amount = Decimal::from_raw_units(settlement.account.claimable_units);
    settlement.account.claimable_units = Integer::default();
    settlement.write(model, node_id);
    Ok(amount)
}

pub(super) fn balance(ctx: &ViewContext, node_id: u64) -> Result<Decimal, Error> {
    Ok(Decimal::from_raw_units(
        read_settlement(&ctx.model(), node_id)?
            .account
            .claimable_units,
    ))
}

pub(super) fn change_weight(
    model: &ProtocolStateWriteModel<context::ProcStorage>,
    node_id: u64,
    old: Integer,
    new: Integer,
) -> Result<(), Error> {
    if old == new {
        return Ok(());
    }
    let mut settlement = read_settlement(model, node_id)?;
    settlement.account.share_weight = sub(settlement.account.share_weight, old)?.add(new)?;
    if !model.bond_cleanup_pending().get(&node_id).unwrap_or(false) {
        model.set_reward_weight(sub(model.reward_weight(), old)?.add(new)?);
    }
    settlement.needs_write = true;
    settlement.write(model, node_id);
    Ok(())
}

pub(super) fn per_host(weight: Decimal, count: u64) -> Result<Integer, Error> {
    if count == 0 {
        return Ok(Integer::default());
    }
    Ok(weight
        .to_raw_units()
        .checked_mul_add_div_rem(WEIGHT_SCALE, Integer::default(), count.into())?
        .0)
}

pub(super) fn membership_changed(
    model: &ProtocolStateWriteModel<context::ProcStorage>,
    agreement_id: &str,
    added: Option<u64>,
    removed: Option<u64>,
) -> Result<(), Error> {
    let id = agreement_id.to_string();
    let old = model.reward_weights().get(&id).unwrap_or_default();
    if let Some(node_id) = removed {
        change_weight(model, node_id, old, Integer::default())?;
    }
    let agreement = model
        .agreements()
        .get(&id)
        .expect("membership agreement exists");
    let count = model
        .memberships()
        .by_agreement_active(id.clone(), true)
        .len();
    let new = if agreement.active() {
        per_host(agreement.storage_weight(), count)?
    } else {
        Integer::default()
    };
    if old == new {
        if let Some(node_id) = added {
            change_weight(model, node_id, Integer::default(), new)?;
        }
    } else {
        // User membership changes pay for reweighting this file, never the global
        // population. Forced removals use the bounded prepare/apply/fold path below.
        for (_, node_id) in model
            .memberships()
            .by_agreement_active(id.clone(), true)
            .keys()
        {
            let previous = if Some(node_id) == added {
                Integer::default()
            } else {
                old
            };
            change_weight(model, node_id, previous, new)?;
        }
    }
    model.reward_weights().set(&id, new);
    Ok(())
}

pub(super) fn stop(
    model: &ProtocolStateWriteModel<context::ProcStorage>,
    node_id: u64,
) -> Result<(), Error> {
    let account = settle(model, node_id)?;
    model.set_reward_weight(sub(model.reward_weight(), account.share_weight)?);
    cleanup::exclude_prepared_increase(model, node_id)?;
    Ok(())
}

pub(super) fn accrue(ctx: &CoreContext) -> Result<Decimal, Error> {
    let proc = ctx.proc_context();
    let model = proc.model();
    let height = proc.block_height();
    if model
        .last_reward_height()
        .is_some_and(|last| last >= height)
    {
        return Err(Error::Message(
            "storage reward height already processed".into(),
        ));
    }
    let budget = token::storage_emission_budget()
        .ok_or(Error::Message("storage emission is not prepared".into()))?;
    let denominator = model
        .total_storage_weight()
        .to_raw_units()
        .mul(WEIGHT_SCALE)?;
    let step = budget
        .to_raw_units()
        .checked_mul_add_div_rem(INDEX_SCALE, Integer::default(), denominator)?
        .0;
    let previous = model.reward_remainder();
    let (whole, remainder) =
        step.checked_mul_add_div_rem(model.reward_weight(), previous, INDEX_SCALE)?;
    // Mint the change in ceil(total exact liability), retaining the common
    // fractional liability across participation changes. Pool overfunding stays
    // below one token atom; individual unclaimed fractions remain their owners'.
    let mut funded = whole;
    if remainder > Integer::default() {
        funded = funded.add(Integer::from(1))?;
    }
    if previous > Integer::default() {
        funded = sub(funded, Integer::from(1))?;
    }
    let amount = Decimal::from_raw_units(funded);
    token::allocate_storage_emission(ctx.core_signer(), proc.contract_signer().as_ref(), amount)?;
    model.set_reward_index(model.reward_index().add(step)?);
    model.set_reward_remainder(remainder);
    model.set_last_reward_height(Some(height));
    Ok(amount)
}
