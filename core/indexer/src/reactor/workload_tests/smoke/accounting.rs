use anyhow::{Context, Result, ensure};
use indexer_types::{ContractAddress, OpStatus, ResultRow};
use libsql::params;
use serde_json::{Value, json};

use crate::database::queries::{
    get_contract_id_from_address, get_contract_signer_id, get_identity,
};
use crate::runtime::filestorage::{address as filestorage_address, api as filestorage};
use crate::runtime::numerics::{add_decimal, div_decimal, mul_decimal, sub_decimal};
use crate::runtime::staking::{address as staking_address, api as staking};
use crate::runtime::token::{address as token_address, api as token};
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, Runtime};

pub(super) struct Balances {
    payer: Decimal,
    burner: Decimal,
    core: Decimal,
    ordering_pool: Decimal,
    storage_pool: Decimal,
    supply: Decimal,
    staking_escrow: Decimal,
    storage_escrow: Decimal,
    active_stake: Decimal,
}

pub(super) async fn balance(runtime: &mut Runtime, holder: HolderRef) -> Result<Decimal> {
    Ok(token::balance(runtime, holder).await?.unwrap_or_default())
}

pub(super) async fn escrow(runtime: &mut Runtime, address: &ContractAddress) -> Result<Decimal> {
    let conn = runtime.get_storage_conn();
    let id = get_contract_id_from_address(&conn, address)
        .await?
        .context("missing contract")?;
    let signer = get_contract_signer_id(&conn, id)
        .await?
        .context("missing contract signer")?;
    balance(runtime, HolderRef::SignerId(signer)).await
}

impl Balances {
    pub(super) async fn capture(runtime: &mut Runtime, payer: &str) -> Result<Self> {
        let validators = staking::get_active_set(runtime).await?;
        let payer_id = get_identity(&runtime.get_storage_conn(), payer)
            .await?
            .context("missing funded payer identity")?
            .signer_id();
        // The API field is named x_only_pubkey, but contains the normalized Holder key.
        let holder = HolderRef::SignerId(payer_id).to_string();
        ensure!(
            validators.len() == 1 && validators[0].x_only_pubkey == holder,
            "smoke requires its single funded validator"
        );
        Ok(Self {
            payer: balance(runtime, HolderRef::XOnlyPubkey(payer.into())).await?,
            burner: balance(runtime, HolderRef::Burner).await?,
            core: balance(runtime, HolderRef::Core).await?,
            ordering_pool: balance(runtime, HolderRef::OrderingPool).await?,
            storage_pool: balance(runtime, HolderRef::StoragePool).await?,
            supply: token::total_supply(runtime).await?,
            staking_escrow: escrow(runtime, &staking_address()).await?,
            storage_escrow: escrow(runtime, &filestorage_address()).await?,
            active_stake: validators[0].stake,
        })
    }
}

pub(super) fn lifecycle_value<'a>(
    rows: &'a [ResultRow],
    address: &ContractAddress,
    name: &str,
) -> Result<&'a str> {
    let matching: Vec<_> = rows
        .iter()
        .filter(|row| row.txid.is_none() && row.contract == address.to_string() && row.func == name)
        .collect();
    ensure!(
        matching.len() == 1 && matching[0].status == OpStatus::Ok,
        "missing, duplicate or failed lifecycle receipt: {name}"
    );
    matching[0]
        .value
        .as_deref()
        .context("missing lifecycle return value")
}

pub(super) async fn check(
    runtime: &mut Runtime,
    before: &Balances,
    payer: &str,
    txid: &str,
    rows: &[ResultRow],
) -> Result<Value> {
    let after = Balances::capture(runtime, payer).await?;
    let paid: Vec<_> = rows
        .iter()
        .filter(|row| row.txid.as_deref() == Some(txid))
        .collect();
    ensure!(
        paid.len() == 3
            && rows
                .iter()
                .all(|row| row.txid.is_none() || row.txid.as_deref() == Some(txid))
    );
    let gas = paid.iter().try_fold(0u64, |sum, row| {
        sum.checked_add(row.gas).context("gas overflow")
    })?;
    let conn = runtime.get_storage_conn();
    let mut usage = conn
        .query(
            "SELECT u.user_fuel, u.deposit_fuel FROM transaction_execution_usage u
         JOIN transactions t ON u.tx_id = t.id WHERE t.txid = ?",
            params![txid],
        )
        .await?;
    let usage = usage
        .next()
        .await?
        .context("missing persisted transaction usage")?;
    let user_fuel: u64 = usage.get(0)?;
    let deposit_fuel: u64 = usage.get(1)?;
    ensure!(runtime.gas_to_fuel_multiplier == 1000 && deposit_fuel.is_multiple_of(1000));
    let rounded = user_fuel
        .checked_add(deposit_fuel)
        .context("fuel overflow")?
        .div_ceil(1000);
    ensure!(
        gas >= rounded && gas <= rounded + 2,
        "per-operation gas does not reconcile with aggregate fuel"
    );
    let execution_gas = gas
        .checked_sub(deposit_fuel / 1000)
        .context("deposit exceeds gas")?;
    let fee = mul_decimal(
        Decimal::try_from(execution_gas)?,
        Decimal::from("0.000000001"),
    )?;
    ensure!(
        runtime.pricing.execution_fee(execution_gas)? == fee,
        "execution price differs from pinned source policy"
    );
    ensure!(
        sub_decimal(before.payer, after.payer)? == fee,
        "payer debit differs from fee"
    );
    ensure!(
        sub_decimal(after.burner, before.burner)? == fee,
        "burner credit differs from fee"
    );

    // native-contracts/token/src/lib.rs::mint_emission fixes this operation
    // order (5 / 100 / 52,560, then / 10), including each Decimal rounding.
    // The emission starts after transaction fees have reduced total supply.
    let supply_before_emission = sub_decimal(before.supply, fee)?;
    let scheduled = div_decimal(
        div_decimal(
            mul_decimal(supply_before_emission, Decimal::from("5"))?,
            Decimal::from("100"),
        )?,
        Decimal::from("52560"),
    )?;
    let ordering = div_decimal(scheduled, Decimal::from("10"))?;
    let emission = token::wave::mint_emission_parse_return_expr(lifecycle_value(
        rows,
        &token_address(),
        "mint-emission",
    )?)?;
    ensure!(
        emission.scheduled_total == scheduled
            && emission.ordering_minted == ordering
            && emission.storage_unminted == sub_decimal(scheduled, ordering)?,
        "emission formula differs"
    );
    let distributed = staking::wave::distribute_ordering_reward_parse_return_expr(
        lifecycle_value(rows, &staking_address(), "distribute-ordering-reward")?,
    )?;
    let storage = filestorage::wave::accrue_storage_rewards_parse_return_expr(lifecycle_value(
        rows,
        &filestorage_address(),
        "accrue-storage-rewards",
    )?)?;
    ensure!(
        distributed == ordering,
        "ordering reward not fully distributed"
    );
    ensure!(
        storage == Decimal::default(),
        "empty storage fixture unexpectedly minted rewards"
    );
    ensure!(
        after.supply == add_decimal(supply_before_emission, add_decimal(ordering, storage)?)?,
        "supply does not reconcile"
    );
    ensure!(
        after.core == before.core && after.core == Decimal::default(),
        "Core escrow remains funded"
    );
    ensure!(
        after.ordering_pool == before.ordering_pool && after.storage_pool == before.storage_pool,
        "reward pool balance differs"
    );
    ensure!(
        after.staking_escrow == add_decimal(before.staking_escrow, ordering)?
            && after.active_stake == add_decimal(before.active_stake, ordering)?,
        "staking credit differs"
    );
    ensure!(
        after.storage_escrow == add_decimal(before.storage_escrow, storage)?,
        "storage escrow differs"
    );
    Ok(json!({
        "execution_fee":fee.to_string(),"scheduled_emission":scheduled.to_string(),
        "ordering_minted":ordering.to_string(),"storage_minted":storage.to_string(),
        "supply_before":before.supply.to_string(),"supply_after":after.supply.to_string(),
        "user_fuel":user_fuel,"deposit_fuel":deposit_fuel,"paid_gas":gas,
    }))
}
