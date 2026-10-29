use anyhow::{Result, ensure};
use indexer_types::ContractAddress;
use stdlib::Wavey;

use super::super::{ANCHOR_HEIGHT, test_provenance};
use crate::runtime::wit::Signer;
use crate::runtime::{Runtime, TransactionContext, from_wave_expr, to_wave_expr};

const ENTRIES: usize = 257;
const PAGE_SIZE: usize = 128;

#[derive(PartialEq, Wavey)]
struct Entry {
    key: String,
    value: String,
}

fn key(index: usize) -> String {
    format!("entry-{index:08}")
}

fn expression(cursor: Option<String>, limit: usize, descending: bool) -> String {
    format!(
        "entries-page({}, {limit}, {descending})",
        to_wave_expr(cursor)
    )
}

pub(super) async fn prepare(runtime: &mut Runtime) -> Result<ContractAddress> {
    let core = Signer::Core(Box::new(Signer::Nobody));
    let contract = ContractAddress {
        name: "mixedpages".into(),
        height: ANCHOR_HEIGHT,
        tx_index: 7,
    };
    runtime
        .set_context(
            ANCHOR_HEIGHT,
            Some(TransactionContext::builder().tx_index(7).build()),
            None,
            None,
        )
        .await;
    runtime
        .publish(
            &core,
            runtime.core_payment(),
            &contract.name,
            include_bytes!("../../../../../../../test-contracts/binaries/workload_storage.wasm.br"),
            &test_provenance()?,
        )
        .await?;
    for start in (0..ENTRIES).step_by(PAGE_SIZE) {
        let count = PAGE_SIZE.min(ENTRIES - start);
        runtime
            .execute(
                Some(&core),
                Some(runtime.core_payment()),
                &contract,
                &format!("seed-entries({start}, {count})"),
            )
            .await?;
    }
    Ok(contract)
}

pub(super) fn call(round: usize) -> String {
    let (cursor, descending) = match round {
        0 => (None, false),
        1 => (Some(key(127)), false),
        2 => (Some(key(255)), false),
        3 => (None, true),
        4 => (Some(key(129)), true),
        _ => unreachable!("pagination workload has five rounds"),
    };
    expression(cursor, PAGE_SIZE, descending)
}

fn entries(indices: impl Iterator<Item = usize>) -> Vec<Entry> {
    indices
        .map(|index| Entry {
            key: key(index),
            value: format!("value-{index:08}"),
        })
        .collect()
}

pub(super) fn check(round: usize, value: &str) -> Result<()> {
    let expected = match round {
        0 => entries(0..128),
        1 => entries(128..256),
        2 => entries(256..257),
        3 => entries((129..257).rev()),
        4 => entries((1..129).rev()),
        _ => unreachable!("pagination workload has five rounds"),
    };
    ensure!(from_wave_expr::<Vec<Entry>>(value) == expected);
    Ok(())
}

pub(super) async fn check_boundaries(
    runtime: &mut Runtime,
    contract: &ContractAddress,
) -> Result<()> {
    for (cursor, limit, descending, expected) in [
        (Some(key(1)), PAGE_SIZE, true, entries(0..1)),
        (Some(key(0)), PAGE_SIZE, true, Vec::new()),
        (Some(key(256)), PAGE_SIZE, false, Vec::new()),
        (None, 0, false, Vec::new()),
        (None, 0, true, Vec::new()),
    ] {
        let value = runtime
            .execute_system_view(contract, &expression(cursor, limit, descending))
            .await?;
        ensure!(from_wave_expr::<Vec<Entry>>(&value) == expected);
    }
    Ok(())
}
