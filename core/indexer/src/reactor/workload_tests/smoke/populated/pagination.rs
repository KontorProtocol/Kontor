use anyhow::{Result, ensure};
use indexer_types::ContractAddress;
use stdlib::Wavey;

use super::super::{ANCHOR_HEIGHT, test_provenance};
use crate::runtime::wit::Signer;
use crate::runtime::{Runtime, TransactionContext, from_wave_expr, to_wave_expr};

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

pub(super) async fn prepare(runtime: &mut Runtime, entries: usize) -> Result<ContractAddress> {
    ensure!(
        (1..=100_000_000).contains(&entries),
        "fixture keys must retain eight-digit lexical order"
    );
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
    for start in (0..entries).step_by(PAGE_SIZE) {
        let count = PAGE_SIZE.min(entries - start);
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

fn page(round: usize, count: usize) -> (usize, bool) {
    let pages = count.div_ceil(PAGE_SIZE);
    let position = round % (2 * pages);
    (position % pages, position >= pages)
}

pub(super) fn call(round: usize, count: usize) -> String {
    let (page, descending) = page(round, count);
    let cursor = (page > 0).then(|| {
        key(if descending {
            count - page * PAGE_SIZE
        } else {
            page * PAGE_SIZE - 1
        })
    });
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

pub(super) fn check(round: usize, count: usize, value: &str) -> Result<()> {
    let (page, descending) = page(round, count);
    let offset = page * PAGE_SIZE;
    let expected = if descending {
        let end = count - offset;
        entries((end.saturating_sub(PAGE_SIZE)..end).rev())
    } else {
        entries(offset..count.min(offset + PAGE_SIZE))
    };
    ensure!(from_wave_expr::<Vec<Entry>>(value) == expected);
    Ok(())
}

pub(super) async fn check_boundaries(
    runtime: &mut Runtime,
    contract: &ContractAddress,
    count: usize,
) -> Result<()> {
    for (cursor, limit, descending, expected) in [
        (Some(key(1)), PAGE_SIZE, true, entries(0..1)),
        (Some(key(0)), PAGE_SIZE, true, Vec::new()),
        (Some(key(count - 1)), PAGE_SIZE, false, Vec::new()),
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
