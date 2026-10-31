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
    let contract = publish(runtime, ANCHOR_HEIGHT).await?;
    seed(runtime, &contract, entries).await?;
    Ok(contract)
}

pub(super) async fn publish(runtime: &mut Runtime, height: u64) -> Result<ContractAddress> {
    let core = Signer::Core(Box::new(Signer::Nobody));
    let contract = ContractAddress {
        name: "mixedpages".into(),
        height,
        tx_index: 7,
    };
    runtime
        .set_context(
            height,
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
    Ok(contract)
}

pub(super) async fn seed(
    runtime: &mut Runtime,
    contract: &ContractAddress,
    entries: usize,
) -> Result<()> {
    let core = Signer::Core(Box::new(Signer::Nobody));
    for start in (0..entries).step_by(PAGE_SIZE) {
        let count = PAGE_SIZE.min(entries - start);
        runtime
            .execute(
                Some(&core),
                Some(runtime.core_payment()),
                contract,
                &format!("seed-entries({start}, {count})"),
            )
            .await?;
    }
    Ok(())
}

fn page(round: usize, count: usize, rounds: usize) -> (usize, bool) {
    let pages = count.div_ceil(PAGE_SIZE);
    if pages * 2 > rounds + 1 {
        let descending = round % 2 == 1;
        let samples = if descending {
            rounds / 2
        } else {
            rounds.div_ceil(2)
        };
        return ((round / 2) * (pages - 1) / (samples - 1), descending);
    }
    let position = round % (2 * pages);
    (position % pages, position >= pages)
}

pub(super) fn call(round: usize, count: usize, rounds: usize) -> String {
    let (page, descending) = page(round, count, rounds);
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

fn expected_entries(round: usize, count: usize, rounds: usize) -> Vec<Entry> {
    let (page, descending) = page(round, count, rounds);
    let offset = page * PAGE_SIZE;
    if descending {
        let end = count - offset;
        entries((end.saturating_sub(PAGE_SIZE)..end).rev())
    } else {
        entries(offset..count.min(offset + PAGE_SIZE))
    }
}

#[cfg(target_os = "linux")]
pub(super) fn expected_wave(round: usize, count: usize, rounds: usize) -> String {
    to_wave_expr(expected_entries(round, count, rounds))
}

pub(super) fn check(round: usize, count: usize, rounds: usize, value: &str) -> Result<()> {
    ensure!(from_wave_expr::<Vec<Entry>>(value) == expected_entries(round, count, rounds));
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

#[test]
fn workload_pagination_samples_both_ends_and_directions() {
    assert_eq!(
        (0..5).map(|round| page(round, 257, 5)).collect::<Vec<_>>(),
        [(0, false), (1, false), (2, false), (0, true), (1, true)]
    );
    assert_eq!(
        (0..5)
            .map(|round| page(round, 10_000, 5))
            .collect::<Vec<_>>(),
        [(0, false), (0, true), (39, false), (78, true), (78, false)]
    );
    assert_eq!(page(48, 100_000, 50), (781, false));
    assert_eq!(page(49, 100_000, 50), (781, true));
    assert_eq!(
        call(4, 10_000, 5),
        "entries-page(some(\"entry-00009983\"), 128, false)"
    );
    assert_eq!(
        call(3, 10_000, 5),
        "entries-page(some(\"entry-00000016\"), 128, true)"
    );
}
