use anyhow::{Result, ensure};
use indexer_types::ContractAddress;

use crate::runtime::wit::Signer;
use crate::runtime::{Runtime, from_wave_expr, to_wave_expr};

const ENTRIES: usize = 257;
const PAGE_SIZE: usize = 128;

fn key(index: usize) -> String {
    format!("entry-{index:08}")
}

fn expression(cursor: Option<String>, limit: usize, descending: bool) -> String {
    format!(
        "entries-page({}, {limit}, {descending})",
        to_wave_expr(cursor)
    )
}

pub(super) async fn seed(runtime: &mut Runtime, contract: &ContractAddress) -> Result<()> {
    let core = Signer::Core(Box::new(Signer::Nobody));
    for start in (0..ENTRIES).step_by(PAGE_SIZE) {
        let count = PAGE_SIZE.min(ENTRIES - start);
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

fn entries(indices: impl Iterator<Item = usize>) -> Vec<(String, String)> {
    indices
        .map(|index| (key(index), format!("value-{index:08}")))
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
    ensure!(from_wave_expr::<Vec<(String, String)>>(value) == expected);
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
        ensure!(from_wave_expr::<Vec<(String, String)>>(&value) == expected);
    }
    Ok(())
}
