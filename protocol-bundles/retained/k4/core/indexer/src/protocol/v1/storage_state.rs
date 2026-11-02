use futures_util::{Stream, stream};
use stdlib::subtree_end;

use super::storage_error::ReadError;
use crate::protocol::storage_state::{StateCallbacks, WritePosition, WriteState};

#[derive(Debug, Clone)]
pub struct LiveRow {
    pub path: Vec<u8>,
    pub size: u64,
    pub depositor: Option<u64>,
    pub deposited_gas: Option<u64>,
}

pub(crate) async fn write_value(
    write: WriteState,
    position: WritePosition,
    path: &[u8],
    value: &[u8],
    deposit: (Option<u64>, Option<u64>),
) -> Result<(), ReadError> {
    write((
        position,
        value.len() as u64,
        path.to_vec(),
        value.to_vec(),
        false,
        deposit.0,
        deposit.1,
    ))
    .await
    .map_err(ReadError::Infrastructure)?;
    Ok(())
}

pub(crate) fn live_subtree(
    callbacks: StateCallbacks,
    contract_id: u64,
    path: &[u8],
) -> impl Stream<Item = Result<LiveRow, ReadError>> + Send + 'static {
    let owner = callbacks.1(contract_id, path.to_vec(), subtree_end(path));
    stream::try_unfold(owner, move |owner| {
        let advance = callbacks.2.clone();
        async move {
            Ok(advance(owner)
                .await
                .map_err(ReadError::Infrastructure)?
                .map(|(owner, (path, size, depositor, deposited_gas))| {
                    (
                        LiveRow {
                            path,
                            size,
                            depositor,
                            deposited_gas,
                        },
                        owner,
                    )
                }))
        }
    })
}

pub(crate) async fn tombstone_rows(
    write: WriteState,
    position: WritePosition,
    rows: &[LiveRow],
) -> Result<(bool, u64), ReadError> {
    let removed = !rows.is_empty();
    let freed = rows
        .iter()
        .map(|row| row.path.len() as u64 + row.size)
        .sum();
    for row in rows {
        write((position, 0, row.path.clone(), Vec::new(), true, None, None))
            .await
            .map_err(ReadError::Infrastructure)?;
    }
    Ok((removed, freed))
}

pub(crate) async fn exists(
    callbacks: StateCallbacks,
    contract_id: u64,
    path: &[u8],
) -> Result<bool, ReadError> {
    callbacks.3(contract_id, path.to_vec(), subtree_end(path))
        .await
        .map_err(ReadError::Infrastructure)
}
