use anyhow::{Result, anyhow};
use tokio_util::sync::CancellationToken;
use bitcoin::BlockHash;

use crate::{
    database::{
        self,
        queries,
        types::BlockRow,
    },
    retry::{new_backoff_unlimited, retry},
};

pub async fn select_block_at_height(
    reader: &database::Reader,
    height: u64,
    cancel_token: CancellationToken,
) -> Result<BlockRow> {

    retry(
        async || match queries::select_block_at_height(
            &*reader.connection().await?,
            height,
        )
        .await
        {
            Ok(Some(row)) => Ok(row),
            Ok(None) => Err(anyhow!(
                "Block at height not found: {}", height
            )),
            Err(e) => Err(e),
        },
        "read block at height",
        new_backoff_unlimited(),
        cancel_token.clone(),
    )
    .await
}

pub async fn select_block_with_hash(
    reader: &database::Reader,
    hash: &BlockHash,
    cancel_token: CancellationToken,
) -> Result<BlockRow> {

    retry(
        async || match queries::select_block_with_hash(
            &*reader.connection().await?,
            &hash,
        )
        .await
        {
            Ok(Some(row)) => Ok(row),
            Ok(None) => Err(anyhow!("Block with hash not found: {}", &hash)),
            Err(e) => Err(e),
        },
        "get block with hash",
        new_backoff_unlimited(),
        cancel_token.clone(),
    )
    .await
}
