use anyhow::{Error, Result};
use bitcoin::{self, BlockHash};
use tokio_util::sync::CancellationToken;

use crate::{
    bitcoin_client::client::BitcoinRpc,
    retry::{new_backoff_unlimited, retry},
};

pub trait BlockchainInfo {
    fn get_blockchain_height(&self) -> impl Future<Output = Result<u64, Error>> + Send;

    fn get_block_hash(&self, height: u64) -> impl Future<Output = Result<BlockHash, Error>> + Send;
}

pub struct Info<C: BitcoinRpc> {
    cancel_token: CancellationToken,
    bitcoin: C,
}

impl<C: BitcoinRpc> Info<C> {
    pub fn new(cancel_token: CancellationToken, bitcoin: C) -> Self {
        Self {
            cancel_token,
            bitcoin,
        }
    }
}

impl<C: BitcoinRpc> BlockchainInfo for Info<C> {
    async fn get_blockchain_height(&self) -> Result<u64, Error> {
        let info = retry(
            || self.bitcoin.get_blockchain_info(),
            "get blockchain info",
            new_backoff_unlimited(),
            self.cancel_token.clone(),
        )
        .await?;
        Ok(info.blocks)
    }

    async fn get_block_hash(&self, height: u64) -> Result<BlockHash, Error> {
        retry(
            || self.bitcoin.get_block_hash(height),
            "get block hash",
            new_backoff_unlimited(),
            self.cancel_token.clone(),
        )
        .await
    }
}
