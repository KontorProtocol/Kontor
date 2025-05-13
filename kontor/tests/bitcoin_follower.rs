use anyhow::Result;
use tokio_util::sync::CancellationToken;

use bitcoin::{Network};

use kontor::{
    bitcoin_follower::rpc::run_producer,
    bitcoin_client::{ client, types, error },
};

#[derive(Clone)]
struct MockClient {
    height: u64,
}

impl client::BitcoinRpc for MockClient {
    async fn get_blockchain_info(&self) -> Result<types::GetBlockchainInfoResult, error::Error> {
        Ok(types::GetBlockchainInfoResult{
            chain: Network::Bitcoin,
            blocks: self.height,
            headers: self.height,
            difficulty: 1.0,
            median_time: 1,
            verification_progress: 1.0,
            initial_block_download: false,
            size_on_disk: 0,
            pruned: false,
            prune_height: None,
            automatic_pruning: None,
            prune_target_size: None,
        })
    }
}

#[tokio::test]
async fn test_producer() -> Result<()> {
    let cancel_token = CancellationToken::new();

    let client = MockClient{ height: 1000 };
    let (producer, mut rx) = run_producer(700, client, cancel_token.clone());

    let (target_height, height) = rx.recv().await.unwrap();
    assert_eq!(target_height, 1000);
    assert_eq!(height, 700);

    let (target_height, height) = rx.recv().await.unwrap();
    assert_eq!(target_height, 1000);
    assert_eq!(height, 701);

    assert!(!producer.is_finished());

    cancel_token.cancel();
    let _ = producer.await;

    Ok(())
}
