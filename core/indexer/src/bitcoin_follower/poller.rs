use std::{
    sync::Arc,
    collections::{HashMap, VecDeque},
    thread,
    time::Duration,
};

use anyhow::{Result, bail};
use bitcoin::BlockHash;
use indexer_types::Block;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use tokio::{select, sync::{mpsc::Sender, Notify}, task::JoinSet, time::sleep};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::{
    bitcoin_client::client::BitcoinRpc,
    block::TransactionFilterMap,
    retry::{new_backoff_unlimited, retry},
};

use super::event::BitcoinEvent;

const HASH_CACHE_SIZE: usize = 50;

fn max_concurrent_fetches() -> usize {
    thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(4)
}

pub struct PollerConfig {
    pub poll_interval: Duration,
}

impl Default for PollerConfig {
    fn default() -> Self {
        Self {
            poll_interval: Duration::from_secs(2),
        }
    }
}

// -- Block hash cache for reorg detection --

struct BlockHashCache {
    hashes: HashMap<u64, BlockHash>,
    heights: VecDeque<u64>,
    capacity: usize,
}

impl BlockHashCache {
    fn new(capacity: usize) -> Self {
        Self {
            hashes: HashMap::new(),
            heights: VecDeque::new(),
            capacity,
        }
    }

    fn insert(&mut self, height: u64, hash: BlockHash) {
        if self.hashes.contains_key(&height) {
            return;
        }
        if self.heights.len() >= self.capacity
            && let Some(oldest) = self.heights.pop_front()
        {
            self.hashes.remove(&oldest);
        }
        self.hashes.insert(height, hash);
        self.heights.push_back(height);
    }

    fn get(&self, height: u64) -> Option<&BlockHash> {
        self.hashes.get(&height)
    }

    fn truncate_above(&mut self, height: u64) {
        while let Some(&back) = self.heights.back() {
            if back > height {
                self.heights.pop_back();
                self.hashes.remove(&back);
            } else {
                break;
            }
        }
    }
}

// -- Fetch + process a single block --

async fn fetch_and_process<C: BitcoinRpc>(
    bitcoin: C,
    height: u64,
    f: TransactionFilterMap,
    cancel_token: CancellationToken,
) -> Result<Block> {
    let block_hash = retry(
        || bitcoin.get_block_hash(height),
        "get block hash",
        new_backoff_unlimited(),
        cancel_token.clone(),
    )
    .await?;

    let block = retry(
        || bitcoin.get_block(&block_hash),
        "get block",
        new_backoff_unlimited(),
        cancel_token.clone(),
    )
    .await?;

    let prev_hash = block.header.prev_blockhash;
    let transactions = tokio::task::spawn_blocking(move || {
        block
            .txdata
            .into_par_iter()
            .enumerate()
            .filter_map(f)
            .collect()
    })
    .await?;

    Ok(Block {
        height,
        hash: block_hash,
        prev_hash,
        transactions,
    })
}

// -- Delivery: validate block ordering and detect reorgs --

enum DeliveryResult {
    /// All blocks in the batch were delivered successfully.
    Ok {
        /// Events to send to the consumer.
        events: Vec<BitcoinEvent>,
        /// The next height to fetch.
        next_height: u64,
    },
    /// A reorg was detected at the given height. The caller should
    /// use `find_fork_point` to locate the common ancestor.
    Reorg {
        /// The height at which the prev_hash mismatch was found.
        mismatch_height: u64,
    },
}

fn deliver_blocks(
    pending: &mut HashMap<u64, Block>,
    cache: &mut BlockHashCache,
    next_height: u64,
    batch_end: u64,
    tip: u64,
) -> DeliveryResult {
    let mut events = Vec::new();

    for height in next_height..batch_end {
        let Some(block) = pending.remove(&height) else {
            break;
        };

        if let Some(&expected_prev) = cache.get(height - 1)
            && block.prev_hash != expected_prev
        {
            warn!(
                "Reorg detected at height {}: prev_hash {} != cached {}",
                height, block.prev_hash, expected_prev
            );
            return DeliveryResult::Reorg {
                mismatch_height: height,
            };
        }

        cache.insert(height, block.hash);
        events.push(BitcoinEvent::BlockInsert {
            target_height: tip,
            block,
        });
    }

    DeliveryResult::Ok {
        next_height: next_height + events.len() as u64,
        events,
    }
}

/// Apply a rollback: truncate the cache, update next_height, and send
/// the Rollback event. Returns `true` if the channel is still open.
async fn apply_rollback(
    cache: &mut BlockHashCache,
    next_height: &mut u64,
    fork_height: u64,
    event_tx: &Sender<BitcoinEvent>,
) -> bool {
    cache.truncate_above(fork_height);
    *next_height = fork_height + 1;
    event_tx
        .send(BitcoinEvent::Rollback {
            to_height: fork_height,
        })
        .await
        .is_ok()
}

/// Wait for the next poll trigger: timer, ZMQ wake, or cancellation.
async fn wait_for_poll(
    poll_interval: Duration,
    poll_notify: &Notify,
    cancel_token: &CancellationToken,
) -> bool {
    select! {
        _ = sleep(poll_interval) => true,
        _ = poll_notify.notified() => true,
        _ = cancel_token.cancelled() => false,
    }
}

// -- Main poller loop --

pub async fn run<C: BitcoinRpc>(
    bitcoin: C,
    f: TransactionFilterMap,
    event_tx: Sender<BitcoinEvent>,
    cancel_token: CancellationToken,
    start_height: u64,
    known_hashes: Vec<(u64, BlockHash)>,
    poll_notify: Arc<Notify>,
    config: PollerConfig,
) -> Result<()> {
    let mut cache = BlockHashCache::new(HASH_CACHE_SIZE);
    let mut next_height = start_height;
    let concurrency = max_concurrent_fetches();

    // Seed cache with consumer's known block hashes. This represents
    // the consumer's view of the chain — used to detect reorgs that
    // happened while offline by comparing against the node.
    for (height, hash) in &known_hashes {
        cache.insert(*height, *hash);
    }

    // Detect offline reorg: compare the consumer's most recent hash
    // against the node. If they differ, walk back through the
    // consumer-seeded cache to find the fork point.
    if start_height > 0 && cache.get(start_height - 1).is_some() {
        let fork_height = find_fork_point(&bitcoin, &cache, start_height - 1, &cancel_token).await;

        match fork_height {
            Ok(fork_height) if fork_height < start_height - 1 => {
                warn!("Offline reorg detected: fork at height {fork_height}, rolling back");
                if !apply_rollback(&mut cache, &mut next_height, fork_height, &event_tx).await {
                    info!("Event channel closed, exiting");
                    return Ok(());
                }
            }
            Err(e) => return Err(e),
            _ => {} // No reorg — hashes match at tip
        }
    }

    loop {
        if cancel_token.is_cancelled() {
            info!("Poller cancelled");
            return Ok(());
        }

        // 1. Discover tip
        let tip = match retry(
            || bitcoin.get_blockchain_info(),
            "get blockchain info",
            new_backoff_unlimited(),
            cancel_token.clone(),
        )
        .await
        {
            Ok(info) => info.blocks,
            Err(_) if cancel_token.is_cancelled() => return Ok(()),
            Err(e) => return Err(e),
        };

        if tip < next_height - 1 {
            warn!(
                "Chain tip ({tip}) behind last delivered height ({}), possible reorg",
                next_height - 1
            );
            // Chain shrunk — find how deep the reorg actually goes
            cache.truncate_above(tip);
            let fork_height = find_fork_point(&bitcoin, &cache, tip, &cancel_token).await?;

            if !apply_rollback(&mut cache, &mut next_height, fork_height, &event_tx).await {
                info!("Event channel closed, exiting");
                return Ok(());
            }

            continue;
        }

        if tip < next_height
            && !wait_for_poll(config.poll_interval, &poll_notify, &cancel_token).await
        {
            return Ok(());
        }

        // 2. Spawn parallel fetches for blocks we're behind on
        let batch_end = std::cmp::min(next_height + concurrency as u64, tip + 1);
        let mut join_set = JoinSet::new();

        for height in next_height..batch_end {
            let bitcoin = bitcoin.clone();
            let cancel_token = cancel_token.clone();
            join_set.spawn(async move {
                let block = fetch_and_process(bitcoin, height, f, cancel_token).await;
                (height, block)
            });
        }

        // 3. Collect results into a buffer
        let mut pending: HashMap<u64, Block> = HashMap::new();
        while let Some(result) = join_set.join_next().await {
            match result {
                Ok((height, Ok(block))) => {
                    pending.insert(height, block);
                }
                Ok((height, Err(e))) => {
                    if cancel_token.is_cancelled() {
                        return Ok(());
                    }
                    error!("Failed to fetch block at height {}: {}", height, e);
                    return Err(e);
                }
                Err(e) => {
                    error!("Fetch task panicked: {}", e);
                    return Err(e.into());
                }
            }
        }

        // 4. Deliver in order, checking for reorgs
        match deliver_blocks(&mut pending, &mut cache, next_height, batch_end, tip) {
            DeliveryResult::Ok {
                events,
                next_height: new_next,
            } => {
                next_height = new_next;

                for event in events {
                    if event_tx.send(event).await.is_err() {
                        info!("Event channel closed, exiting");
                        return Ok(());
                    }
                }

            }
            DeliveryResult::Reorg { mismatch_height } => {
                let fork_height =
                    find_fork_point(&bitcoin, &cache, mismatch_height - 1, &cancel_token).await?;

                if !apply_rollback(&mut cache, &mut next_height, fork_height, &event_tx).await {
                    info!("Event channel closed, exiting");
                    return Ok(());
                }
            }
        }
    }
}

/// Walk back through the cache comparing against the Bitcoin node's
/// block hashes to find where the chains diverged.
async fn find_fork_point<C: BitcoinRpc>(
    bitcoin: &C,
    cache: &BlockHashCache,
    from_height: u64,
    cancel_token: &CancellationToken,
) -> Result<u64> {
    let mut height = from_height;
    loop {
        let Some(&cached_hash) = cache.get(height) else {
            bail!("reorg deeper than cached history (exhausted at height {height})");
        };

        let chain_hash = retry(
            || bitcoin.get_block_hash(height),
            "get block hash for reorg",
            new_backoff_unlimited(),
            cancel_token.clone(),
        )
        .await?;

        if chain_hash == cached_hash {
            return Ok(height);
        }

        if height == 0 {
            bail!("reorg deeper than cached history (reached genesis)");
        }
        height -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::bitcoin_client::mock::MockBitcoinRpc;
    use crate::test_utils::new_numbered_blockchain;
    use bitcoin::hashes::Hash;

    fn hash(n: u8) -> BlockHash {
        BlockHash::from_byte_array([n; 32])
    }

    // -- BlockHashCache tests --

    #[test]
    fn cache_insert_and_get() {
        let mut cache = BlockHashCache::new(5);
        let h = hash(1);
        cache.insert(10, h);
        assert_eq!(cache.get(10), Some(&h));
        assert_eq!(cache.get(11), None);
    }

    #[test]
    fn cache_evicts_oldest_when_full() {
        let mut cache = BlockHashCache::new(3);
        cache.insert(1, hash(1));
        cache.insert(2, hash(2));
        cache.insert(3, hash(3));
        cache.insert(4, hash(4));

        assert_eq!(cache.get(1), None);
        assert_eq!(cache.get(2), Some(&hash(2)));
        assert_eq!(cache.get(4), Some(&hash(4)));
    }

    #[test]
    fn cache_insert_duplicate_is_noop() {
        let mut cache = BlockHashCache::new(3);
        cache.insert(1, hash(1));
        cache.insert(2, hash(2));
        cache.insert(1, hash(99));
        assert_eq!(cache.get(1), Some(&hash(1)));
    }

    #[test]
    fn cache_truncate_above() {
        let mut cache = BlockHashCache::new(10);
        for i in 1..=5 {
            cache.insert(i, hash(i as u8));
        }
        cache.truncate_above(3);

        assert_eq!(cache.get(1), Some(&hash(1)));
        assert_eq!(cache.get(2), Some(&hash(2)));
        assert_eq!(cache.get(3), Some(&hash(3)));
        assert_eq!(cache.get(4), None);
        assert_eq!(cache.get(5), None);
        assert_eq!(cache.heights.len(), 3);
    }

    #[test]
    fn cache_truncate_above_allows_reinsertion() {
        let mut cache = BlockHashCache::new(10);
        for i in 1..=5 {
            cache.insert(i, hash(i as u8));
        }
        cache.truncate_above(3);
        cache.insert(4, hash(44));
        assert_eq!(cache.get(4), Some(&hash(44)));
    }

    // -- find_fork_point tests --

    #[tokio::test]
    async fn fork_point_all_match() {
        let blocks = new_numbered_blockchain(5);
        let rpc = MockBitcoinRpc::new(blocks.clone());

        let mut cache = BlockHashCache::new(10);
        for b in &blocks {
            cache.insert(b.height, b.hash);
        }

        let cancel = CancellationToken::new();
        let fp = find_fork_point(&rpc, &cache, 5, &cancel).await.unwrap();
        assert_eq!(fp, 5);
    }

    #[tokio::test]
    async fn fork_point_diverges_at_tip() {
        // Original chain: blocks 1..=5
        // Reorged chain: blocks 1..=4 same, block 5 different
        let mut blocks = new_numbered_blockchain(5);
        let mut cache = BlockHashCache::new(10);
        for b in &blocks {
            cache.insert(b.height, b.hash);
        }

        // Replace block 5 with one that has a different hash
        let alt_block_5 = indexer_types::Block {
            height: 5,
            hash: BlockHash::from_byte_array([0xAA; 32]),
            prev_hash: blocks[3].hash,
            transactions: vec![],
        };
        blocks[4] = alt_block_5;
        let rpc = MockBitcoinRpc::new(blocks);

        let cancel = CancellationToken::new();
        let fp = find_fork_point(&rpc, &cache, 5, &cancel).await.unwrap();
        assert_eq!(fp, 4);
    }

    #[tokio::test]
    async fn fork_point_deep_reorg() {
        // Original chain: blocks 1..=5
        // Reorged chain: blocks 1..=2 same, 3..=5 different
        let blocks = new_numbered_blockchain(5);
        let mut cache = BlockHashCache::new(10);
        for b in &blocks {
            cache.insert(b.height, b.hash);
        }

        // Build alternate chain forking after block 2
        let mut alt_blocks = blocks[..2].to_vec();
        for i in 3..=5 {
            alt_blocks.push(indexer_types::Block {
                height: i,
                hash: BlockHash::from_byte_array([0xA0 + i as u8; 32]),
                prev_hash: alt_blocks.last().unwrap().hash,
                transactions: vec![],
            });
        }
        let rpc = MockBitcoinRpc::new(alt_blocks);

        let cancel = CancellationToken::new();
        let fp = find_fork_point(&rpc, &cache, 5, &cancel).await.unwrap();
        assert_eq!(fp, 2);
    }

    #[tokio::test]
    async fn fork_point_beyond_cache_errors() {
        // Cache only has heights 4 and 5, chain diverges at both.
        // Should error since we can't verify further back.
        let blocks = new_numbered_blockchain(5);
        let mut cache = BlockHashCache::new(10);
        cache.insert(4, blocks[3].hash);
        cache.insert(5, blocks[4].hash);

        let mut alt_blocks = blocks[..3].to_vec();
        for i in 4..=5 {
            alt_blocks.push(indexer_types::Block {
                height: i,
                hash: BlockHash::from_byte_array([0xB0 + i as u8; 32]),
                prev_hash: alt_blocks.last().unwrap().hash,
                transactions: vec![],
            });
        }
        let rpc = MockBitcoinRpc::new(alt_blocks);

        let cancel = CancellationToken::new();
        let result = find_fork_point(&rpc, &cache, 5, &cancel).await;
        assert!(result.is_err());
    }

    // -- deliver_blocks tests --

    fn make_block(height: u64, prev: BlockHash) -> Block {
        Block {
            height,
            hash: BlockHash::from_byte_array([height as u8; 32]),
            prev_hash: prev,
            transactions: vec![],
        }
    }

    #[test]
    fn deliver_blocks_in_order() {
        let mut cache = BlockHashCache::new(10);
        let b1 = make_block(1, hash(0));
        cache.insert(0, hash(0));
        let b2 = Block {
            height: 2,
            hash: hash(2),
            prev_hash: b1.hash,
            transactions: vec![],
        };
        let mut pending: HashMap<u64, Block> = HashMap::new();
        pending.insert(1, b1.clone());
        pending.insert(2, b2.clone());

        match deliver_blocks(&mut pending, &mut cache, 1, 3, 10) {
            DeliveryResult::Ok {
                events,
                next_height,
            } => {
                assert_eq!(next_height, 3);
                assert_eq!(events.len(), 2);
                assert!(
                    matches!(&events[0], BitcoinEvent::BlockInsert { block, .. } if block.height == 1)
                );
                assert!(
                    matches!(&events[1], BitcoinEvent::BlockInsert { block, .. } if block.height == 2)
                );
            }
            DeliveryResult::Reorg { .. } => panic!("unexpected reorg"),
        }
    }

    #[test]
    fn deliver_blocks_detects_reorg() {
        let mut cache = BlockHashCache::new(10);
        cache.insert(0, hash(0));

        // Block 1 has a prev_hash that doesn't match what's in the cache
        let bad_block = Block {
            height: 1,
            hash: hash(99),
            prev_hash: hash(77), // doesn't match cache[0] = hash(0)
            transactions: vec![],
        };
        let mut pending = HashMap::new();
        pending.insert(1, bad_block);

        match deliver_blocks(&mut pending, &mut cache, 1, 2, 10) {
            DeliveryResult::Reorg { mismatch_height } => {
                assert_eq!(mismatch_height, 1);
            }
            DeliveryResult::Ok { .. } => panic!("expected reorg"),
        }
    }

    #[test]
    fn deliver_blocks_no_cache_entry_skips_check() {
        // No entry in cache for prev height — block is accepted
        let mut cache = BlockHashCache::new(10);
        let b1 = make_block(5, hash(99));
        let mut pending = HashMap::new();
        pending.insert(5, b1);

        match deliver_blocks(&mut pending, &mut cache, 5, 6, 10) {
            DeliveryResult::Ok {
                events,
                next_height,
            } => {
                assert_eq!(next_height, 6);
                assert_eq!(events.len(), 1);
            }
            DeliveryResult::Reorg { .. } => panic!("unexpected reorg"),
        }
    }

    #[test]
    fn deliver_blocks_reorg_mid_batch() {
        // Batch of 3 blocks, reorg at the second one
        let mut cache = BlockHashCache::new(10);
        cache.insert(0, hash(0));

        let b1 = make_block(1, hash(0));
        let b2 = Block {
            height: 2,
            hash: hash(20),
            prev_hash: hash(77), // doesn't match b1.hash
            transactions: vec![],
        };
        let b3 = make_block(3, hash(20));
        let mut pending = HashMap::new();
        pending.insert(1, b1);
        pending.insert(2, b2);
        pending.insert(3, b3);

        match deliver_blocks(&mut pending, &mut cache, 1, 4, 10) {
            DeliveryResult::Reorg { mismatch_height } => {
                assert_eq!(mismatch_height, 2);
                // Block 1 should have been inserted into cache before reorg
                assert!(cache.get(1).is_some());
            }
            DeliveryResult::Ok { .. } => panic!("expected reorg"),
        }
    }

    // -- run() integration tests --

    use crate::test_utils::gen_numbered_blocks;
    use tokio::sync::mpsc;
    use tokio::time::timeout;

    fn noop_filter(_: (usize, bitcoin::Transaction)) -> Option<indexer_types::Transaction> {
        None
    }

    fn fast_config() -> PollerConfig {
        PollerConfig {
            poll_interval: Duration::from_millis(10),
        }
    }

    const TEST_TIMEOUT: Duration = Duration::from_secs(5);

    #[tokio::test]
    async fn run_delivers_blocks_in_order() {
        let blocks = new_numbered_blockchain(5);
        let rpc = MockBitcoinRpc::new(blocks.clone());
        let cancel = CancellationToken::new();
        let (tx, mut rx) = mpsc::channel(16);

        let cancel2 = cancel.clone();
        let handle = tokio::spawn(async move {
            run(rpc, noop_filter, tx, cancel2, 1, vec![], Arc::new(Notify::new()), fast_config()).await
        });

        for expected in &blocks {
            let event = timeout(TEST_TIMEOUT, rx.recv()).await.unwrap().unwrap();
            match event {
                BitcoinEvent::BlockInsert { block, .. } => {
                    assert_eq!(block.height, expected.height);
                    assert_eq!(block.hash, expected.hash);
                }
                other => panic!("expected BlockInsert, got {:?}", other),
            }
        }

        cancel.cancel();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_delivers_new_blocks_at_tip() {
        let blocks = new_numbered_blockchain(3);
        let rpc = MockBitcoinRpc::new(blocks.clone());
        let cancel = CancellationToken::new();
        let (tx, mut rx) = mpsc::channel(16);

        let rpc2 = rpc.clone();
        let cancel2 = cancel.clone();
        let handle = tokio::spawn(async move {
            run(rpc2, noop_filter, tx, cancel2, 1, vec![], Arc::new(Notify::new()), fast_config()).await
        });

        for expected in &blocks {
            let event = timeout(TEST_TIMEOUT, rx.recv()).await.unwrap().unwrap();
            match event {
                BitcoinEvent::BlockInsert { block, .. } => {
                    assert_eq!(block.height, expected.height);
                    assert_eq!(block.hash, expected.hash);
                }
                other => panic!("expected BlockInsert, got {:?}", other),
            }
        }

        let more = gen_numbered_blocks(3, 5, blocks[2].hash);
        rpc.append_blocks(more.clone());

        for expected in &more {
            let event = timeout(TEST_TIMEOUT, rx.recv()).await.unwrap().unwrap();
            match event {
                BitcoinEvent::BlockInsert { block, .. } => {
                    assert_eq!(block.height, expected.height);
                    assert_eq!(block.hash, expected.hash);
                }
                other => panic!("expected BlockInsert, got {:?}", other),
            }
        }

        cancel.cancel();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_detects_reorg() {
        let blocks = new_numbered_blockchain(5);
        let rpc = MockBitcoinRpc::new(blocks.clone());
        let cancel = CancellationToken::new();
        let (tx, mut rx) = mpsc::channel(16);

        let rpc2 = rpc.clone();
        let cancel2 = cancel.clone();
        let handle = tokio::spawn(async move {
            run(rpc2, noop_filter, tx, cancel2, 1, vec![], Arc::new(Notify::new()), fast_config()).await
        });

        for expected in &blocks {
            let event = timeout(TEST_TIMEOUT, rx.recv()).await.unwrap().unwrap();
            match event {
                BitcoinEvent::BlockInsert { block, .. } => {
                    assert_eq!(block.height, expected.height);
                }
                other => panic!("expected BlockInsert, got {:?}", other),
            }
        }

        // Fork after block 3
        let mut forked = blocks[..3].to_vec();
        for i in 4..=6 {
            forked.push(indexer_types::Block {
                height: i,
                hash: BlockHash::from_byte_array([0xF0 + i as u8; 32]),
                prev_hash: forked.last().unwrap().hash,
                transactions: vec![],
            });
        }
        rpc.replace_blocks(forked.clone());

        let event = timeout(TEST_TIMEOUT, rx.recv()).await.unwrap().unwrap();
        match event {
            BitcoinEvent::Rollback { to_height } => {
                assert_eq!(to_height, 3);
            }
            other => panic!("expected Rollback, got {:?}", other),
        }

        for expected in &forked[3..] {
            let event = timeout(TEST_TIMEOUT, rx.recv()).await.unwrap().unwrap();
            match event {
                BitcoinEvent::BlockInsert { block, .. } => {
                    assert_eq!(block.height, expected.height);
                    assert_eq!(block.hash, expected.hash);
                }
                other => panic!("expected BlockInsert, got {:?}", other),
            }
        }

        cancel.cancel();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_rollback_on_chain_shrink() {
        let blocks = new_numbered_blockchain(5);
        let rpc = MockBitcoinRpc::new(blocks.clone());
        let cancel = CancellationToken::new();
        let (tx, mut rx) = mpsc::channel(16);

        let rpc2 = rpc.clone();
        let cancel2 = cancel.clone();
        let handle = tokio::spawn(async move {
            run(rpc2, noop_filter, tx, cancel2, 1, vec![], Arc::new(Notify::new()), fast_config()).await
        });

        for _ in 0..5 {
            let event = timeout(TEST_TIMEOUT, rx.recv()).await.unwrap().unwrap();
            assert!(matches!(event, BitcoinEvent::BlockInsert { .. }));
        }

        rpc.replace_blocks(blocks[..3].to_vec());

        let event = timeout(TEST_TIMEOUT, rx.recv()).await.unwrap().unwrap();
        match event {
            BitcoinEvent::Rollback { to_height } => {
                assert_eq!(to_height, 3);
            }
            other => panic!("expected Rollback, got {:?}", other),
        }

        cancel.cancel();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_detects_offline_reorg() {
        // Consumer had blocks 1-5 (original chain). While offline, a
        // 2-block reorg replaced blocks 4-5. Node now has alt chain
        // with 6 blocks. Consumer provides its hash history; startup
        // compares against the node and finds the fork at height 3.
        let original = new_numbered_blockchain(5);

        let mut alt_chain = original[..3].to_vec();
        for i in 4..=6 {
            alt_chain.push(indexer_types::Block {
                height: i,
                hash: BlockHash::from_byte_array([0xD0 + i as u8; 32]),
                prev_hash: alt_chain.last().unwrap().hash,
                transactions: vec![],
            });
        }
        let rpc = MockBitcoinRpc::new(alt_chain.clone());
        let cancel = CancellationToken::new();
        let (tx, mut rx) = mpsc::channel(16);

        // Consumer provides its full hash history
        let known: Vec<(u64, BlockHash)> = original.iter().map(|b| (b.height, b.hash)).collect();

        let cancel2 = cancel.clone();
        let handle = tokio::spawn(async move {
            run(rpc, noop_filter, tx, cancel2, 6, known, Arc::new(Notify::new()), fast_config()).await
        });

        let event = timeout(TEST_TIMEOUT, rx.recv()).await.unwrap().unwrap();
        match event {
            BitcoinEvent::Rollback { to_height } => {
                assert_eq!(to_height, 3);
            }
            other => panic!("expected Rollback, got {:?}", other),
        }

        for expected in &alt_chain[3..] {
            let event = timeout(TEST_TIMEOUT, rx.recv()).await.unwrap().unwrap();
            match event {
                BitcoinEvent::BlockInsert { block, .. } => {
                    assert_eq!(block.height, expected.height);
                    assert_eq!(block.hash, expected.hash);
                }
                other => panic!("expected BlockInsert, got {:?}", other),
            }
        }

        cancel.cancel();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_no_offline_reorg_when_hashes_match() {
        // Consumer's known hashes match the chain — no rollback on startup.
        let blocks = new_numbered_blockchain(5);
        let rpc = MockBitcoinRpc::new(blocks.clone());
        let cancel = CancellationToken::new();
        let (tx, mut rx) = mpsc::channel(16);

        // Consumer processed blocks 1-3, resuming from 4
        let known: Vec<(u64, BlockHash)> = blocks[..3].iter().map(|b| (b.height, b.hash)).collect();

        let cancel2 = cancel.clone();
        let handle = tokio::spawn(async move {
            run(rpc, noop_filter, tx, cancel2, 4, known, Arc::new(Notify::new()), fast_config()).await
        });

        for expected in &blocks[3..] {
            let event = timeout(TEST_TIMEOUT, rx.recv()).await.unwrap().unwrap();
            match event {
                BitcoinEvent::BlockInsert { block, .. } => {
                    assert_eq!(block.height, expected.height);
                    assert_eq!(block.hash, expected.hash);
                }
                other => panic!("expected BlockInsert, got {:?}", other),
            }
        }

        cancel.cancel();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_offline_reorg_deeper_than_cache_errors() {
        // Consumer only provides hashes for blocks 4-5, but the reorg
        // goes back to block 2. find_fork_point exhausts the cache
        // and run() should propagate the error.
        let original = new_numbered_blockchain(5);

        let mut alt_chain = original[..2].to_vec();
        for i in 3..=6 {
            alt_chain.push(indexer_types::Block {
                height: i,
                hash: BlockHash::from_byte_array([0xD0 + i as u8; 32]),
                prev_hash: alt_chain.last().unwrap().hash,
                transactions: vec![],
            });
        }
        let rpc = MockBitcoinRpc::new(alt_chain);

        // Consumer only knows blocks 4-5 — not deep enough
        let known: Vec<(u64, BlockHash)> =
            original[3..5].iter().map(|b| (b.height, b.hash)).collect();

        let cancel = CancellationToken::new();
        let (tx, _rx) = mpsc::channel(16);

        let result = run(rpc, noop_filter, tx, cancel, 6, known, Arc::new(Notify::new()), fast_config()).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn run_start_height_1_skips_offline_check() {
        // start_height=1 means start_height-1=0, and there's no block 0
        // hash to check. The poller should skip the offline reorg check
        // and just start delivering blocks.
        let blocks = new_numbered_blockchain(3);
        let rpc = MockBitcoinRpc::new(blocks.clone());
        let cancel = CancellationToken::new();
        let (tx, mut rx) = mpsc::channel(16);

        let cancel2 = cancel.clone();
        let handle = tokio::spawn(async move {
            run(rpc, noop_filter, tx, cancel2, 1, vec![], Arc::new(Notify::new()), fast_config()).await
        });

        for expected in &blocks {
            let event = timeout(TEST_TIMEOUT, rx.recv()).await.unwrap().unwrap();
            match event {
                BitcoinEvent::BlockInsert { block, .. } => {
                    assert_eq!(block.height, expected.height);
                    assert_eq!(block.hash, expected.hash);
                }
                other => panic!("expected BlockInsert, got {:?}", other),
            }
        }

        cancel.cancel();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_reorg_during_catchup() {
        // Poller delivered blocks 1-10. Chain reorgs: fork after block
        // 5, new tip is 8. Chain-shrink detection sees tip dropped,
        // runs find_fork_point which walks back to the real fork at 5.
        let blocks = new_numbered_blockchain(10);
        let rpc = MockBitcoinRpc::new(blocks.clone());
        let cancel = CancellationToken::new();
        let (tx, mut rx) = mpsc::channel(32);

        let rpc2 = rpc.clone();
        let cancel2 = cancel.clone();
        let handle = tokio::spawn(async move {
            run(rpc2, noop_filter, tx, cancel2, 1, vec![], Arc::new(Notify::new()), fast_config()).await
        });

        for expected in &blocks {
            let event = timeout(TEST_TIMEOUT, rx.recv()).await.unwrap().unwrap();
            match event {
                BitcoinEvent::BlockInsert { block, .. } => {
                    assert_eq!(block.height, expected.height);
                }
                other => panic!(
                    "expected BlockInsert at {}, got {:?}",
                    expected.height, other
                ),
            }
        }

        // Fork after block 5, new chain has blocks 6-8
        let mut forked = blocks[..5].to_vec();
        for i in 6..=8 {
            forked.push(indexer_types::Block {
                height: i,
                hash: BlockHash::from_byte_array([0xE0 + i as u8; 32]),
                prev_hash: forked.last().unwrap().hash,
                transactions: vec![],
            });
        }
        rpc.replace_blocks(forked.clone());

        // Single rollback to the real fork point
        let event = timeout(TEST_TIMEOUT, rx.recv()).await.unwrap().unwrap();
        match event {
            BitcoinEvent::Rollback { to_height } => {
                assert_eq!(to_height, 5);
            }
            other => panic!("expected Rollback to 5, got {:?}", other),
        }

        for expected in &forked[5..] {
            let event = timeout(TEST_TIMEOUT, rx.recv()).await.unwrap().unwrap();
            match event {
                BitcoinEvent::BlockInsert { block, .. } => {
                    assert_eq!(block.height, expected.height);
                    assert_eq!(block.hash, expected.hash);
                }
                other => panic!("expected BlockInsert, got {:?}", other),
            }
        }

        cancel.cancel();
        handle.await.unwrap().unwrap();
    }

    #[tokio::test]
    async fn run_cancellation_stops_cleanly() {
        let blocks = new_numbered_blockchain(3);
        let rpc = MockBitcoinRpc::new(blocks);
        let cancel = CancellationToken::new();
        let (tx, _rx) = mpsc::channel(16);

        cancel.cancel();

        let result = run(rpc, noop_filter, tx, cancel, 1, vec![], Arc::new(Notify::new()), fast_config()).await;
        assert!(result.is_ok());
    }
}
