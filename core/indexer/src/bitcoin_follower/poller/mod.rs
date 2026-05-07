use std::{
    collections::{HashMap, VecDeque},
    sync::Arc,
    thread,
    time::Duration,
};

use anyhow::{Result, bail};
use bitcoin::BlockHash;
use indexer_types::Block;
use rayon::iter::{IndexedParallelIterator, IntoParallelIterator, ParallelIterator};
use tokio::{
    select,
    sync::{
        Notify,
        mpsc::{Receiver, Sender},
    },
    task::JoinSet,
    time::sleep,
};
use tokio_util::sync::CancellationToken;
use tracing::{error, info, warn};

use crate::{
    bitcoin_client::client::BitcoinRpc,
    block::TransactionFilterMap,
    retry::{new_backoff_unlimited, retry},
};

use super::event::BlockEvent;

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
        events: Vec<BlockEvent>,
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
        events.push(BlockEvent::BlockInsert {
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
    event_tx: &Sender<BlockEvent>,
) -> bool {
    cache.truncate_above(fork_height);
    *next_height = fork_height + 1;
    event_tx
        .send(BlockEvent::Rollback {
            to_height: fork_height,
        })
        .await
        .is_ok()
}

enum PollResult {
    Continue,
    Replay(u64),
    Cancelled,
}

/// Wait for the next poll trigger: timer, ZMQ wake, replay request, or cancellation.
async fn wait_for_poll(
    poll_interval: Duration,
    poll_notify: &Notify,
    replay_rx: &mut Receiver<u64>,
    cancel_token: &CancellationToken,
) -> PollResult {
    select! {
        _ = sleep(poll_interval) => PollResult::Continue,
        _ = poll_notify.notified() => PollResult::Continue,
        Some(height) = replay_rx.recv() => PollResult::Replay(height),
        _ = cancel_token.cancelled() => PollResult::Cancelled,
    }
}

// -- Main poller loop --

pub async fn run<C: BitcoinRpc>(
    bitcoin: C,
    f: TransactionFilterMap,
    event_tx: Sender<BlockEvent>,
    cancel_token: CancellationToken,
    start_height: u64,
    known_hashes: Vec<(u64, BlockHash)>,
    poll_notify: Arc<Notify>,
    config: PollerConfig,
    mut replay_rx: Receiver<u64>,
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

        if tip < next_height {
            match wait_for_poll(
                config.poll_interval,
                &poll_notify,
                &mut replay_rx,
                &cancel_token,
            )
            .await
            {
                PollResult::Continue => continue,
                PollResult::Replay(height) => {
                    info!(height, "Replay request received — resetting poller");
                    cache.truncate_above(height);
                    next_height = height + 1;
                    continue;
                }
                PollResult::Cancelled => return Ok(()),
            }
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
mod tests;
