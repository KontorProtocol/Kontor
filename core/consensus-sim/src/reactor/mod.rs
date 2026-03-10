mod bitcoin;
mod consensus;
mod finality;
pub mod types;

use std::collections::BTreeMap;

use anyhow::anyhow;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;
use tracing::info;

use malachitebft_app_channel::Channels;
use malachitebft_app_channel::app::types::ProposedValue;
use malachitebft_app_channel::app::types::core::Round;
use malachitebft_core_types::CommitCertificate;

use crate::DecidedBatch;
use crate::state_log::StateLog;

use indexer::consensus::signing::Ed25519Provider;
use indexer::consensus::{Address, Ctx, Genesis, Height, Value};
use indexer::reactor::bitcoin_state::BitcoinState;

pub use types::{FinalityEvent, PendingBatch, StateEvent};

pub struct State {
    pub(super) node_index: usize,
    pub(super) signing_provider: Ed25519Provider,
    pub(super) genesis: Genesis,
    pub(super) address: Address,
    pub(super) current_height: Height,
    pub(super) current_round: Round,
    pub(super) decided: BTreeMap<Height, (Value, CommitCertificate<Ctx>)>,
    pub(super) undecided: BTreeMap<(Height, Round), ProposedValue<Ctx>>,

    // Bitcoin state
    pub(super) bitcoin_state: BitcoinState,

    // Finality tracking
    pub(super) pending_batches: Vec<PendingBatch>,

    // State machine replication
    pub(super) state_log: StateLog,
    pub(super) last_processed_anchor: u64,

    // Observation channels
    pub(super) decided_tx: Option<mpsc::Sender<DecidedBatch>>,
    pub(super) finality_tx: Option<mpsc::Sender<FinalityEvent>>,
    pub(super) state_tx: Option<mpsc::Sender<StateEvent>>,
}

impl State {
    pub fn new(
        node_index: usize,
        signing_provider: Ed25519Provider,
        genesis: Genesis,
        address: Address,
        decided_tx: Option<mpsc::Sender<DecidedBatch>>,
        finality_tx: Option<mpsc::Sender<FinalityEvent>>,
        state_tx: Option<mpsc::Sender<StateEvent>>,
    ) -> Self {
        Self {
            node_index,
            signing_provider,
            genesis,
            address,
            current_height: Height::new(1),
            current_round: Round::new(0),
            decided: BTreeMap::new(),
            undecided: BTreeMap::new(),
            bitcoin_state: BitcoinState::new(types::FINALITY_WINDOW + 6),
            pending_batches: Vec::new(),
            state_log: StateLog::new(),
            last_processed_anchor: 0,
            decided_tx,
            finality_tx,
            state_tx,
        }
    }
}

/// Run the reactor loop, handling both consensus messages and bitcoin events.
pub async fn run(
    state: &mut State,
    channels: &mut Channels<Ctx>,
    bitcoin_rx: &mut mpsc::Receiver<indexer::bitcoin_follower::event::BitcoinEvent>,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                info!("Reactor cancelled");
                return Ok(());
            }
            Some(event) = bitcoin_rx.recv() => {
                bitcoin::handle_bitcoin_event(state, event);
            }
            Some(msg) = channels.consensus.recv() => {
                consensus::handle_consensus_msg(state, channels, msg).await?;
            }
            else => break,
        }
    }

    Err(anyhow!("All channels closed"))
}
