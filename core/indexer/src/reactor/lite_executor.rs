use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::Result;
use bitcoin::{BlockHash, Network, Transaction as BitcoinTransaction, Txid};
use futures_util::future::BoxFuture;
use indexer_types::Transaction;
use tokio::sync::{OnceCell, mpsc};

use super::prepare_executor_startup;
use crate::bitcoin_follower::event::BlockEvent;
use crate::block::filter_map;
use crate::database::Writer;
use crate::protocol::coordinator::selection::ExecutionSelection;
use crate::protocol::coordinator::{bootstrap, linked};
use crate::protocol::v1::execution;
use crate::reactor::executor::{Executor, TxPolicy};
use crate::reactor::mock_bitcoin::MockBitcoin;
use crate::runtime::numerics::decimal_to_string;
use crate::runtime::ownership::OwnerService;
use crate::runtime::ownership::adapter::SessionFactory;
use crate::runtime::pool::LinkedSession;
use crate::runtime::{GenesisValidator, Runtime};
use crate::test_utils::test_genesis;

pub async fn shared_session_factory() -> SessionFactory {
    static ONCE: OnceCell<SessionFactory> = OnceCell::const_new();
    ONCE.get_or_init(|| async {
        linked::session_factory(Network::Regtest, None).expect("cluster session factory")
    })
    .await
    .clone()
}

/// Uses the production executor with mock Bitcoin I/O and explicit test pauses.
pub struct LiteExecutor {
    data_dir: PathBuf,
    mock_bitcoin: Arc<Mutex<MockBitcoin>>,
    block_tx: mpsc::Sender<BlockEvent>,
    validation_delay: Option<Duration>,
}

impl LiteExecutor {
    pub fn data_dir(&self) -> PathBuf {
        self.data_dir.clone()
    }

    pub async fn open(
        data_dir: &Path,
        db_name: &str,
        mock_bitcoin: Arc<Mutex<MockBitcoin>>,
        genesis_validators: &[GenesisValidator],
        factory: SessionFactory,
        service: &OwnerService,
        block_tx: mpsc::Sender<BlockEvent>,
    ) -> Result<(Self, LinkedSession, u64, Option<BlockHash>)> {
        let writer = Writer::new(data_dir, db_name).await?;
        let parameters = test_genesis(genesis_validators);
        let genesis = (
            decimal_to_string(parameters.sigma_min),
            parameters
                .validators
                .iter()
                .map(|v| {
                    (
                        v.x_only_pubkey.clone(),
                        decimal_to_string(v.stake),
                        v.ed25519_pubkey.clone(),
                    )
                })
                .collect(),
        );
        // Fresh and restarted nodes use the same journal checks. No synthetic
        // counter state or signer funding is inserted outside ordered execution.
        let (baseline, initialize) =
            bootstrap::prepare(&writer.connection(), Network::Regtest, 1, &genesis).await?;
        let (height, hash) = prepare_executor_startup(1, &writer).await?;
        let mut executor = factory(writer.connection()).await?;
        let maintenance = executor.operations.maintenance.clone();
        let pauses = mock_bitcoin.clone();
        executor.operations.maintenance = Arc::new(move |owner, selection| {
            let maintenance = maintenance.clone();
            let pauses = pauses.clone();
            Box::pin(async move {
                maintenance(owner, selection).await?;
                // Pause before the coordinator settles the owned rollback stage,
                // so shutdown must retain both the root and its SQL transaction.
                let gate = { pauses.lock().unwrap().rollback_stage_gate.clone() };
                if let Some(gate) = gate {
                    gate.wait().await;
                }
                Ok(())
            })
        });
        let session = LinkedSession::new(writer.connection(), executor);
        if initialize {
            linked::initialize(service, &session, Network::Regtest, 1, genesis).await?;
        }
        bootstrap::complete(service, &session, Network::Regtest, &baseline).await?;
        Ok((
            Self {
                data_dir: data_dir.to_path_buf(),
                mock_bitcoin,
                block_tx,
                validation_delay: None,
            },
            session,
            height,
            hash,
        ))
    }

    pub fn set_validation_delay(&mut self, delay: Duration) {
        self.validation_delay = Some(delay);
    }
}

impl Executor for LiteExecutor {
    fn validate_txs(
        &self,
        txs: Vec<BitcoinTransaction>,
        _threshold_sat_per_vb: u64,
    ) -> BoxFuture<'static, Result<Vec<(BitcoinTransaction, TxPolicy)>>> {
        let delay = self.validation_delay;
        Box::pin(async move {
            if let Some(delay) = delay
                && !txs.is_empty()
            {
                tokio::time::sleep(delay).await;
            }
            Ok(txs.into_iter().map(|tx| (tx, TxPolicy::Accepted)).collect())
        })
    }

    async fn resolve_transactions(&self, txids: &[Txid]) -> Vec<Option<BitcoinTransaction>> {
        let mock = self.mock_bitcoin.lock().unwrap();
        txids.iter().map(|t| mock.get_raw_transaction(t)).collect()
    }

    async fn execute_transaction_inner(
        &self,
        _selection: &ExecutionSelection,
        runtime: &mut Runtime,
        height: u64,
        tx_id: u64,
        tx: &Transaction,
    ) -> Result<Vec<Vec<Option<anyhow::Error>>>> {
        execution::execute_transaction(runtime, height, tx_id, tx).await
    }

    async fn replay_blocks_after(&mut self, after_height: u64) -> Result<()> {
        let events = self.mock_bitcoin.lock().unwrap().get_all_block_events();
        for event in events {
            if let BlockEvent::BlockInsert { block, .. } = &event
                && block.height > after_height
            {
                let _ = self.block_tx.send(event).await;
            }
        }
        Ok(())
    }

    fn parse_transaction(
        &self,
        _selection: &ExecutionSelection,
        tx: &BitcoinTransaction,
    ) -> Option<Transaction> {
        filter_map((0, tx.clone()))
    }
}
