use std::sync::{Arc, Mutex};

use anyhow::Result;
use bitcoin::Txid;

use indexer::database::queries::{
    contract_has_state, get_transaction_by_txid, insert_block, insert_contract, insert_transaction,
};
use indexer::database::types::ContractRow;
use indexer::reactor::executor::Executor;
use indexer::reactor::mock_bitcoin::MockBitcoin;
use indexer::runtime::wit::Signer;
use indexer::runtime::{ComponentCache, ContractAddress, Runtime, Storage, TransactionContext};
use indexer::test_utils::{new_mock_block_hash, new_mock_transaction, new_test_db};

use indexer_types::{BlockRow, TransactionRow};
use testlib::ContractReader;

pub struct LiteExecutor {
    _db_dir: tempfile::TempDir,
    counter_address: ContractAddress,
    signer: Signer,
    mock_bitcoin: Arc<Mutex<MockBitcoin>>,
    pub replay_requests: Vec<u64>,
}

impl LiteExecutor {
    pub fn data_dir(&self) -> std::path::PathBuf {
        self._db_dir.path().to_path_buf()
    }

    pub async fn new(
        mock_bitcoin: Arc<Mutex<MockBitcoin>>,
        shared_pubkey: String,
    ) -> Result<(Self, Runtime)> {
        let (_reader, writer, (db_dir, _db_name)) = new_test_db().await?;
        let conn = writer.connection();

        // Insert genesis block only
        insert_block(
            &conn,
            BlockRow::builder()
                .height(0)
                .hash(new_mock_block_hash(0))
                .relevant(true)
                .build(),
        )
        .await?;

        let storage = Storage::builder().height(0).conn(conn).build();
        let mut runtime = Runtime::new(ComponentCache::new(), storage).await?;
        runtime.publish_native_contracts(&[]).await?;

        // Create identity using shared key so all nodes have the same state
        let signer = Signer::XOnlyPubKey(shared_pubkey);
        runtime.issuance(&signer).await?;

        // Publish counter contract
        let contract_reader = ContractReader::new("../../test-contracts").await?;
        let counter_bytes = contract_reader
            .read("counter")
            .await?
            .expect("counter contract WASM not found — run build.sh in test-contracts/");

        let mock_tx = new_mock_transaction(1);
        let conn = runtime.get_storage_conn();
        if get_transaction_by_txid(&conn, &mock_tx.txid.to_string())
            .await?
            .is_none()
        {
            insert_transaction(
                &conn,
                TransactionRow::builder()
                    .height(0)
                    .tx_index(0)
                    .txid(mock_tx.txid.to_string())
                    .build(),
            )
            .await?;
        }

        let counter_address = ContractAddress {
            name: "counter".to_string(),
            height: 0,
            tx_index: 0,
        };

        let contract_id = insert_contract(
            &conn,
            ContractRow::builder()
                .height(0)
                .tx_index(0)
                .name("counter".to_string())
                .bytes(counter_bytes)
                .build(),
        )
        .await?;

        if !contract_has_state(&conn, contract_id).await? {
            runtime
                .set_context(
                    0,
                    Some(
                        TransactionContext::builder()
                            .tx_index(0)
                            .txid(mock_tx.txid)
                            .build(),
                    ),
                    None,
                    None,
                )
                .await;
            runtime
                .execute(Some(&signer), &counter_address, "init()")
                .await?;
        }

        let _conn = runtime.get_storage_conn();
        Ok((
            Self {
                _db_dir: db_dir,
                counter_address,
                signer,
                mock_bitcoin,
                replay_requests: Vec::new(),
            },
            runtime,
        ))
    }
}

impl Executor for LiteExecutor {
    async fn validate_transaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Option<indexer_types::Transaction> {
        Some(indexer_types::Transaction {
            txid: tx.compute_txid(),
            index: 0,
            inputs: vec![],
            op_return_data: Default::default(),
        })
    }

    async fn resolve_transaction(&self, txid: &Txid) -> Option<bitcoin::Transaction> {
        // Fall back to MockBitcoin (stand-in for Bitcoin RPC)
        self.mock_bitcoin.lock().unwrap().get_raw_transaction(txid)
    }

    async fn execute_transaction(
        &self,
        runtime: &mut Runtime,
        height: i64,
        tx_id: i64,
        tx: &indexer_types::Transaction,
    ) {
        runtime
            .set_context(
                height,
                Some(
                    TransactionContext::builder()
                        .tx_id(tx_id)
                        .tx_index(tx.index)
                        .txid(tx.txid)
                        .build(),
                ),
                None,
                None,
            )
            .await;

        if let Err(e) = runtime
            .execute(Some(&self.signer), &self.counter_address, "increment()")
            .await
        {
            tracing::error!("counter increment error: {e}");
        }
    }

    async fn replay_blocks_from(&mut self, height: u64) {
        self.replay_requests.push(height);
    }

    fn parse_transaction(&self, tx: &bitcoin::Transaction) -> Option<indexer_types::Transaction> {
        Some(indexer_types::Transaction {
            txid: tx.compute_txid(),
            index: 0,
            inputs: vec![],
            op_return_data: Default::default(),
        })
    }
}
