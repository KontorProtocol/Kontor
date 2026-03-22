use std::collections::HashMap;

use anyhow::Result;
use bitcoin::Txid;

use indexer::consensus::Height;
use indexer::database::queries::{
    confirm_transaction, get_transaction_by_txid, insert_batch, insert_block, insert_transaction,
    insert_unconfirmed_batch_tx, select_unconfirmed_batch_tx, set_batch_processed,
    set_block_processed,
};
use indexer::reactor::executor::Executor;
use indexer::runtime::wit::Signer;
use indexer::runtime::{ContractAddress, Runtime, TransactionContext};
use indexer::test_utils::{new_mock_transaction, new_test_db};

use indexer_types::{BlockRow, TransactionRow};
use testlib::ContractReader;

pub struct LiteExecutor {
    runtime: Runtime,
    _db_dir: tempfile::TempDir,
    counter_address: ContractAddress,
    signer: Signer,
    known_txs: HashMap<Txid, bitcoin::Transaction>,
    pub replay_requests: Vec<u64>,
}

impl LiteExecutor {
    pub async fn new() -> Result<Self> {
        use indexer::database::queries::{
            contract_has_state, insert_contract, insert_processed_block,
        };
        use indexer::runtime::{ComponentCache, Storage};
        use indexer::test_utils::new_mock_block_hash;

        let (_reader, writer, (db_dir, _db_name)) = new_test_db().await?;
        let conn = writer.connection();

        // Insert genesis block only
        insert_processed_block(
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

        // Create identity
        let x_only_pubkey = indexer::reg_tester::random_x_only_pubkey();
        let signer = Signer::XOnlyPubKey(x_only_pubkey);
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
            indexer::database::types::ContractRow::builder()
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

        Ok(Self {
            runtime,
            _db_dir: db_dir,
            counter_address,
            signer,
            known_txs: HashMap::new(),
            replay_requests: Vec::new(),
        })
    }

    pub fn connection(&self) -> libsql::Connection {
        self.runtime.get_storage_conn()
    }

    /// Read counter value via the WASM contract
    #[allow(dead_code)]
    pub async fn counter_value(&mut self) -> Result<u64> {
        let result = self
            .runtime
            .execute(None, &self.counter_address, "get()")
            .await?;
        Ok(result.parse::<u64>()?)
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
            ops: Vec::new(),
            op_return_data: Default::default(),
        })
    }

    async fn resolve_transaction(&self, txid: &Txid) -> Option<bitcoin::Transaction> {
        if let Ok(Some(raw_bytes)) =
            select_unconfirmed_batch_tx(&self.connection(), &txid.to_string()).await
            && let Ok(tx) = bitcoin::consensus::deserialize::<bitcoin::Transaction>(&raw_bytes)
        {
            return Some(tx);
        }
        self.known_txs.get(txid).cloned()
    }

    async fn execute_batch(
        &mut self,
        anchor_height: u64,
        anchor_hash: bitcoin::BlockHash,
        consensus_height: Height,
        certificate: &[u8],
        txs: &[indexer_types::Transaction],
        raw_txs: &[bitcoin::Transaction],
    ) {
        let conn = self.connection();

        if let Err(e) = insert_batch(
            &conn,
            consensus_height.as_u64() as i64,
            anchor_height as i64,
            &anchor_hash.to_string(),
            certificate,
        )
        .await
        {
            tracing::error!("insert_batch error: {e}");
            return;
        }

        for raw_tx in raw_txs {
            let txid = raw_tx.compute_txid();
            self.known_txs.insert(txid, raw_tx.clone());
            let serialized = bitcoin::consensus::serialize(raw_tx);
            let _ = insert_unconfirmed_batch_tx(
                &conn,
                &txid.to_string(),
                consensus_height.as_u64() as i64,
                &serialized,
            )
            .await;
        }

        for (i, t) in txs.iter().enumerate() {
            let tx_id = match insert_transaction(
                &conn,
                TransactionRow::builder()
                    .height(anchor_height as i64)
                    .batch_height(consensus_height.as_u64() as i64)
                    .txid(t.txid.to_string())
                    .build(),
            )
            .await
            {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("insert_transaction error: {e}");
                    continue;
                }
            };

            self.runtime
                .set_context(
                    anchor_height as i64,
                    Some(
                        TransactionContext::builder()
                            .tx_id(tx_id)
                            .tx_index(i as i64)
                            .txid(t.txid)
                            .build(),
                    ),
                    None,
                    None,
                )
                .await;

            if let Err(e) = self
                .runtime
                .execute(Some(&self.signer), &self.counter_address, "increment()")
                .await
            {
                tracing::error!("counter increment error: {e}");
            }
        }

        let _ = set_batch_processed(&conn, consensus_height.as_u64() as i64).await;
    }

    async fn execute_block(&mut self, block: &indexer_types::Block) {
        let conn = self.connection();

        let _ = insert_block(
            &conn,
            BlockRow::builder()
                .height(block.height as i64)
                .hash(block.hash)
                .relevant(!block.transactions.is_empty())
                .build(),
        )
        .await;

        for (i, t) in block.transactions.iter().enumerate() {
            if let Ok(Some(_)) = get_transaction_by_txid(&conn, &t.txid.to_string()).await {
                let _ =
                    confirm_transaction(&conn, &t.txid.to_string(), block.height as i64, i as i64)
                        .await;
                continue;
            }

            let tx_id = match insert_transaction(
                &conn,
                TransactionRow::builder()
                    .height(block.height as i64)
                    .tx_index(i as i64)
                    .confirmed_height(block.height as i64)
                    .txid(t.txid.to_string())
                    .build(),
            )
            .await
            {
                Ok(id) => id,
                Err(e) => {
                    tracing::error!("insert_transaction error: {e}");
                    continue;
                }
            };

            self.runtime
                .set_context(
                    block.height as i64,
                    Some(
                        TransactionContext::builder()
                            .tx_id(tx_id)
                            .tx_index(i as i64)
                            .txid(t.txid)
                            .build(),
                    ),
                    None,
                    None,
                )
                .await;

            if let Err(e) = self
                .runtime
                .execute(Some(&self.signer), &self.counter_address, "increment()")
                .await
            {
                tracing::error!("counter increment error: {e}");
            }
        }

        let _ = set_block_processed(&conn, block.height as i64).await;
    }

    async fn replay_blocks_from(&mut self, height: u64) {
        self.replay_requests.push(height);
    }

    fn parse_transaction(&self, tx: &bitcoin::Transaction) -> Option<indexer_types::Transaction> {
        Some(indexer_types::Transaction {
            txid: tx.compute_txid(),
            index: 0,
            ops: vec![],
            op_return_data: Default::default(),
        })
    }
}
