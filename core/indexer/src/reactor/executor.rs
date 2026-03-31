use bitcoin::Txid;
use tokio_util::sync::CancellationToken;
use tracing::warn;

use crate::bitcoin_client::Client;
use crate::block::filter_map;
use crate::bls::validate_aggregate_shape;
use crate::retry::{new_backoff_unlimited, retry};
use crate::runtime::Runtime;

/// Check if a parsed transaction contains only batchable ops.
/// Non-batchable ops (Publish, Issuance, RegisterBlsKey) must only execute
/// via Value::Block decisions, not consensus batches.
/// Aggregate inputs are batchable only if they satisfy the same stateless shape
/// constraints enforced by aggregate execution preflight.
pub fn is_batchable(inputs: &[indexer_types::TransactionInput]) -> bool {
    inputs.iter().all(|input| {
        if input.insts.is_aggregate() {
            return validate_aggregate_shape(&input.insts).is_ok();
        }
        !input.insts.ops.iter().any(|inst| {
            matches!(
                inst,
                indexer_types::Inst::Publish { .. }
                    | indexer_types::Inst::Issuance
                    | indexer_types::Inst::RegisterBlsKey { .. }
            )
        })
    })
}

/// Abstraction over transaction execution and state rollback.
///
/// The consensus orchestration logic (`ConsensusState.process_decided_batch` and
/// `run_finality_checks`) calls these methods instead of directly manipulating state.
#[allow(async_fn_in_trait)]
pub trait Executor {
    /// Validate a transaction and parse its Kontor ops.
    /// Returns the parsed transaction if valid, None otherwise.
    /// Implementations may also propagate the tx to the local bitcoind mempool.
    async fn validate_transaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Option<indexer_types::Transaction>;

    /// Resolve a txid to a full bitcoin::Transaction. Used to fetch transaction
    /// data for batch execution — batches carry only txids.
    async fn resolve_transaction(&self, txid: &Txid) -> Option<bitcoin::Transaction>;

    /// Execute a single transaction's operations at the given height.
    /// Called by the reactor after DB row insertion. Sets context and runs ops.
    async fn execute_transaction(
        &self,
        runtime: &mut Runtime,
        height: i64,
        tx_id: i64,
        tx: &indexer_types::Transaction,
    );

    /// Signal the block source to re-deliver blocks starting from `height`.
    async fn replay_blocks_from(&mut self, height: u64);

    /// Parse a bitcoin::Transaction into an indexer_types::Transaction.
    fn parse_transaction(&self, tx: &bitcoin::Transaction) -> Option<indexer_types::Transaction>;
}

/// Placeholder executor that does nothing.
pub struct NoopExecutor;

impl Executor for NoopExecutor {
    async fn validate_transaction(
        &self,
        _tx: &bitcoin::Transaction,
    ) -> Option<indexer_types::Transaction> {
        None
    }
    async fn resolve_transaction(&self, _txid: &Txid) -> Option<bitcoin::Transaction> {
        None
    }
    async fn execute_transaction(
        &self,
        _runtime: &mut Runtime,
        _height: i64,
        _tx_id: i64,
        _tx: &indexer_types::Transaction,
    ) {
    }
    async fn replay_blocks_from(&mut self, _height: u64) {}
    fn parse_transaction(&self, _tx: &bitcoin::Transaction) -> Option<indexer_types::Transaction> {
        None
    }
}

/// Production executor: handles transaction validation, resolution, and op execution.
/// Does NOT own the Runtime — the reactor owns it and passes &mut Runtime when needed.
pub struct RuntimeExecutor {
    pub bitcoin_client: Option<Client>,
    pub replay_tx: Option<tokio::sync::mpsc::Sender<u64>>,
    pub cancel_token: CancellationToken,
}

impl RuntimeExecutor {
    pub fn new(cancel_token: CancellationToken) -> Self {
        Self {
            bitcoin_client: None,
            replay_tx: None,
            cancel_token,
        }
    }

    pub fn with_bitcoin_client(mut self, client: Client) -> Self {
        self.bitcoin_client = Some(client);
        self
    }

    pub fn with_replay_tx(mut self, tx: tokio::sync::mpsc::Sender<u64>) -> Self {
        self.replay_tx = Some(tx);
        self
    }
}

impl Executor for RuntimeExecutor {
    async fn validate_transaction(
        &self,
        tx: &bitcoin::Transaction,
    ) -> Option<indexer_types::Transaction> {
        // Parse Kontor ops — reject if no valid ops
        let parsed = filter_map((0, tx.clone()))?;

        if !is_batchable(&parsed.inputs) {
            return None;
        }

        // Push to local bitcoind mempool (idempotent, succeeds if already present).
        // -25 (RPC_VERIFY_ERROR): general validation error (missing inputs) — invalid
        // -26 (RPC_VERIFY_REJECTED): rejected by mempool policy — invalid
        // -27 (RPC_VERIFY_ALREADY_IN_UTXO_SET): tx already confirmed — treat as success
        // All other errors (network, node loading) are retried via unlimited backoff.
        if let Some(client) = &self.bitcoin_client {
            let raw_hex = bitcoin::consensus::encode::serialize_hex(tx);
            let result = retry(
                || async {
                    match client.send_raw_transaction(&raw_hex).await {
                        Ok(_) => Ok(true),
                        Err(crate::bitcoin_client::error::Error::BitcoinRpc {
                            code: -27, ..
                        }) => Ok(true),
                        Err(crate::bitcoin_client::error::Error::BitcoinRpc {
                            code: -25 | -26,
                            ..
                        }) => Ok(false),
                        Err(e) => Err(e),
                    }
                },
                "send_raw_transaction",
                new_backoff_unlimited(),
                self.cancel_token.clone(),
            )
            .await;
            match result {
                Ok(true) => {}
                Ok(false) => {
                    warn!(txid = %tx.compute_txid(), "Transaction rejected by bitcoind");
                    return None;
                }
                Err(e) => {
                    warn!(txid = %tx.compute_txid(), %e, "send_raw_transaction failed");
                    return None;
                }
            }
        }

        Some(parsed)
    }
    async fn resolve_transaction(&self, txid: &Txid) -> Option<bitcoin::Transaction> {
        // Fall back to Bitcoin RPC (via tx cache)
        let client = self.bitcoin_client.as_ref()?;
        match client.get_raw_transaction(txid).await {
            Ok(tx) => Some(tx),
            Err(e) => {
                warn!(%txid, %e, "Failed to resolve transaction via RPC");
                None
            }
        }
    }
    async fn execute_transaction(
        &self,
        runtime: &mut Runtime,
        height: i64,
        tx_id: i64,
        tx: &indexer_types::Transaction,
    ) {
        for input in &tx.inputs {
            let op_return_data = tx.op_return_data.get(&(input.input_index as u64)).cloned();
            super::block_handler::process_input(
                runtime,
                input,
                height,
                Some(tx_id),
                tx.index,
                tx.txid,
                op_return_data,
            )
            .await;
        }
    }
    async fn replay_blocks_from(&mut self, height: u64) {
        if let Some(tx) = &self.replay_tx
            && let Err(e) = tx.send(height).await
        {
            tracing::error!(%e, height, "Failed to send replay request to poller");
        }
    }

    fn parse_transaction(&self, tx: &bitcoin::Transaction) -> Option<indexer_types::Transaction> {
        filter_map((0, tx.clone()))
    }
}

#[cfg(test)]
mod tests {
    use super::is_batchable;
    use bitcoin::OutPoint;
    use indexer_types::{AggregateInfo, ContractAddress, Inst, Insts, Signer, TransactionInput};

    fn aggregate_input(ops: Vec<Inst>, signer_ids: Vec<u64>) -> TransactionInput {
        TransactionInput {
            previous_output: OutPoint::null(),
            input_index: 0,
            witness_signer: Signer::XOnlyPubKey("00".repeat(32)),
            insts: Insts {
                ops,
                aggregate: Some(AggregateInfo {
                    signer_ids,
                    signature: vec![7u8; 48],
                }),
            },
        }
    }

    fn direct_input(inst: Inst) -> TransactionInput {
        TransactionInput {
            previous_output: OutPoint::null(),
            input_index: 0,
            witness_signer: Signer::XOnlyPubKey("00".repeat(32)),
            insts: Insts {
                ops: vec![inst],
                aggregate: None,
            },
        }
    }

    fn sample_call(nonce: Option<u64>) -> Inst {
        Inst::Call {
            gas_limit: 50_000,
            contract: ContractAddress {
                name: "arith".to_string(),
                height: 1,
                tx_index: 0,
            },
            nonce,
            expr: "eval(1, id)".to_string(),
        }
    }

    #[test]
    fn is_batchable_accepts_well_formed_aggregate_input() {
        let input = aggregate_input(vec![sample_call(Some(0))], vec![1]);
        assert!(is_batchable(&[input]));
    }

    #[test]
    fn is_batchable_rejects_aggregate_with_mismatched_signer_count() {
        let input = aggregate_input(vec![sample_call(Some(0))], vec![]);
        assert!(!is_batchable(&[input]));
    }

    #[test]
    fn is_batchable_rejects_aggregate_call_without_nonce() {
        let input = aggregate_input(vec![sample_call(None)], vec![1]);
        assert!(!is_batchable(&[input]));
    }

    #[test]
    fn is_batchable_rejects_aggregate_with_non_call_ops() {
        let publish = Inst::Publish {
            gas_limit: 10,
            name: "test".to_string(),
            bytes: vec![],
        };
        let register = Inst::RegisterBlsKey {
            bls_pubkey: vec![0u8; 96],
            schnorr_sig: vec![0u8; 64],
            bls_sig: vec![0u8; 48],
        };
        assert!(!is_batchable(&[aggregate_input(vec![publish], vec![1])]));
        assert!(!is_batchable(&[aggregate_input(vec![register], vec![1])]));
        assert!(!is_batchable(&[aggregate_input(
            vec![Inst::Issuance],
            vec![1]
        )]));
    }

    #[test]
    fn is_batchable_still_rejects_non_batchable_direct_ops() {
        assert!(!is_batchable(&[direct_input(Inst::Publish {
            gas_limit: 10,
            name: "test".to_string(),
            bytes: vec![],
        })]));
        assert!(!is_batchable(&[direct_input(Inst::RegisterBlsKey {
            bls_pubkey: vec![0u8; 96],
            schnorr_sig: vec![0u8; 64],
            bls_sig: vec![0u8; 48],
        })]));
        assert!(!is_batchable(&[direct_input(Inst::Issuance)]));
    }
}
