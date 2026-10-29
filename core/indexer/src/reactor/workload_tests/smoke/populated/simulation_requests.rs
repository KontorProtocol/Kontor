use anyhow::{Context, Result, ensure};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::key::Keypair;
use bitcoin::{OutPoint, Transaction, TxOut};
use indexer_types::{Inst, OpStatus};
use serde_json::json;
use sha2::{Digest, Sha256};

use super::super::{GAS_LIMIT, SMOKE_HEIGHT, checked_signed_instructions, database_projection};
use crate::bitcoin_client::Client;
use crate::block::filter_map;
use crate::reactor::Reactor;
use crate::reactor::executor::RuntimeExecutor;

pub(super) struct SimulationRequests {
    transactions: Vec<Transaction>,
    operations_per_request: usize,
}

impl SimulationRequests {
    pub(super) async fn prepare(
        client: &Client,
        key: &Keypair,
        funding: (OutPoint, TxOut),
        instructions: Vec<Inst>,
        operations_per_request: usize,
    ) -> Result<Self> {
        ensure!(matches!(operations_per_request, 2 | 4));
        ensure!(
            !instructions.is_empty() && instructions.len().is_multiple_of(operations_per_request)
        );
        let mut transactions = Vec::new();
        for operations in instructions.chunks_exact(operations_per_request) {
            // Each request is an alternative spend of the same confirmed funding.
            // Bitcoin validates both signatures, but neither transaction is broadcast.
            let (_, reveal, _) =
                checked_signed_instructions(client, key, funding.clone(), operations.to_vec())
                    .await?;
            transactions.push(reveal);
        }
        Ok(Self {
            transactions,
            operations_per_request,
        })
    }

    pub(super) fn bytes(&self) -> Result<Vec<u8>> {
        let transactions: Vec<_> = self
            .transactions
            .iter()
            .map(|transaction| hex::encode(serialize(transaction)))
            .collect();
        Ok(serde_json::to_vec(&transactions)?)
    }

    pub(super) fn load(bytes: &[u8], operations_per_request: usize) -> Result<Self> {
        ensure!(matches!(operations_per_request, 2 | 4));
        let encoded: Vec<String> = serde_json::from_slice(bytes)?;
        let transactions = encoded
            .iter()
            .map(|transaction| Ok(deserialize(&hex::decode(transaction)?)?))
            .collect::<Result<Vec<_>>>()?;
        Ok(Self {
            transactions,
            operations_per_request,
        })
    }

    pub(super) fn validate(&self, canonical: &[Transaction]) -> Result<()> {
        ensure!(!self.transactions.is_empty() && !canonical.is_empty());
        let mut expected = Vec::new();
        for transaction in canonical {
            let decoded =
                filter_map((0, transaction.clone())).context("canonical reveal missing")?;
            ensure!(decoded.inputs.len() == 1);
            let input = &decoded.inputs[0];
            ensure!(input.insts.aggregate.is_none() && input.insts.ops.len() == 2);
            expected.extend(
                input
                    .insts
                    .ops
                    .iter()
                    .map(|op| (input.x_only_pubkey, op.clone())),
            );
        }
        let mut actual = Vec::new();
        for transaction in &self.transactions {
            let decoded =
                filter_map((0, transaction.clone())).context("simulation reveal missing")?;
            ensure!(decoded.inputs.len() == 1);
            let input = &decoded.inputs[0];
            ensure!(
                input.insts.aggregate.is_none()
                    && input.insts.ops.len() == self.operations_per_request
            );
            actual.extend(
                input
                    .insts
                    .ops
                    .iter()
                    .map(|op| (input.x_only_pubkey, op.clone())),
            );
        }
        ensure!(
            actual == expected,
            "simulation signer or operation mix differs"
        );
        Ok(())
    }

    pub(super) async fn execute(&self, trial: &mut Reactor<RuntimeExecutor>) -> Result<()> {
        let before = database_projection(&trial.db_conn()).await?;
        let height = trial.runtime.storage.height;
        let tip = (trial.last_height, trial.last_hash);
        ensure!(!trial.runtime.simulating);
        for (request_index, transaction) in self.transactions.iter().enumerate() {
            let tx = filter_map((0, transaction.clone())).context("simulation reveal missing")?;
            let mut previous = None;
            for _ in 0..2 {
                let results = trial.simulate(tx.clone()).await?;
                ensure!(
                    database_projection(&trial.db_conn()).await? == before,
                    "configured simulation persisted state, usage, fees or receipts"
                );
                ensure!(
                    !trial.runtime.simulating
                        && trial.runtime.storage.height == height
                        && (trial.last_height, trial.last_hash) == tip,
                    "configured simulation left speculative reactor context"
                );
                ensure!(results.len() == self.operations_per_request);
                for (index, result) in results.iter().enumerate() {
                    ensure!(
                        result.op().is_some(),
                        "simulation rejected a fixture operation"
                    );
                    let row = result
                        .result()
                        .context("simulation omitted a paid result")?;
                    let slot = (request_index * self.operations_per_request + index) % 20;
                    let failed = matches!(slot, 11 | 12);
                    ensure!(
                        row.height == SMOKE_HEIGHT
                            && row.input_index == Some(0)
                            && row.op_index == Some(u32::try_from(index)?)
                            && row.txid.as_deref() == Some(tx.txid.to_string().as_str())
                            && row.gas > 0
                            && row.gas <= GAS_LIMIT
                            && row.status
                                == if failed {
                                    OpStatus::ContractErr
                                } else {
                                    OpStatus::Ok
                                },
                        "configured simulation outcome or position differs at request {request_index}, op {index}"
                    );
                    // ContractErr is a returned WIT result. Only execution failures
                    // populate simulate's separate error_message field.
                    ensure!(
                        result.error_message().is_none(),
                        "configured simulation unexpectedly failed execution at request {request_index}, op {index}: {result:?}"
                    );
                    if failed {
                        ensure!(
                            row.value.as_deref()
                                == Some("err(message(\"deliberate failure after write\"))"),
                            "configured simulation returned a different contract error"
                        );
                    }
                }
                if let Some(previous) = &previous {
                    ensure!(
                        &results == previous,
                        "repeated configured simulation differs"
                    );
                }
                previous = Some(results);
            }
        }
        eprintln!(
            "workload_simulations={}",
            json!({
                "requests": self.transactions.len(),
                "operations_per_request": self.operations_per_request,
                "repetitions": 2,
                "input_sha256": hex::encode(Sha256::digest(self.bytes()?)),
                "scope": "sequential rollback correctness before canonical execution, no arrival timing",
            })
        );
        Ok(())
    }
}
