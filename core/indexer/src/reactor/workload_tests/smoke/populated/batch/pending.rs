use std::collections::btree_map::Entry as MapEntry;
use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, ensure};
use indexer_types::{Block, ResultRow};
use serde::{Deserialize, Serialize};

use super::{BatchProof, TransactionProof, receipts};
use crate::consensus::FINALITY_WINDOW;
use crate::reactor::Reactor;
use crate::reactor::executor::RuntimeExecutor;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Confirmation {
    pub(crate) txid: String,
    pub(crate) height: u64,
    pub(crate) filtered_index: u32,
    pub(crate) bitcoin_index: u32,
}

#[derive(Clone)]
struct Entry {
    proof: TransactionProof,
    confirmation: Confirmation,
}

#[derive(Clone)]
pub(crate) struct Pending {
    entries: BTreeMap<String, Entry>,
    seen: BTreeSet<String>,
    height: u64,
}

impl Pending {
    pub(crate) fn new(height: u64) -> Self {
        Self {
            entries: BTreeMap::new(),
            seen: BTreeSet::new(),
            height,
        }
    }

    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }

    pub(crate) fn record(
        &mut self,
        batch: BatchProof,
        confirmations: Vec<Confirmation>,
    ) -> Result<()> {
        ensure!(
            batch.anchor_height == self.height,
            "pending batch anchor differs from canonical tip"
        );
        ensure!(
            batch.transactions.len() == confirmations.len(),
            "pending confirmation plan length differs"
        );
        let deadline = batch
            .anchor_height
            .checked_add(FINALITY_WINDOW)
            .context("pending deadline overflow")?;
        let mut additions = BTreeMap::new();
        let mut filtered: BTreeSet<_> = self
            .entries
            .values()
            .map(|entry| (entry.confirmation.height, entry.confirmation.filtered_index))
            .collect();
        let mut raw: BTreeSet<_> = self
            .entries
            .values()
            .map(|entry| (entry.confirmation.height, entry.confirmation.bitcoin_index))
            .collect();
        for (proof, confirmation) in batch.transactions.into_iter().zip(confirmations) {
            ensure!(
                proof.transaction.txid == confirmation.txid,
                "pending confirmation plan changed transaction"
            );
            ensure!(
                !self.seen.contains(&confirmation.txid)
                    && !additions.contains_key(&confirmation.txid),
                "duplicate pending transaction"
            );
            ensure!(
                confirmation.height > self.height && confirmation.height <= deadline,
                "pending confirmation outside finality window"
            );
            ensure!(
                confirmation.bitcoin_index > 0,
                "pending confirmation names coinbase"
            );
            ensure!(
                filtered.insert((confirmation.height, confirmation.filtered_index))
                    && raw.insert((confirmation.height, confirmation.bitcoin_index)),
                "pending confirmation positions collide"
            );
            additions.insert(
                confirmation.txid.clone(),
                Entry {
                    proof,
                    confirmation,
                },
            );
        }
        self.seen.extend(additions.keys().cloned());
        self.entries.extend(additions);
        Ok(())
    }

    pub(crate) async fn check_unconfirmed(&self, trial: &Reactor<RuntimeExecutor>) -> Result<()> {
        ensure!(
            trial.last_height == self.height,
            "pending observation height changed"
        );
        let conn = trial.db_conn();
        let mut anchors = BTreeMap::new();
        for entry in self.entries.values() {
            let anchor = entry.proof.transaction.height;
            if let MapEntry::Vacant(slot) = anchors.entry(anchor) {
                slot.insert(receipts(&conn, anchor).await?);
            }
            entry.proof.check(&conn, &anchors[&anchor], None).await?;
        }
        Ok(())
    }

    pub(crate) async fn check_block(
        &mut self,
        trial: &Reactor<RuntimeExecutor>,
        block: &Block,
    ) -> Result<Vec<ResultRow>> {
        ensure!(
            block.height
                == self
                    .height
                    .checked_add(1)
                    .context("pending height overflow")?,
            "pending block height is not consecutive"
        );
        ensure!(
            trial.last_height == block.height && trial.last_hash == Some(block.hash),
            "pending block differs from canonical tip"
        );
        let mut positions = BTreeMap::new();
        let mut raw_positions = BTreeSet::new();
        for (index, transaction) in block.transactions.iter().enumerate() {
            let txid = transaction.txid.to_string();
            ensure!(
                positions
                    .insert(txid.clone(), (u32::try_from(index)?, transaction.index))
                    .is_none(),
                "duplicate confirmation in block"
            );
            ensure!(
                transaction.index > 0 && raw_positions.insert(transaction.index),
                "duplicate or coinbase Bitcoin position"
            );
            ensure!(
                !self.seen.contains(&txid) || self.entries.contains_key(&txid),
                "batch transaction confirmed twice"
            );
        }
        let conn = trial.db_conn();
        let mut anchors = BTreeMap::new();
        let mut confirmed = Vec::new();
        let mut checked = Vec::new();
        for (txid, entry) in &self.entries {
            let plan = &entry.confirmation;
            ensure!(
                plan.height >= block.height,
                "pending confirmation omitted at planned height"
            );
            let expected = if plan.height == block.height {
                ensure!(
                    positions.get(txid) == Some(&(plan.filtered_index, plan.bitcoin_index)),
                    "pending confirmation missing or at wrong position"
                );
                confirmed.push(txid.clone());
                Some((block.height, plan.filtered_index, plan.bitcoin_index))
            } else {
                ensure!(
                    !positions.contains_key(txid),
                    "pending transaction confirmed before planned height"
                );
                ensure!(
                    block.height
                        < entry
                            .proof
                            .transaction
                            .height
                            .checked_add(FINALITY_WINDOW)
                            .context("pending deadline overflow")?,
                    "pending transaction missed finality deadline"
                );
                None
            };
            let anchor = entry.proof.transaction.height;
            if let MapEntry::Vacant(slot) = anchors.entry(anchor) {
                slot.insert(receipts(&conn, anchor).await?);
            }
            let paid = entry
                .proof
                .check(&conn, &anchors[&anchor], expected)
                .await?;
            if expected.is_some() {
                checked.extend(paid);
            }
        }
        // Failed observations leave the obligation set intact for diagnosis.
        for txid in confirmed {
            self.entries.remove(&txid);
        }
        self.height = block.height;
        Ok(checked)
    }
}

mod tests;
