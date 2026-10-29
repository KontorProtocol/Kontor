use bitcoin::{Transaction, Txid};

use crate::consensus::{Height, Value};

#[derive(Clone)]
pub struct DeferredDecision {
    pub consensus_height: Height,
    pub value: Value,
    pub certificate: Vec<u8>,
    /// The txid list as DECIDED, retained when a rollback exclusion has narrowed
    /// `value` to the subset this node will actually execute.
    ///
    /// `batch_txids` must record what CONSENSUS decided, not what we ran: a peer
    /// syncing this height re-derives the exclusions itself by applying the same
    /// deadline rules, so it needs the full decided content. Recording the narrowed
    /// list would serve a value that no longer matches its own certificate.
    ///
    /// `None` when nothing was excluded, i.e. the two are the same list.
    ///
    /// Holds the BODIES, not just the txids. An excluded transaction never
    /// confirmed, so it exists in no mempool and no block — this decision is the
    /// only place its body still exists, and dropping it makes the height
    /// unresolvable for every syncing peer.
    pub certified_txs: Option<Vec<Transaction>>,
}

impl DeferredDecision {
    /// The bodies this decision can still serve to a syncing peer.
    ///
    /// An EXCLUDED transaction is the one a peer cannot obtain any other way — it
    /// never confirmed, so it is in nobody's mempool and bitcoind has never heard of
    /// it — which makes this the set that has to be persisted, not the executed one.
    pub fn decided_txs(&self) -> Vec<Transaction> {
        match &self.certified_txs {
            Some(decided) => decided.clone(),
            None => self.value.batch_raw_txs(),
        }
    }

    /// The txid list as DECIDED — what `batch_txids` must record (I4).
    pub fn decided_txids(&self) -> Vec<Txid> {
        match &self.certified_txs {
            Some(decided) => decided.iter().map(|t| t.compute_txid()).collect(),
            None => self.value.batch_txids(),
        }
    }
}
