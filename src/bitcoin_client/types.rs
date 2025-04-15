use std::fmt;

use bitcoin::{Amount, Network, Txid};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Serialize)]
pub struct Request {
    pub jsonrpc: String,
    pub id: String,
    pub method: String,
    pub params: Vec<Value>,
}

#[derive(Deserialize, Debug)]
pub struct Response {
    pub result: Option<Value>,
    pub error: Option<Value>,
    pub id: String,
}

fn deserialize_bip70_network<'de, D>(deserializer: D) -> Result<Network, D::Error>
where
    D: serde::Deserializer<'de>,
{
    struct NetworkVisitor;
    impl serde::de::Visitor<'_> for NetworkVisitor {
        type Value = Network;

        fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Self::Value, E> {
            Network::from_core_arg(s).map_err(|_| {
                E::invalid_value(
                    serde::de::Unexpected::Str(s),
                    &"bitcoin network encoded as a string",
                )
            })
        }

        fn expecting(&self, formatter: &mut fmt::Formatter) -> fmt::Result {
            write!(formatter, "bitcoin network encoded as a string")
        }
    }

    deserializer.deserialize_str(NetworkVisitor)
}

// https://github.com/rust-bitcoin/rust-bitcoincore-rpc/blob/master/json/src/lib.rs#L1016C1-L1058C2
// removed some unused properties that would require copying more types and functions
#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct GetBlockchainInfoResult {
    /// Current network name as defined in BIP70 (main, test, signet, regtest)
    #[serde(deserialize_with = "deserialize_bip70_network")]
    pub chain: Network,
    /// The current number of blocks processed in the server
    pub blocks: u64,
    /// The current number of headers we have validated
    pub headers: u64,
    /// The current difficulty
    pub difficulty: f64,
    /// Median time for the current best block
    #[serde(rename = "mediantime")]
    pub median_time: u64,
    /// Estimate of verification progress [0..1]
    #[serde(rename = "verificationprogress")]
    pub verification_progress: f64,
    /// Estimate of whether this node is in Initial Block Download mode
    #[serde(rename = "initialblockdownload")]
    pub initial_block_download: bool,
    /// The estimated size of the block and undo files on disk
    pub size_on_disk: u64,
    /// If the blocks are subject to pruning
    pub pruned: bool,
    /// Lowest-height complete block stored (only present if pruning is enabled)
    #[serde(rename = "pruneheight")]
    pub prune_height: Option<u64>,
    /// Whether automatic pruning is enabled (only present if pruning is enabled)
    pub automatic_pruning: Option<bool>,
    /// The target size used by pruning (only present if automatic pruning is enabled)
    pub prune_target_size: Option<u64>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TestMempoolAcceptResult {
    pub txid: Txid,
    pub allowed: bool,
    #[serde(rename = "reject-reason")]
    pub reject_reason: Option<String>,
    pub vsize: Option<u64>,
    pub fees: Option<TestMempoolAcceptResultFees>,
}

#[derive(Clone, PartialEq, Eq, Debug, Deserialize, Serialize)]
pub struct TestMempoolAcceptResultFees {
    #[serde(with = "bitcoin::amount::serde::as_btc")]
    pub base: Amount,
}
