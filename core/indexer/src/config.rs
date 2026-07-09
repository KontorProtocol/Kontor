use std::path::PathBuf;

use bitcoin::Network;
use clap::Parser;
use serde::{Deserialize, Serialize};

use crate::consensus::signing::ConsensusMode;
use crate::logging;

/// Default per-call gas budget for read-only `/view` queries. Generous out of the
/// box (operators raise it further on read/archive nodes); independent of the fixed
/// system core-call budget, which is effectively unmetered.
pub const DEFAULT_VIEW_GAS_LIMIT: u64 = 1_000_000;

#[derive(Debug, Clone, Serialize, Deserialize, Parser)]
pub struct Config {
    #[clap(
        long,
        env = "LOG_FORMAT",
        help = "Log format (plain, json)",
        default_value = "plain"
    )]
    pub log_format: logging::Format,

    #[clap(
        long,
        env = "BITCOIN_RPC_URL",
        help = "URL of the Bitcoin RPC server (e.g., http://localhost:8332)"
    )]
    pub bitcoin_rpc_url: String,

    #[clap(
        long,
        env = "BITCOIN_RPC_USER",
        help = "User for Bitcoin RPC authentication"
    )]
    pub bitcoin_rpc_user: String,

    #[clap(
        long,
        env = "BITCOIN_RPC_PASSWORD",
        help = "Password for Bitcoin RPC authentication"
    )]
    pub bitcoin_rpc_password: String,

    #[clap(
        long,
        env = "ZMQ_ADDRESS",
        help = "ZMQ address for sequence notifications (e.g., tcp://localhost:28332)",
        default_value = "tcp://127.0.0.1:28332"
    )]
    pub zmq_address: String,

    #[clap(
        long,
        env = "API_PORT",
        help = "Port number for the API server (e.g., 8080)",
        default_value = "9333"
    )]
    pub api_port: u16,

    #[clap(long, env = "DATA_DIR", help = "Directory path for Kontor data")]
    pub data_dir: PathBuf,

    #[clap(
        long,
        env = "STARTING_BLOCK_HEIGHT",
        help = "Block height to begin parsing at (e.g. 850000)",
        default_value = "921300"
    )]
    pub starting_block_height: u64,

    #[clap(
        long,
        env = "NETWORK",
        help = "Network for Bitcoin RPC authentication",
        default_value = "bitcoin"
    )]
    pub network: bitcoin::Network,

    // --- Consensus ---
    #[clap(
        long,
        env = "CONSENSUS_MODE",
        default_value = "follower",
        help = "validator (signs votes/proposals) | follower (sync-only)"
    )]
    pub consensus_mode: ConsensusMode,

    #[clap(
        long,
        env = "CONSENSUS_PRIVATE_KEY",
        help = "Hex-encoded Ed25519 private key for consensus participation (validator mode only)"
    )]
    pub consensus_private_key: Option<String>,

    /// Path to a file containing the hex-encoded Ed25519 private key.
    /// Standard `_FILE` convention for k8s-mounted secrets — pairs with an
    /// init container that derives the per-pod key from a master seed and
    /// writes it to a shared volume. Mutually exclusive with
    /// `--consensus-private-key`; if both are set, the daemon refuses to
    /// start so a misconfiguration can't silently pick the wrong source.
    #[clap(
        long,
        env = "CONSENSUS_PRIVATE_KEY_FILE",
        help = "Path to a file containing the hex-encoded Ed25519 private key (alternative to --consensus-private-key for k8s secret mounts)"
    )]
    pub consensus_private_key_file: Option<PathBuf>,

    #[clap(
        long,
        env = "CONSENSUS_LISTEN_ADDR",
        default_value = "/ip4/127.0.0.1/tcp/26656",
        help = "Multiaddr for consensus P2P (e.g. /ip4/127.0.0.1/tcp/26656)"
    )]
    pub consensus_listen_addr: String,

    #[clap(
        long,
        env = "CONSENSUS_PEERS",
        help = "Comma-separated multiaddrs of persistent consensus peers",
        value_delimiter = ','
    )]
    pub consensus_peers: Vec<String>,

    #[clap(
        long,
        env = "GENESIS_FILE",
        help = "Path to genesis JSON file containing the initial validator set"
    )]
    pub genesis_file: PathBuf,

    /// Hard deadline for kontor's empty-batch fallback is 80% of this value
    /// (see `consensus_state::PendingProposal::hard_deadline`). Tuned to match
    /// the reactor's 500ms debounce; lower values fire empty batches too
    /// aggressively for kontor's Bitcoin-anchored mempool turnover. Override
    /// only if you know the debounce model and have a reason.
    #[clap(
        long,
        env = "CONSENSUS_PROPOSE_TIMEOUT_MS",
        default_value = "10000",
        help = "Consensus propose timeout in milliseconds"
    )]
    pub consensus_propose_timeout_ms: u64,

    // --- State pruning ---
    /// Prune finalized, superseded `contract_state` versions to bound state
    /// growth. `false` = archive node: full version history retained, no GC.
    #[clap(
        long,
        env = "PRUNE",
        default_value_t = true,
        action = clap::ArgAction::Set,
        help = "Prune finalized superseded contract_state versions to bound state growth (false = archive node)"
    )]
    pub prune: bool,

    /// Blocks below the tip to retain before a `contract_state` version becomes
    /// eligible for pruning. Floored at the consensus finality window at the
    /// prune call site. Must stay ABOVE the reactor's maximum in-flight block
    /// buffer (`MAX_PENDING_BLOCKS` + the block channel capacity) plus real
    /// reorg headroom: a rollback queued behind a full buffer is processed only
    /// after the buffered blocks are decided, so `last_height` can sprint that
    /// far past the fork before the rollback lands — the retained history is
    /// what lets that self-heal instead of tripping the deep-reorg bail.
    /// Default 288 ≈ two days of Bitcoin blocks: 160 of buffer sprint + 128 of
    /// genuine reorg headroom.
    #[clap(
        long,
        env = "PRUNE_RETAIN_BLOCKS",
        default_value = "288",
        help = "Blocks below tip to retain before pruning (default 288 ≈ 2 days of Bitcoin blocks)"
    )]
    pub prune_retain_blocks: u64,

    // --- Read serving ---
    /// Per-call gas budget for read-only `/view` queries served by this node's
    /// runtime pool. NON-consensus: a `/view` read never enters a block, so nodes
    /// may set different caps without diverging. Lean validators keep the default;
    /// a read/archive node serving heavy queries (leaderboards, large scans) raises
    /// it. Applies ONLY to the read-only pool's runtimes — never to a view
    /// cross-called inside a consensus procedure, which keeps the fixed consensus
    /// limit (the pool builds separate `Runtime` instances from the reactor's).
    #[clap(
        long,
        env = "VIEW_GAS_LIMIT",
        default_value_t = DEFAULT_VIEW_GAS_LIMIT,
        help = "Per-call gas budget for read-only /view queries (default 1000000; raise on read/archive nodes)"
    )]
    pub view_gas_limit: u64,
}

impl Config {
    pub fn new_na() -> Self {
        let na = "n/a".to_string();
        Self {
            log_format: logging::Format::Plain,
            network: Network::Bitcoin,
            bitcoin_rpc_url: na.clone(),
            bitcoin_rpc_user: na.clone(),
            bitcoin_rpc_password: na.clone(),
            zmq_address: na,
            api_port: 9333,
            data_dir: "will be set".into(),
            starting_block_height: 1,
            consensus_mode: ConsensusMode::Follower,
            consensus_private_key: None,
            consensus_private_key_file: None,
            consensus_listen_addr: "/ip4/127.0.0.1/tcp/26656".to_string(),
            consensus_peers: Vec::new(),
            genesis_file: PathBuf::new(),
            consensus_propose_timeout_ms: 10000,
            prune: true,
            prune_retain_blocks: 288,
            view_gas_limit: DEFAULT_VIEW_GAS_LIMIT,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisValidatorConfig {
    pub x_only_pubkey: String,
    pub stake: String,
    pub ed25519_pubkey: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GenesisConfig {
    pub validators: Vec<GenesisValidatorConfig>,
}

impl GenesisConfig {
    pub fn load(path: &std::path::Path) -> anyhow::Result<Self> {
        let contents = std::fs::read_to_string(path)?;
        Ok(serde_json::from_str(&contents)?)
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegtestConfig {
    pub bitcoin_rpc_url: String,
    pub bitcoin_rpc_user: String,
    pub bitcoin_rpc_password: String,
}

impl Default for RegtestConfig {
    fn default() -> Self {
        Self {
            bitcoin_rpc_url: "http://127.0.0.1:18443".into(),
            bitcoin_rpc_user: "rpc".into(),
            bitcoin_rpc_password: "rpc".into(),
        }
    }
}
