use std::path::PathBuf;

use bitcoin::Network;
use clap::Parser;
use serde::{Deserialize, Serialize};

use crate::consensus::signing::ConsensusMode;
use crate::logging;

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

    #[clap(
        long,
        env = "CONSENSUS_PROPOSE_TIMEOUT_MS",
        help = "Consensus propose timeout in milliseconds (default: 3000)"
    )]
    pub consensus_propose_timeout_ms: Option<u64>,
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
            consensus_propose_timeout_ms: None,
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
