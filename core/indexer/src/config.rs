use std::path::PathBuf;

use bitcoin::Network;
use clap::Parser;
use serde::{Deserialize, Serialize};

use crate::logging;

#[derive(Debug, Clone, Serialize, Deserialize, Parser)]
#[clap(
    author = "Unspendable Labs",
    version = "0.1.0",
    about = "Kontor",
    long_about = r#"Kontor is a Bitcoin Layer 2"#
)]
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

    #[clap(
        long,
        env = "DATA_DIR",
        help = "Directory path for Kontor data, certs, database, etc"
    )]
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

    #[clap(
        long,
        env = "USE_LOCAL_REGTEST",
        help = "Whether or not to use a local regtest",
        default_value = "false"
    )]
    pub use_local_regtest: bool,
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
            api_port: 0,
            data_dir: "will be set".into(),
            starting_block_height: 1,
            use_local_regtest: false,
        }
    }

    pub fn should_use_tls(&self) -> bool {
        let cert_path = self.data_dir.join("cert.pem");
        let key_path = self.data_dir.join("key.pem");
        cert_path.exists() && key_path.exists()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, Parser)]
pub struct TestConfig {
    #[clap(
        long,
        env = "TESTNET_BITCOIN_RPC_URL",
        help = "URL of the Bitcoin RPC server (e.g., http://localhost:8332)"
    )]
    pub bitcoin_rpc_url: String,

    #[clap(
        long,
        env = "TESTNET_BITCOIN_RPC_USER",
        help = "User for Bitcoin RPC authentication"
    )]
    pub bitcoin_rpc_user: String,

    #[clap(
        long,
        env = "TESTNET_BITCOIN_RPC_PASSWORD",
        help = "Password for Bitcoin RPC authentication"
    )]
    pub bitcoin_rpc_password: String,
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
