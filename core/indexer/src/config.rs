use std::path::PathBuf;

use clap::Parser;
use serde::{Deserialize, Serialize};

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
        default_value = "tcp://localhost:28332"
    )]
    pub zmq_address: String,

    #[clap(
        long,
        env = "API_PORT",
        help = "Port number for the API server (e.g., 8080)",
        default_value = "8443"
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
        default_value = "894000"
    )]
    pub starting_block_height: u64,
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

    #[clap(
        long,
        env = "SEGWIT_SELLER_KEY_PATH",
        help = "Full path to the seller's key file"
    )]
    pub seller_key_path: PathBuf,

    #[clap(
        long,
        env = "SEGWIT_BUYER_KEY_PATH",
        help = "Full path to the buyer's key file"
    )]
    pub buyer_key_path: PathBuf,

    #[clap(
        long,
        env = "TAPROOT_KEY_PATH",
        help = "Full path to the taproot key file"
    )]
    pub taproot_key_path: PathBuf,
}
