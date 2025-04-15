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
        env = "ZMQ_PUB_SEQUENCE_ADDRESS",
        help = "ZMQ address for sequence notifications (e.g., tcp://localhost:28332)"
    )]
    pub zmq_pub_sequence_address: String,

    #[clap(
        long,
        env = "API_PORT",
        help = "Port number for the API server (e.g., 8080)"
    )]
    pub api_port: u16,

    #[clap(
        long,
        env = "CERT_DIR",
        help = "Directory path for TLS cert.pem and key.pem files (e.g., /var/lib/myapp/certs)"
    )]
    pub cert_dir: PathBuf,

    #[clap(
        long,
        env = "DATABASE_DIR",
        help = "Directory path for the database (e.g., /var/lib/myapp/db)"
    )]
    pub database_dir: PathBuf,

    #[clap(
        long,
        env = "STARTING_BLOCK_HEIGHT",
        help = "Block height to begin parsing at (e.g. 850000)",
        default_value = "887000"
    )]
    pub starting_block_height: u64,
    #[clap(
        long,
        env = "SELLER_KEY_PATH",
        help = "Full path to the seller's key file"
    )]
    pub seller_key_path: PathBuf,

    #[clap(
        long,
        env = "BUYER_KEY_PATH",
        help = "Full path to the buyer's key file"
    )]
    pub buyer_key_path: PathBuf,
}
