use std::{path::Path, time::Duration};

use anyhow::{Result, bail};
use bitcoin::{
    Address, Network, XOnlyPublicKey,
    key::{Keypair, Secp256k1, rand},
};
use clap::Parser;
use indexer::{
    api,
    bitcoin_client::{self, client::RegtestRpc},
    config::Config,
    logging,
    retry::retry_simple,
};
use tempfile::TempDir;
use tokio::{
    fs,
    io::AsyncWriteExt,
    process::{Child, Command},
    time::sleep,
};

const REGTEST_CONF: &str = r#"
regtest=1
rpcuser=rpc
rpcpassword=rpc
server=1
txindex=1
prune=0
dbcache=4000
zmqpubsequence=tcp://127.0.0.1:28332
zmqpubsequencehwm=0
zmqpubrawtx=tcp://127.0.0.1:28332
zmqpubrawtxhwm=0
"#;

async fn create_bitcoin_conf(data_dir: &Path) -> Result<()> {
    let mut f = fs::File::create(data_dir.join("bitcoin.conf")).await?;
    f.write_all(REGTEST_CONF.as_bytes()).await?;
    Ok(())
}

async fn run_bitcoin(data_dir: &Path) -> Result<(Child, bitcoin_client::Client)> {
    create_bitcoin_conf(data_dir).await?;
    let process = Command::new("/home/quorra/bitcoin/build/bin/bitcoind")
        .arg(format!("-datadir={}", data_dir.to_string_lossy()))
        .spawn()?;
    let client = bitcoin_client::Client::new_from_config(&Config::try_parse()?)?;
    retry_simple(async || {
        let i = client.get_blockchain_info().await?;
        if i.chain != Network::Regtest {
            bail!("Network not regtest");
        }
        Ok(())
    })
    .await?;
    Ok((process, client))
}

async fn run_kontor(data_dir: &Path) -> Result<(Child, api::client::Client)> {
    let process = Command::new("../target/debug/kontor")
        .arg("--data-dir")
        .arg(data_dir.to_string_lossy().into_owned())
        .spawn()?;
    let client = api::client::Client::new_from_config(&Config::try_parse()?)?;
    retry_simple(async || {
        let i = client.index().await?;
        if !i.available {
            bail!("Not available");
        }
        Ok(())
    })
    .await?;
    Ok((process, client))
}

fn generate_taproot_address() -> (Address, XOnlyPublicKey) {
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut rand::thread_rng());
    let (x_only_public_key, _parity) = keypair.x_only_public_key();
    (
        Address::p2tr(&secp, x_only_public_key, None, Network::Regtest),
        x_only_public_key,
    )
}

pub struct Identity {
    pub name: String,
    pub address: Address,
    pub x_only_public_key: XOnlyPublicKey,
}

impl Identity {
    pub fn new(name: &str) -> Self {
        let (address, x_only_public_key) = generate_taproot_address();
        Self {
            name: name.to_string(),
            address,
            x_only_public_key,
        }
    }
}

#[tokio::test]
#[ignore]
async fn test_regtest() -> Result<()> {
    logging::setup();
    let temp_bitcoin_data_dir = TempDir::new()?;
    let temp_kontor_data_dir = TempDir::new()?;
    let (mut bitcoin, bitcoin_client) = run_bitcoin(temp_bitcoin_data_dir.path()).await?;
    let (mut kontor, kontor_client) = run_kontor(temp_kontor_data_dir.path()).await?;

    let alice = Identity::new("alice");

    bitcoin_client
        .generate_to_address(1, &alice.address.to_string())
        .await?;

    sleep(Duration::from_secs(5)).await;

    kontor_client.stop().await?;
    kontor.wait().await?;
    bitcoin_client.stop().await?;
    bitcoin.wait().await?;
    Ok(())
}
