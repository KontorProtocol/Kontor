use std::path::Path;

use anyhow::Result;
use clap::Parser;
use indexer::{api, bitcoin_client, config::Config, logging, retry::retry_simple};
use tempfile::TempDir;
use tokio::{
    fs,
    io::AsyncWriteExt,
    process::{Child, Command},
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
    let i = retry_simple(|| client.get_blockchain_info()).await?;
    assert_eq!(i.chain, bitcoin::Network::Regtest);
    Ok((process, client))
}

async fn run_kontor(data_dir: &Path) -> Result<(Child, api::client::Client)> {
    let process = Command::new("../target/debug/kontor")
        .arg("--data-dir")
        .arg(data_dir.to_string_lossy().into_owned())
        .spawn()?;
    let client = api::client::Client::new_from_config(&Config::try_parse()?)?;
    let i = retry_simple(|| client.index()).await?;
    assert!(i.available);
    Ok((process, client))
}

#[tokio::test]
#[ignore]
async fn test_regtest() -> Result<()> {
    logging::setup();
    let temp_bitcoin_data_dir = TempDir::new()?;
    let temp_kontor_data_dir = TempDir::new()?;
    let (mut bitcoin, bitcoin_client) = run_bitcoin(temp_bitcoin_data_dir.path()).await?;
    let (mut kontor, kontor_client) = run_kontor(temp_kontor_data_dir.path()).await?;

    kontor_client.stop().await?;
    kontor.wait().await?;
    bitcoin_client.stop().await?;
    bitcoin.wait().await?;
    Ok(())
}
