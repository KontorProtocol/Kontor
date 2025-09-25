use std::path::Path;

use anyhow::{Result, bail};
use bitcoin::{
    Address, Network, XOnlyPublicKey,
    key::{Keypair, Secp256k1, rand},
};
use clap::Parser;
use indexer::{
    api::client::Client as KontorClient,
    bitcoin_client::{self, Client as BitcoinClient, client::RegtestRpc},
    config::Config,
    logging,
    retry::retry_simple,
};
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

async fn run_kontor(data_dir: &Path) -> Result<(Child, KontorClient)> {
    let process = Command::new("../target/debug/kontor")
        .arg("--data-dir")
        .arg(data_dir.to_string_lossy().into_owned())
        .spawn()?;
    let client = KontorClient::new_from_config(&Config::try_parse()?)?;
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

pub struct RegTester {
    _bitcoin_data_dir: TempDir,
    bitcoin_child: Child,
    bitcoin_client: BitcoinClient,
    _kontor_data_dir: TempDir,
    kontor_child: Child,
    kontor_client: KontorClient,
    height: i64,
}

impl RegTester {
    pub async fn new() -> Result<Self> {
        let _bitcoin_data_dir = TempDir::new()?;
        let _kontor_data_dir = TempDir::new()?;
        let (bitcoin_child, bitcoin_client) = run_bitcoin(_bitcoin_data_dir.path()).await?;
        let (kontor_child, kontor_client) = run_kontor(_kontor_data_dir.path()).await?;
        Ok(Self {
            _bitcoin_data_dir,
            bitcoin_child,
            bitcoin_client,
            _kontor_data_dir,
            kontor_child,
            kontor_client,
            height: 0,
        })
    }

    pub async fn fund(&mut self, address: &str) -> Result<()> {
        self.bitcoin_client.generate_to_address(1, address).await?;
        self.height += 1;
        Ok(())
    }

    pub async fn identity(&mut self, name: &str) -> Result<Identity> {
        let identity = Identity::new(name);
        self.fund(&identity.address.to_string()).await?;
        Ok(identity)
    }

    pub async fn wait(&self) -> Result<()> {
        retry_simple(async || {
            let i = self.kontor_client.index().await?;
            if i.height != self.height {
                bail!("Not caught up");
            }
            Ok(())
        })
        .await?;
        Ok(())
    }

    pub async fn stop(&mut self) -> Result<()> {
        self.wait().await?;
        self.kontor_client.stop().await?;
        self.kontor_child.wait().await?;
        self.bitcoin_client.stop().await?;
        self.bitcoin_child.wait().await?;
        Ok(())
    }
}

async fn run_test_regtest(reg_tester: &mut RegTester) -> Result<()> {
    reg_tester.identity("alice").await?;
    Ok(())
}

#[tokio::test]
async fn test_regtest() -> Result<()> {
    logging::setup();
    let mut reg_tester = RegTester::new().await?;
    let r = run_test_regtest(&mut reg_tester).await;
    reg_tester.stop().await?;
    r
}
