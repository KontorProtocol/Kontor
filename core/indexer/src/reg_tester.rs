use std::{path::Path, str::FromStr};

use crate::{
    api::{
        client::Client as KontorClient, compose::ComposeAddressQuery, ws::Response,
        ws_client::WebSocketClient,
    },
    bitcoin_client::{self, Client as BitcoinClient, client::RegtestRpc},
    config::{Config, RegtestConfig},
    database::types::ContractResultId,
    reactor::{results::ResultEvent, types::Inst},
    retry::retry_simple,
    runtime::{ContractAddress, serialize_cbor, wit::Signer},
    test_utils,
};
use anyhow::{Context, Result, anyhow, bail};
use bitcoin::{
    Address, Amount, BlockHash, Network, OutPoint, Transaction, TxIn, TxOut, Txid, XOnlyPublicKey,
    absolute::LockTime,
    consensus::serialize as serialize_tx,
    key::{Keypair, Secp256k1, rand},
    taproot::TaprootBuilder,
    transaction::Version,
};
use clap::Parser;
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
    let process = Command::new("bitcoind")
        .arg(format!("-datadir={}", data_dir.to_string_lossy()))
        .spawn()?;
    let client = bitcoin_client::Client::new_from_config(&RegtestConfig::default())?;
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
    let config = Config::try_parse()?;
    tokio::fs::copy(config.data_dir.join("cert.pem"), data_dir.join("cert.pem")).await?;
    tokio::fs::copy(config.data_dir.join("key.pem"), data_dir.join("key.pem")).await?;
    let process = Command::new("../target/debug/kontor")
        .arg("--data-dir")
        .arg(data_dir.to_string_lossy().into_owned())
        .arg("--network")
        .arg("regtest")
        .arg("--starting-block-height")
        .arg("102")
        .arg("--use-local-regtest")
        .spawn()?;
    let client = KontorClient::new_from_config(&config)?;
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

pub fn generate_taproot_address() -> (Address, Keypair) {
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut rand::thread_rng());
    let (x_only_public_key, ..) = keypair.x_only_public_key();
    (
        Address::p2tr(&secp, x_only_public_key, None, Network::Regtest),
        keypair,
    )
}

fn outpoint_to_utxo_id(outpoint: &OutPoint) -> String {
    format!("{}:{}", outpoint.txid, outpoint.vout)
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub address: Address,
    pub keypair: Keypair,
    pub next_funding_utxo: (OutPoint, TxOut),
}

impl Identity {
    pub fn x_only_public_key(&self) -> XOnlyPublicKey {
        self.keypair.x_only_public_key().0
    }

    pub fn signer(&self) -> Signer {
        Signer::XOnlyPubKey(self.x_only_public_key().to_string())
    }
}

pub struct RegTester {
    pub bitcoin_client: BitcoinClient,
    kontor_client: KontorClient,
    ws_client: WebSocketClient,
    identity: Identity,
    pub height: i64,
}

impl RegTester {
    pub async fn setup() -> Result<(
        TempDir,
        Child,
        BitcoinClient,
        TempDir,
        Child,
        KontorClient,
        Identity,
    )> {
        let bitcoin_data_dir = TempDir::new()?;
        let kontor_data_dir = TempDir::new()?;
        let (bitcoin_child, bitcoin_client) = run_bitcoin(bitcoin_data_dir.path()).await?;
        let (address, keypair) = generate_taproot_address();
        let block_hashes = bitcoin_client
            .generate_to_address(101, &address.to_string())
            .await?;
        let block_hash = BlockHash::from_str(
            block_hashes
                .first()
                .ok_or(anyhow!("One block not created"))?,
        )?;
        let block = bitcoin_client.get_block(&block_hash).await?;
        let out_point = OutPoint {
            txid: block.txdata[0].compute_txid(),
            vout: 0,
        };
        let tx_out = block.txdata[0].output[0].clone();
        let identity = Identity {
            address,
            keypair,
            next_funding_utxo: (out_point, tx_out),
        };
        let (kontor_child, kontor_client) = run_kontor(kontor_data_dir.path()).await?;
        Ok((
            bitcoin_data_dir,
            bitcoin_child,
            bitcoin_client,
            kontor_data_dir,
            kontor_child,
            kontor_client,
            identity,
        ))
    }

    pub async fn teardown(
        bitcoin_client: BitcoinClient,
        mut bitcoin_child: Child,
        kontor_client: KontorClient,
        mut kontor_child: Child,
    ) -> Result<()> {
        kontor_client.stop().await?;
        kontor_child.wait().await?;
        bitcoin_client.stop().await?;
        bitcoin_child.wait().await?;
        Ok(())
    }

    pub async fn new(
        identity: Identity,
        bitcoin_client: BitcoinClient,
        kontor_client: KontorClient,
    ) -> Result<Self> {
        let ws_client = WebSocketClient::new().await?;
        Ok(Self {
            identity,
            ws_client,
            bitcoin_client,
            kontor_client,
            height: 101,
        })
    }

    async fn mempool_accept(&self, raw_txs: &[String]) -> Result<()> {
        let result = self.bitcoin_client.test_mempool_accept(raw_txs).await?;
        for (i, r) in result.iter().enumerate() {
            if !r.allowed {
                bail!("Transaction rejected: {} {:?}", i, r.reject_reason);
            }
        }
        Ok(())
    }

    pub async fn instruction(&mut self, ident: &mut Identity, inst: Inst) -> Result<String> {
        let script_data = serialize_cbor(&inst)?;
        let mut compose_res = self
            .kontor_client
            .compose(ComposeAddressQuery {
                address: ident.address.to_string(),
                x_only_public_key: ident.x_only_public_key().to_string(),
                funding_utxo_ids: outpoint_to_utxo_id(&ident.next_funding_utxo.0),
                script_data,
            })
            .await?;
        let secp = Secp256k1::new();
        test_utils::sign_key_spend(
            &secp,
            &mut compose_res.commit_transaction,
            std::slice::from_ref(&ident.next_funding_utxo.1),
            &ident.keypair,
            0,
            None,
        )?;
        let tap_script = &compose_res.per_participant[0].commit.tap_script;
        let taproot_spend_info = TaprootBuilder::new()
            .add_leaf(0, tap_script.clone())
            .map_err(|e| anyhow!("Failed to add leaf: {}", e))?
            .finalize(&secp, ident.x_only_public_key())
            .map_err(|e| anyhow!("Failed to finalize Taproot tree: {:?}", e))?;
        test_utils::sign_script_spend(
            &secp,
            &taproot_spend_info,
            &compose_res.per_participant[0].commit.tap_script,
            &mut compose_res.reveal_transaction,
            &[compose_res.commit_transaction.output[0].clone()],
            &ident.keypair,
            0,
        )?;

        let commit_tx_hex = hex::encode(serialize_tx(&compose_res.commit_transaction));
        let reveal_tx_hex = hex::encode(serialize_tx(&compose_res.reveal_transaction));

        self.mempool_accept(&[commit_tx_hex.clone(), reveal_tx_hex.clone()])
            .await?;
        let commit_txid = self
            .bitcoin_client
            .send_raw_transaction(&commit_tx_hex)
            .await?;
        let reveal_txid = compose_res.reveal_transaction.compute_txid();
        let id = ContractResultId::builder()
            .txid(reveal_txid.to_string())
            .build();
        self.ws_client
            .subscribe(&id)
            .await
            .context("Failed to subscribe to contract result")?;
        self.bitcoin_client
            .send_raw_transaction(&reveal_tx_hex)
            .await?;

        self.bitcoin_client
            .generate_to_address(1, &self.identity.address.to_string())
            .await?;
        self.height += 1;

        ident.next_funding_utxo = (
            OutPoint {
                txid: Txid::from_str(&commit_txid)?,
                vout: (compose_res.commit_transaction.output.len() - 1) as u32,
            },
            compose_res
                .commit_transaction
                .output
                .last()
                .unwrap()
                .clone(),
        );
        if let Response::Result { result, .. } = self
            .ws_client
            .next()
            .await
            .context("Failed to receive response from websocket")?
        {
            match result {
                ResultEvent::Ok { value } => Ok(value),
                ResultEvent::Err { message } => Err(anyhow!("{}", message)),
            }
        } else {
            Err(anyhow!("Unexpected response from websocket"))
        }
    }

    pub async fn identity(&mut self) -> Result<Identity> {
        let (address, keypair) = generate_taproot_address();
        let mut tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: self.identity.next_funding_utxo.0,
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(4_999_999_000),
                script_pubkey: address.script_pubkey(),
            }],
        };
        let secp = Secp256k1::new();
        test_utils::sign_key_spend(
            &secp,
            &mut tx,
            std::slice::from_ref(&self.identity.next_funding_utxo.1),
            &self.identity.keypair,
            0,
            None,
        )?;

        let raw_tx = hex::encode(serialize_tx(&tx));
        self.mempool_accept(std::slice::from_ref(&raw_tx)).await?;
        let txid = self.bitcoin_client.send_raw_transaction(&raw_tx).await?;
        self.bitcoin_client
            .generate_to_address(1, &self.identity.address.to_string())
            .await?;
        self.height += 1;
        let block_hash = self
            .bitcoin_client
            .get_block_hash((self.height - 100) as u64)
            .await?;
        let block = self.bitcoin_client.get_block(&block_hash).await?;
        self.identity.next_funding_utxo = (
            OutPoint {
                txid: block.txdata[0].compute_txid(),
                vout: 0,
            },
            block.txdata[0].output[0].clone(),
        );

        let next_funding_utxo = (
            OutPoint {
                txid: Txid::from_str(&txid)?,
                vout: 0,
            },
            tx.output[0].clone(),
        );
        Ok(Identity {
            address,
            keypair,
            next_funding_utxo,
        })
    }

    pub async fn view(&self, contract_address: &ContractAddress, expr: &str) -> Result<String> {
        let result = self.kontor_client.view(contract_address, expr).await?;
        match result {
            ResultEvent::Ok { value } => Ok(value),
            ResultEvent::Err { message } => Err(anyhow!("{}", message)),
        }
    }

    pub async fn wit(&self, contract_address: &ContractAddress) -> Result<String> {
        let response = self.kontor_client.wit(contract_address).await?;
        Ok(response.wit)
    }
}
