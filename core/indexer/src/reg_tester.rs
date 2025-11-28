use std::{path::Path, str::FromStr, sync::Arc};

use crate::{
    api::{
        client::Client as KontorClient,
        compose::{ComposeOutputs, ComposeQuery, InstructionQuery, RevealOutputs, RevealQuery},
        handlers::{OpWithResult, ResultRow, TransactionHex, ViewResult},
        ws_client::WebSocketClient,
    },
    bitcoin_client::{
        self, Client as BitcoinClient,
        client::RegtestRpc,
        types::{GetMempoolInfoResult, TestMempoolAcceptResult},
    },
    config::RegtestConfig,
    database::types::OpResultId,
    retry::retry_simple,
    runtime::{ContractAddress, wit::Signer},
    test_utils,
};
use anyhow::{Context, Result, anyhow, bail};
use bitcoin::{
    Address, Amount, BlockHash, CompressedPublicKey, Network, OutPoint, Transaction, TxIn, TxOut,
    Txid, XOnlyPublicKey,
    absolute::LockTime,
    consensus::serialize as serialize_tx,
    key::{Keypair, PrivateKey, Secp256k1, rand},
    taproot::TaprootBuilder,
    transaction::Version,
};
use indexer_types::Inst;
use tempfile::TempDir;
use tokio::{
    fs,
    io::AsyncWriteExt,
    process::{Child, Command},
    sync::Mutex,
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

    // Check if bitcoind is in PATH
    let bitcoind_check = Command::new("which").arg("bitcoind").output().await;

    if bitcoind_check.is_err() || !bitcoind_check.unwrap().status.success() {
        bail!(
            "bitcoind not found in PATH. Regtest tests require Bitcoin Core.\n\
             See TESTING.md for details."
        );
    }

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
    let config = RegtestConfig::default();
    let program = format!("{}/../target/debug/kontor", env!("CARGO_MANIFEST_DIR"));
    let process = Command::new(program)
        .arg("--api-port")
        .arg("9333")
        .arg("--data-dir")
        .arg(data_dir.to_string_lossy().into_owned())
        .arg("--network")
        .arg("regtest")
        .arg("--starting-block-height")
        .arg("102")
        .arg("--bitcoin-rpc-url")
        .arg(config.bitcoin_rpc_url)
        .arg("--bitcoin-rpc-user")
        .arg(config.bitcoin_rpc_user)
        .arg("--bitcoin-rpc-password")
        .arg(config.bitcoin_rpc_password)
        .spawn()?;
    let client = KontorClient::new("http://localhost:9333/api")?;
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

#[derive(Debug, Clone)]
pub struct P2wpkhIdentity {
    pub address: Address,
    pub compressed_public_key: CompressedPublicKey,
    pub private_key: PrivateKey,
    pub keypair: Keypair,
    pub next_funding_utxo: (OutPoint, TxOut),
}

fn generate_random_ecdsa_key(network: Network) -> (PrivateKey, CompressedPublicKey) {
    let secp = Secp256k1::new();
    let secret_key = bitcoin::secp256k1::SecretKey::new(&mut rand::thread_rng());
    let private_key = PrivateKey::new(secret_key, network);
    let public_key = bitcoin::key::PublicKey::from_private_key(&secp, &private_key);
    let compressed_pubkey = CompressedPublicKey(public_key.inner);
    (private_key, compressed_pubkey)
}

pub struct RegTesterInner {
    pub bitcoin_client: BitcoinClient,
    kontor_client: KontorClient,
    ws_client: WebSocketClient,
    identity: Identity,
    pub height: i64,
}

pub struct InstructionResult {
    pub result: ResultRow,
    pub commit_tx_hex: String,
    pub reveal_tx_hex: String,
}

impl RegTesterInner {
    pub async fn new(
        identity: Identity,
        bitcoin_client: BitcoinClient,
        kontor_client: KontorClient,
    ) -> Result<Self> {
        let ws_client = WebSocketClient::new(9333).await?;
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

    pub async fn mempool_accept_result(
        &self,
        raw_txs: &[String],
    ) -> Result<Vec<TestMempoolAcceptResult>> {
        self.bitcoin_client
            .test_mempool_accept(raw_txs)
            .await
            .map_err(|e| anyhow!("Failed to accept transactions: {}", e))
    }
    pub async fn mempool_info(&self) -> Result<GetMempoolInfoResult> {
        let result = self.bitcoin_client.get_mempool_info().await?;
        Ok(result)
    }

    pub async fn instruction(
        &mut self,
        ident: &mut Identity,
        inst: Inst,
    ) -> Result<InstructionResult> {
        let query = ComposeQuery::builder()
            .instructions(vec![InstructionQuery {
                address: ident.address.to_string(),
                x_only_public_key: ident.x_only_public_key().to_string(),
                funding_utxo_ids: outpoint_to_utxo_id(&ident.next_funding_utxo.0),
                script_data: inst,
            }])
            .sat_per_vbyte(2)
            .build();
        let mut compose_res = self.kontor_client.compose(query).await?;
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
        let id: OpResultId = OpResultId::builder().txid(reveal_txid.to_string()).build();
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
        self.ws_client
            .next()
            .await
            .context("Failed to receive response from websocket")?;

        let result = self
            .kontor_client
            .result(&id)
            .await?
            .ok_or(anyhow!("Could not find op result"))?;
        tracing::info!("Instruction result: {:?}", result);
        if result.value.is_some() {
            Ok(InstructionResult {
                result,
                commit_tx_hex,
                reveal_tx_hex,
            })
        } else {
            Err(anyhow!("Instruction failed in processing"))
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
                value: self.identity.next_funding_utxo.1.value - Amount::from_sat(1000),
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

    pub async fn identity_p2wpkh(&mut self) -> Result<P2wpkhIdentity> {
        let network = Network::Regtest;
        let secp = Secp256k1::new();
        let (private_key, compressed_public_key) = generate_random_ecdsa_key(network);
        let address = Address::p2wpkh(&compressed_public_key, network);
        let keypair = Keypair::new(&secp, &mut rand::thread_rng());
        let mut funded = self.fund_address(&address, 1).await?;
        let next_funding_utxo = funded
            .pop()
            .ok_or_else(|| anyhow!("failed to fund p2wpkh identity"))?;
        Ok(P2wpkhIdentity {
            address,
            compressed_public_key,
            private_key,
            keypair,
            next_funding_utxo,
        })
    }

    pub async fn fund_address(
        &mut self,
        address: &Address,
        count: u32,
    ) -> Result<Vec<(OutPoint, TxOut)>> {
        if count == 0 {
            return Ok(vec![]);
        }

        let total_output_value = self.identity.next_funding_utxo.1.value - Amount::from_sat(1000);
        let value_per_output = total_output_value.to_sat() / count as u64;
        let remainder = total_output_value.to_sat() % count as u64;

        let mut outputs = Vec::with_capacity(count as usize);
        for i in 0..count {
            let mut value = value_per_output;
            if i == 0 {
                value += remainder;
            }
            outputs.push(TxOut {
                value: Amount::from_sat(value),
                script_pubkey: address.script_pubkey(),
            });
        }

        let mut tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: self.identity.next_funding_utxo.0,
                ..Default::default()
            }],
            output: outputs,
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
        let txid_str = self.bitcoin_client.send_raw_transaction(&raw_tx).await?;
        let txid = Txid::from_str(&txid_str)?;
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

        let next_funding_utxos = tx
            .output
            .into_iter()
            .enumerate()
            .map(|(i, tx_out)| {
                (
                    OutPoint {
                        txid,
                        vout: i as u32,
                    },
                    tx_out,
                )
            })
            .collect();

        Ok(next_funding_utxos)
    }

    pub async fn view(&self, contract_address: &ContractAddress, expr: &str) -> Result<String> {
        let result = self.kontor_client.view(contract_address, expr).await?;
        match result {
            ViewResult::Ok { value } => Ok(value),
            ViewResult::Err { message } => Err(anyhow!("{}", message)),
        }
    }

    pub async fn wit(&self, contract_address: &ContractAddress) -> Result<String> {
        let response = self.kontor_client.wit(contract_address).await?;
        Ok(response.wit)
    }

    pub async fn checkpoint(&mut self) -> Result<Option<String>> {
        self.kontor_client
            .index()
            .await
            .map(|index| index.checkpoint)
    }
}

#[derive(Clone)]
pub struct RegTester {
    inner: Arc<Mutex<RegTesterInner>>,
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
        Ok(Self {
            inner: Arc::new(Mutex::new(
                RegTesterInner::new(identity, bitcoin_client, kontor_client).await?,
            )),
        })
    }

    pub async fn bitcoin_client(&self) -> BitcoinClient {
        self.inner.lock().await.bitcoin_client.clone()
    }

    pub async fn kontor_client(&self) -> KontorClient {
        self.inner.lock().await.kontor_client.clone()
    }

    pub async fn wait_next_block(&self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        inner
            .ws_client
            .next()
            .await
            .context("Failed to receive response from websocket")?;
        inner.height += 1;
        Ok(())
    }

    pub async fn mempool_accept_result(
        &self,
        raw_txs: &[String],
    ) -> Result<Vec<TestMempoolAcceptResult>> {
        self.inner.lock().await.mempool_accept_result(raw_txs).await
    }

    pub async fn transaction_hex_inspect(&self, tx_hex: &str) -> Result<Vec<OpWithResult>> {
        self.inner
            .lock()
            .await
            .kontor_client
            .transaction_hex_inspect(TransactionHex {
                hex: tx_hex.to_string(),
            })
            .await
    }

    pub async fn transaction_inspect(&self, txid: &Txid) -> Result<Vec<OpWithResult>> {
        self.inner
            .lock()
            .await
            .kontor_client
            .transaction_inspect(txid)
            .await
    }

    pub async fn compose(&self, query: ComposeQuery) -> Result<ComposeOutputs> {
        self.inner.lock().await.kontor_client.compose(query).await
    }

    pub async fn compose_reveal(&self, query: RevealQuery) -> Result<RevealOutputs> {
        self.inner
            .lock()
            .await
            .kontor_client
            .compose_reveal(query)
            .await
    }

    pub async fn mempool_info(&self) -> Result<GetMempoolInfoResult> {
        self.inner.lock().await.mempool_info().await
    }
    pub async fn instruction(
        &mut self,
        ident: &mut Identity,
        inst: Inst,
    ) -> Result<InstructionResult> {
        self.inner.lock().await.instruction(ident, inst).await
    }

    pub async fn identity(&mut self) -> Result<Identity> {
        self.inner.lock().await.identity().await
    }

    pub async fn identity_p2wpkh(&mut self) -> Result<P2wpkhIdentity> {
        self.inner.lock().await.identity_p2wpkh().await
    }

    pub async fn fund_address(
        &mut self,
        address: &Address,
        count: u32,
    ) -> Result<Vec<(OutPoint, TxOut)>> {
        self.inner.lock().await.fund_address(address, count).await
    }

    pub async fn view(&self, contract_address: &ContractAddress, expr: &str) -> Result<String> {
        self.inner.lock().await.view(contract_address, expr).await
    }

    pub async fn wit(&self, contract_address: &ContractAddress) -> Result<String> {
        self.inner.lock().await.wit(contract_address).await
    }

    pub async fn height(&self) -> i64 {
        self.inner.lock().await.height
    }

    pub async fn checkpoint(&mut self) -> Result<Option<String>> {
        self.inner.lock().await.checkpoint().await
    }
}
