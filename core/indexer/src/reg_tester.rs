use std::{
    collections::HashMap,
    path::{Path, PathBuf},
    str::FromStr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};

use backon::BackoffBuilder;

use crate::{
    api::client::Client as KontorClient,
    bitcoin_client::{
        self, Client as BitcoinClient, client::RegtestRpc, types::TestMempoolAcceptResult,
    },
    bls::{
        RegistrationProof, bls_derivation_path, derive_bls_secret_key_eip2333,
        taproot_derivation_path,
    },
    config::{GenesisConfig, GenesisValidatorConfig, RegtestConfig},
    consensus::signing::PrivateKey as Ed25519PrivateKey,
    database::types::OpResultId,
    keygen,
    retry::{retry_extended, retry_simple},
    runtime::ContractAddress,
    test_utils,
};
use anyhow::{Result, anyhow, bail};
use bitcoin::{
    Address, Amount, BlockHash, CompressedPublicKey, Network, OutPoint, Transaction, TxIn, TxOut,
    Txid, XOnlyPublicKey,
    absolute::LockTime,
    bip32::{DerivationPath, Xpriv},
    consensus::serialize as serialize_tx,
    key::rand::RngCore,
    key::{Keypair, PrivateKey, Secp256k1, rand},
    taproot::TaprootBuilder,
    transaction::Version,
};
use indexer_types::{
    Info, Inst, InstKind, Insts, OpWithResult, ResultRow, RevealOutputs, TransactionHex, ViewResult,
};
use tempfile::TempDir;
use tokio::{
    fs,
    io::AsyncWriteExt,
    process::{Child, Command},
    sync::Mutex,
};

fn regtest_conf(rpc_port: u16, zmq_port: u16) -> String {
    format!(
        r#"regtest=1
server=1
txindex=1
prune=0
dbcache=4000
listen=0

[regtest]
rpcuser=rpc
rpcpassword=rpc
rpcport={rpc_port}
# Default ancestor/descendant limit is 25; contract regtests chain many
# commit/reveal pairs on one identity before the auto-miner confirms a block.
limitancestorcount=500
limitdescendantcount=500
zmqpubsequence=tcp://127.0.0.1:{zmq_port}
zmqpubsequencehwm=0
zmqpubrawtx=tcp://127.0.0.1:{zmq_port}
zmqpubrawtxhwm=0
"#
    )
}

/// Derive a BLS12-381 secret key from a BIP-39 seed using EIP-2333.
///
/// EIP-2333 defines a tree-structured key derivation for BLS12-381 that operates natively
/// on BLS12-381 scalars (unlike BIP-32, which is secp256k1-specific). All EIP-2333 child
/// derivation is hardened by design, so paths are written without the `'` marker.
///
async fn create_bitcoin_conf(data_dir: &Path, rpc_port: u16, zmq_port: u16) -> Result<()> {
    let mut f = fs::File::create(data_dir.join("bitcoin.conf")).await?;
    f.write_all(regtest_conf(rpc_port, zmq_port).as_bytes())
        .await?;
    Ok(())
}

/// Returns (child, client, rpc_url, zmq_port)
async fn run_bitcoin(data_dir: &Path) -> Result<(Child, bitcoin_client::Client, String, u16)> {
    let rpc_port = allocate_ports(1)?[0];
    let zmq_port = allocate_ports(1)?[0];
    create_bitcoin_conf(data_dir, rpc_port, zmq_port).await?;

    // Check if bitcoind is in PATH
    let bitcoind_check = Command::new("which").arg("bitcoind").output().await;

    if bitcoind_check.is_err() || !bitcoind_check.unwrap().status.success() {
        bail!(
            "bitcoind not found in PATH. Regtest tests require Bitcoin Core.\n\
             See TESTING.md for details."
        );
    }

    // Drop bitcoind's stdout — it inherits the parent's pipe and its
    // startup writes interleave with kontor's own `println!`s, splitting
    // long single-line outputs (notably the regtest `KONTOR_REGTEST_INFO`
    // payload) at noise newlines. stderr is left inherited for debug.
    let process = Command::new("bitcoind")
        .arg(format!("-datadir={}", data_dir.to_string_lossy()))
        .stdout(std::process::Stdio::null())
        .spawn()?;
    let config = RegtestConfig {
        bitcoin_rpc_url: format!("http://127.0.0.1:{rpc_port}"),
        ..RegtestConfig::default()
    };
    let client = bitcoin_client::Client::new_from_config(&config)?;
    retry_simple(async || {
        let i = client.get_blockchain_info().await?;
        if i.chain != Network::Regtest {
            bail!("Network not regtest");
        }
        Ok(())
    })
    .await?;
    let rpc_url = config.bitcoin_rpc_url;
    Ok((process, client, rpc_url, zmq_port))
}

struct ConsensusNodeConfig {
    private_key_hex: String,
    listen_addr: String,
    peers: Vec<String>,
    genesis_file: String,
}

/// Default node binary the cluster spawns — the release build, which is
/// what the regtest test suite expects. `kontor regtest` overrides this
/// with the running binary (`current_exe()`).
pub fn default_kontor_bin() -> PathBuf {
    PathBuf::from(format!(
        "{}/../target/release/kontor",
        env!("CARGO_MANIFEST_DIR")
    ))
}

/// Spawn a `kontor` node process and return a handle + API client. Returns as
/// soon as the process is launched — it does *not* wait for the node to become
/// available. Callers decide what to wait for: a seed waits only for its listen
/// address ([`RegTesterCluster::wait_for_listen_addr`]), while nodes that will
/// reach quorum wait for availability ([`RegTesterCluster::wait_for_available`]).
async fn run_kontor(
    data_dir: &Path,
    api_port: u16,
    bitcoin_rpc_url: &str,
    zmq_port: u16,
    consensus: Option<&ConsensusNodeConfig>,
    kontor_bin: &Path,
) -> Result<(Child, KontorClient)> {
    let config = RegtestConfig::default();
    let mut cmd = Command::new(kontor_bin);
    cmd.arg("run")
        .arg("--api-port")
        .arg(api_port.to_string())
        .arg("--data-dir")
        .arg(data_dir.to_string_lossy().into_owned())
        .arg("--network")
        .arg("regtest")
        .arg("--starting-block-height")
        .arg("102")
        .arg("--bitcoin-rpc-url")
        .arg(bitcoin_rpc_url)
        .arg("--bitcoin-rpc-user")
        .arg(config.bitcoin_rpc_user)
        .arg("--bitcoin-rpc-password")
        .arg(config.bitcoin_rpc_password)
        .arg("--zmq-address")
        .arg(format!("tcp://127.0.0.1:{zmq_port}"));

    if let Some(c) = consensus {
        cmd.arg("--consensus-mode")
            .arg("validator")
            .arg("--consensus-private-key")
            .arg(&c.private_key_hex)
            .arg("--consensus-listen-addr")
            .arg(&c.listen_addr)
            .arg("--genesis-file")
            .arg(&c.genesis_file);
        for peer in &c.peers {
            cmd.arg("--consensus-peers").arg(peer);
        }
    }

    let process = cmd.spawn()?;
    let client = KontorClient::new(format!("http://localhost:{api_port}/api"))?;
    Ok((process, client))
}

/// Generate a random x-only public key string (for test signers that don't need a full identity).
pub fn random_x_only_pubkey() -> String {
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut rand::thread_rng());
    keypair.x_only_public_key().0.to_string()
}

/// Derive a secp256k1 Keypair from a BIP-39 seed via BIP-32 HD wallet derivation.
///
/// Full BIP-32 derivation in one step: seed → master xpriv → child xpriv at `path` → Keypair.
pub fn derive_taproot_keypair_from_seed(seed: &[u8], path: &str) -> Result<Keypair> {
    let secp = Secp256k1::new();
    let master = Xpriv::new_master(Network::Regtest, seed)?;
    let derivation_path: DerivationPath = path.parse()?;
    let child = master.derive_priv(&secp, &derivation_path)?;
    Ok(Keypair::from_secret_key(&secp, &child.private_key))
}

fn outpoint_to_utxo_id(outpoint: &OutPoint) -> String {
    format!("{}:{}", outpoint.txid, outpoint.vout)
}

#[derive(Debug, Clone)]
pub struct Identity {
    pub address: Address,
    pub keypair: Keypair,
    pub next_funding_utxo: (OutPoint, TxOut),
    pub bls_secret_key: [u8; 32],
    pub bls_pubkey: [u8; 96],
}

impl Identity {
    pub fn x_only_public_key(&self) -> XOnlyPublicKey {
        self.keypair.x_only_public_key().0
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

type PublishCache = Arc<Mutex<HashMap<String, Arc<Mutex<Option<ContractAddress>>>>>>;

/// Thread-safe identity pool shared between the cluster and module RegTesters.
#[derive(Clone)]
pub struct IdentityPool {
    registered: Arc<Mutex<std::collections::VecDeque<Identity>>>,
    unregistered: Arc<Mutex<std::collections::VecDeque<Identity>>>,
    publish_cache: PublishCache,
}

impl IdentityPool {
    pub fn new() -> Self {
        Self {
            registered: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            unregistered: Arc::new(Mutex::new(std::collections::VecDeque::new())),
            publish_cache: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Returns a per-key lock guard. If the inner Option is Some, the contract
    /// is already published. If None, the caller should publish and set it.
    pub async fn lock_published(
        &self,
        name: &str,
    ) -> tokio::sync::OwnedMutexGuard<Option<ContractAddress>> {
        let entry = {
            let mut cache = self.publish_cache.lock().await;
            cache
                .entry(name.to_string())
                .or_insert_with(|| Arc::new(Mutex::new(None)))
                .clone()
        };
        entry.lock_owned().await
    }

    pub async fn pop_registered(&self) -> Result<Identity> {
        self.registered
            .lock()
            .await
            .pop_front()
            .ok_or_else(|| anyhow!("Identity pool exhausted"))
    }

    pub async fn pop_unregistered(&self) -> Result<Identity> {
        self.unregistered
            .lock()
            .await
            .pop_front()
            .ok_or_else(|| anyhow!("Unregistered identity pool exhausted"))
    }

    pub async fn extend_registered(&self, identities: Vec<Identity>) {
        self.registered.lock().await.extend(identities);
    }

    pub async fn extend_unregistered(&self, identities: Vec<Identity>) {
        self.unregistered.lock().await.extend(identities);
    }
}

pub struct RegTesterInner {
    pub bitcoin_client: BitcoinClient,
    kontor_client: KontorClient,
    /// Address to mine blocks to (cluster admin identity's address).
    mine_address: String,
    /// Shared identity pool for popping pre-created identities.
    pub pool: IdentityPool,
}

pub struct SendInstructionResult {
    pub reveal_txid: bitcoin::Txid,
    pub commit_tx_hex: String,
    pub reveal_tx_hex: String,
}

pub struct ComposeInstsResult {
    pub commit_transaction: Transaction,
    pub reveal_transaction: Transaction,
    pub commit_tx_hex: String,
    pub reveal_tx_hex: String,
}

pub struct InstructionResult {
    pub result: ResultRow,
    pub commit_tx_hex: String,
    pub reveal_tx_hex: String,
}

impl RegTesterInner {
    pub async fn with_port(
        bitcoin_client: BitcoinClient,
        kontor_client: KontorClient,
        mine_address: String,
        pool: IdentityPool,
    ) -> Result<Self> {
        Ok(Self {
            bitcoin_client,
            kontor_client,
            mine_address,
            pool,
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

    /// Validate and broadcast transactions to the mempool without mining.
    pub async fn send_to_mempool(&self, raw_txs: &[String]) -> Result<Vec<Txid>> {
        self.mempool_accept(raw_txs).await?;
        let mut txids = Vec::with_capacity(raw_txs.len());
        for raw_tx in raw_txs {
            let txid_str = self.bitcoin_client.send_raw_transaction(raw_tx).await?;
            txids.push(Txid::from_str(&txid_str)?);
        }
        Ok(txids)
    }

    pub async fn mine(&self, count: u64) -> Result<()> {
        self.bitcoin_client
            .generate_to_address(count, &self.mine_address)
            .await?;
        Ok(())
    }

    pub async fn compose_instruction(
        &mut self,
        ident: &mut Identity,
        inst: Inst,
    ) -> Result<ComposeInstsResult> {
        self.compose_insts(ident, Insts::single(inst)).await
    }

    pub async fn compose_insts(
        &mut self,
        ident: &mut Identity,
        insts: Insts,
    ) -> Result<ComposeInstsResult> {
        // Build a Reveal describing the simple commit+reveal pattern:
        // one participant (this identity) building a commit, with the
        // reveal having a single Change output back to the participant's
        // address — the v1 "auto-generated change" behavior, now made
        // explicit. sat_per_vbyte left None to exercise the API's
        // fastest_fee fallback (same as the v1 path).
        let reveal = indexer_types::Reveal {
            sat_per_vbyte: None,
            participants: vec![indexer_types::RevealParticipant {
                x_only_public_key: ident.x_only_public_key().to_string(),
                commit_insts: insts,
                output: Some(indexer_types::RevealOutput::Change {
                    script_pubkey: hex::encode(ident.address.script_pubkey().as_bytes()),
                }),
                commit_source: indexer_types::CommitSource::Build {
                    address: ident.address.to_string(),
                    funding_utxo_ids: vec![outpoint_to_utxo_id(&ident.next_funding_utxo.0)],
                },
            }],
            extra_inputs: vec![],
            extra_outputs: vec![],
        };
        let compose_outputs = self.kontor_client.compose(reveal).await?;

        // The single Build participant produces one commit tx.
        let mut commit_transaction = compose_outputs.commits[0].transaction.clone();
        let mut reveal_transaction = compose_outputs.reveal.transaction.clone();

        let secp = Secp256k1::new();
        test_utils::sign_key_spend(
            &secp,
            &mut commit_transaction,
            std::slice::from_ref(&ident.next_funding_utxo.1),
            &ident.keypair,
            0,
            None,
        )?;
        // Pull the participant's tap leaf script out of the reveal PSBT
        // — the indexer populates it as `PSBT_IN_TAP_LEAF_SCRIPT` on
        // each participant input (was a parallel `commit_tap_leaf_
        // scripts` Vec in the response previously).
        let reveal_psbt =
            bitcoin::Psbt::deserialize(&hex::decode(&compose_outputs.reveal.psbt_hex)?)?;
        let (tap_script, _) = test_utils::participant_tap_script(&reveal_psbt.inputs[0])?;
        let taproot_spend_info = TaprootBuilder::new()
            .add_leaf(0, tap_script.clone())
            .map_err(|e| anyhow!("Failed to add leaf: {}", e))?
            .finalize(&secp, ident.x_only_public_key())
            .map_err(|e| anyhow!("Failed to finalize Taproot tree: {:?}", e))?;
        test_utils::sign_script_spend(
            &secp,
            &taproot_spend_info,
            &tap_script,
            &mut reveal_transaction,
            &[commit_transaction.output[0].clone()],
            &ident.keypair,
            0,
        )?;

        let commit_tx_hex = hex::encode(serialize_tx(&commit_transaction));
        let reveal_tx_hex = hex::encode(serialize_tx(&reveal_transaction));

        self.mempool_accept(&[commit_tx_hex.clone(), reveal_tx_hex.clone()])
            .await?;

        Ok(ComposeInstsResult {
            commit_transaction,
            reveal_transaction,
            commit_tx_hex,
            reveal_tx_hex,
        })
    }

    /// Compose, sign, and send an instruction to the mempool without mining.
    /// Updates the identity's funding UTXO for chaining subsequent calls.
    pub async fn send_instruction(
        &mut self,
        ident: &mut Identity,
        inst: Inst,
    ) -> Result<SendInstructionResult> {
        self.send_insts(ident, Insts::single(inst)).await
    }

    pub async fn send_insts(
        &mut self,
        ident: &mut Identity,
        insts: Insts,
    ) -> Result<SendInstructionResult> {
        let composed = self.compose_insts(ident, insts).await?;
        let reveal_txid = composed.reveal_transaction.compute_txid();
        let txids = self
            .send_to_mempool(&[
                composed.commit_tx_hex.clone(),
                composed.reveal_tx_hex.clone(),
            ])
            .await?;

        ident.next_funding_utxo = (
            OutPoint {
                txid: txids[0],
                vout: (composed.commit_transaction.output.len() - 1) as u32,
            },
            composed.commit_transaction.output.last().unwrap().clone(),
        );

        Ok(SendInstructionResult {
            reveal_txid,
            commit_tx_hex: composed.commit_tx_hex,
            reveal_tx_hex: composed.reveal_tx_hex,
        })
    }

    /// Compose, sign, send an instruction to the mempool, and wait for the result.
    /// In cluster mode, only Publish mines immediately (needs block height for contract address).
    /// All other ops are batchable and wait for consensus.
    /// In standalone mode (no consensus), all ops mine immediately.
    pub async fn instruction(
        &mut self,
        ident: &mut Identity,
        inst: Inst,
    ) -> Result<InstructionResult> {
        self.instruction_insts(ident, Insts::single(inst)).await
    }

    pub async fn instruction_insts(
        &mut self,
        ident: &mut Identity,
        insts: Insts,
    ) -> Result<InstructionResult> {
        let needs_mine = insts
            .ops
            .iter()
            .any(|inst| matches!(inst.kind, InstKind::Publish { .. }));
        let sent = self.send_insts(ident, insts).await?;
        let id = OpResultId::builder()
            .txid(sent.reveal_txid.to_string())
            .input_index(0)
            .op_index(0)
            .build();
        let target_txid = sent.reveal_txid.to_string();

        if needs_mine {
            self.mine(1).await?;
        }

        self.wait_for_txids(&[target_txid]).await?;

        let result = self
            .kontor_client
            .result(&id)
            .await?
            .ok_or(anyhow!("Could not find op result"))?;
        tracing::info!("Instruction result: {:?}", result);
        if result.value.is_some() {
            Ok(InstructionResult {
                result,
                commit_tx_hex: sent.commit_tx_hex,
                reveal_tx_hex: sent.reveal_tx_hex,
            })
        } else {
            Err(anyhow!("Instruction failed in processing"))
        }
    }

    /// Pop a pre-created funded identity without BLS registration from the pool.
    pub async fn unregistered_identity(&self) -> Result<Identity> {
        self.pool.pop_unregistered().await
    }

    /// Wait until every txid in `target_txids` has been processed by the
    /// indexer. Long-polls `GET /api/` for state changes (the signature
    /// moves on every block/batch), then re-checks each txid via
    /// `/api/transactions/{txid}` — the REST replacement for the old
    /// websocket `Processed`/`BatchProcessed` event stream.
    async fn wait_for_txids(&self, target_txids: &[String]) -> Result<()> {
        // The handler caps `?wait=` at its own `MAX_WAIT_MS` regardless;
        // this only needs to be sane. 25s keeps each poll clear of the
        // router's request-timeout middleware.
        const LONG_POLL_MS: u64 = 25_000;
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(180);
        let mut remaining: Vec<String> = target_txids.to_vec();
        let mut since = self.kontor_client.index().await?.signature;
        loop {
            let mut still_pending = Vec::new();
            for txid in remaining {
                if self.kontor_client.transaction(&txid).await?.is_none() {
                    still_pending.push(txid);
                }
            }
            remaining = still_pending;
            if remaining.is_empty() {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("wait_for_txids timed out waiting for: {remaining:?}");
            }
            since = self
                .kontor_client
                .index_wait(&since, LONG_POLL_MS)
                .await?
                .signature;
        }
    }

    /// Pop a pre-created identity with BLS registration and issuance from the pool.
    pub async fn identity(&self) -> Result<Identity> {
        self.pool.pop_registered().await
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
    pub async fn bitcoin_client(&self) -> BitcoinClient {
        self.inner.lock().await.bitcoin_client.clone()
    }

    pub async fn kontor_client(&self) -> KontorClient {
        self.inner.lock().await.kontor_client.clone()
    }

    pub async fn get_signer_id(&self, xonly: &str) -> Result<Option<u64>> {
        match self.kontor_client().await.signer(xonly).await {
            Ok(entry) => Ok(Some(entry.signer_id)),
            Err(_) => Ok(None),
        }
    }

    pub async fn get_bls_pubkey(&self, xonly: &str) -> Result<Option<Vec<u8>>> {
        match self.kontor_client().await.signer(xonly).await {
            Ok(entry) => Ok(entry.bls_pubkey),
            Err(_) => Ok(None),
        }
    }

    pub async fn get_signer_entry(
        &self,
        identifier: &str,
    ) -> Result<Option<indexer_types::SignerResponse>> {
        match self.kontor_client().await.signer(identifier).await {
            Ok(entry) => Ok(Some(entry)),
            Err(_) => Ok(None),
        }
    }

    pub async fn mempool_accept_result(
        &self,
        raw_txs: &[String],
    ) -> Result<Vec<TestMempoolAcceptResult>> {
        self.inner.lock().await.mempool_accept_result(raw_txs).await
    }

    pub async fn send_to_mempool(&self, raw_txs: &[String]) -> Result<Vec<Txid>> {
        self.inner.lock().await.send_to_mempool(raw_txs).await
    }

    pub async fn mine(&self, count: u64) -> Result<()> {
        self.inner.lock().await.mine(count).await
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

    pub async fn compose(
        &self,
        reveal: indexer_types::Reveal,
    ) -> Result<indexer_types::ComposeOutputs> {
        self.inner.lock().await.kontor_client.compose(reveal).await
    }

    pub async fn compose_commit(
        &self,
        reveal: indexer_types::Reveal,
    ) -> Result<indexer_types::CommitOutputs> {
        self.inner
            .lock()
            .await
            .kontor_client
            .compose_commit(reveal)
            .await
    }

    pub async fn compose_reveal(&self, reveal: indexer_types::Reveal) -> Result<RevealOutputs> {
        self.inner
            .lock()
            .await
            .kontor_client
            .compose_reveal(reveal)
            .await
    }

    pub async fn compose_instruction(
        &mut self,
        ident: &mut Identity,
        inst: Inst,
    ) -> Result<ComposeInstsResult> {
        self.inner
            .lock()
            .await
            .compose_instruction(ident, inst)
            .await
    }

    pub async fn compose_insts(
        &mut self,
        ident: &mut Identity,
        insts: Insts,
    ) -> Result<ComposeInstsResult> {
        self.inner.lock().await.compose_insts(ident, insts).await
    }

    pub async fn send_instruction(
        &self,
        ident: &mut Identity,
        inst: Inst,
    ) -> Result<SendInstructionResult> {
        self.inner.lock().await.send_instruction(ident, inst).await
    }

    pub async fn send_insts(
        &mut self,
        ident: &mut Identity,
        insts: Insts,
    ) -> Result<SendInstructionResult> {
        self.inner.lock().await.send_insts(ident, insts).await
    }

    pub async fn wait_for_txids(&self, txids: &[String]) -> Result<()> {
        self.inner.lock().await.wait_for_txids(txids).await
    }

    pub async fn instruction(
        &mut self,
        ident: &mut Identity,
        inst: Inst,
    ) -> Result<InstructionResult> {
        self.inner.lock().await.instruction(ident, inst).await
    }

    pub async fn instruction_insts(
        &mut self,
        ident: &mut Identity,
        insts: Insts,
    ) -> Result<InstructionResult> {
        self.inner
            .lock()
            .await
            .instruction_insts(ident, insts)
            .await
    }

    pub async fn unregistered_identity(&mut self) -> Result<Identity> {
        self.inner.lock().await.unregistered_identity().await
    }

    pub async fn identity(&self) -> Result<Identity> {
        self.inner.lock().await.identity().await
    }

    pub async fn view(&self, contract_address: &ContractAddress, expr: &str) -> Result<String> {
        self.inner.lock().await.view(contract_address, expr).await
    }

    pub async fn wit(&self, contract_address: &ContractAddress) -> Result<String> {
        self.inner.lock().await.wit(contract_address).await
    }

    // TODO: reimplement for compose tests — needs admin identity for funding
    pub async fn identity_p2wpkh(&mut self) -> Result<P2wpkhIdentity> {
        bail!("identity_p2wpkh not available on module RegTester — use cluster method")
    }

    pub async fn fund_address(
        &mut self,
        _address: &Address,
        _count: u32,
    ) -> Result<Vec<(OutPoint, TxOut)>> {
        bail!("fund_address not available on module RegTester — use cluster method")
    }

    pub async fn lock_published(
        &self,
        name: &str,
    ) -> tokio::sync::OwnedMutexGuard<Option<ContractAddress>> {
        let pool = self.inner.lock().await.pool.clone();
        pool.lock_published(name).await
    }

    pub async fn checkpoint(&mut self) -> Result<Option<String>> {
        self.inner.lock().await.checkpoint().await
    }

    pub async fn info(&self) -> Result<Info> {
        self.inner.lock().await.kontor_client.index().await
    }
}

fn poll_backoff() -> backon::ExponentialBuilder {
    backon::ExponentialBuilder::new()
        .with_jitter()
        .with_min_delay(std::time::Duration::from_millis(100))
        .with_max_delay(std::time::Duration::from_secs(1))
        .without_max_times()
}

macro_rules! poll_nodes {
    ($self:expr, $timeout:expr, $label:expr, |$node:ident| $check:expr) => {{
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs($timeout);
        let mut backoff = poll_backoff().build();
        loop {
            let mut all_pass = true;
            for nc in &$self.node_configs {
                if let Some(cn) = &nc.running {
                    let $node = &cn.client;
                    if !$check {
                        all_pass = false;
                        break;
                    }
                }
            }
            if all_pass {
                break Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                break Err(anyhow!("Timed out: {}", $label));
            }
            match backoff.next() {
                Some(delay) => tokio::time::sleep(delay).await,
                None => break Err(anyhow!("Backoff exhausted: {}", $label)),
            }
        }
    }};
}

pub struct NodeConfig {
    pub api_port: u16,
    pub ed25519_key: Ed25519PrivateKey,
    pub data_dir: TempDir,
    pub running: Option<ClusterNode>,
}

pub struct ClusterNode {
    pub client: KontorClient,
    child: Child,
}

fn allocate_ports(n: usize) -> std::io::Result<Vec<u16>> {
    let mut ports = Vec::with_capacity(n);
    let mut listeners = Vec::with_capacity(n);
    for _ in 0..n {
        let listener = std::net::TcpListener::bind("127.0.0.1:0")?;
        ports.push(listener.local_addr()?.port());
        listeners.push(listener);
    }
    drop(listeners);
    Ok(ports)
}

enum MinerCmd {
    Pause(tokio::sync::oneshot::Sender<()>),
    Resume(tokio::sync::oneshot::Sender<()>),
    Reset,
}

/// A cluster of N Kontor instances sharing one regtest bitcoind,
/// each with consensus enabled and its own DB.
pub struct RegTesterCluster {
    pub bitcoin_client: BitcoinClient,
    pub node_configs: Vec<NodeConfig>,
    pub identity: Identity,
    pub reg_tester: RegTester,
    pub pool: IdentityPool,
    bitcoin_rpc_url: String,
    zmq_port: u16,
    node_counter: AtomicUsize,
    genesis_path: std::path::PathBuf,
    /// Node binary spawned for each validator; retained so `start_node`
    /// restarts with the same binary `setup_with` was given.
    kontor_bin: PathBuf,
    /// Node 0's resolved consensus listen multiaddr — the bootstrap seed every
    /// other node discovers the cluster through. Read back from node 0 after it
    /// binds its `:0` port. Node 0 is never restarted (tests only cycle higher
    /// indices), so this stays valid for the cluster's lifetime.
    seed_addr: String,
    miner_cmd_tx: tokio::sync::mpsc::Sender<MinerCmd>,
    _miner_handle: tokio::task::JoinHandle<()>,
    _bitcoin_child: Child,
    _bitcoin_data_dir: TempDir,
    _genesis_dir: TempDir,
}

impl RegTesterCluster {
    /// Start a cluster of `n` validators, all in genesis, all started.
    /// Pre-creates `registered` identities (with BLS + issuance) and `unregistered` (funded only).
    pub async fn setup(n: usize, registered: usize, unregistered: usize) -> Result<Self> {
        Self::setup_with(
            n,
            n,
            n,
            registered,
            unregistered,
            None,
            &default_kontor_bin(),
        )
        .await
    }

    /// Create a cluster with `total` keys, `genesis_count` in genesis, `active` started.
    ///
    /// `funding_seed`: `Some` pins the tx-building identity's key (so a
    /// devnet has a deterministic dev account); `None` randomizes it.
    /// `kontor_bin`: the node binary to spawn for each validator.
    pub async fn setup_with(
        total: usize,
        genesis_count: usize,
        active: usize,
        registered: usize,
        unregistered: usize,
        funding_seed: Option<[u8; 64]>,
        kontor_bin: &Path,
    ) -> Result<Self> {
        assert!(genesis_count <= total, "genesis_count must be <= total");
        assert!(active <= total, "active must be <= total");

        let bitcoin_data_dir = TempDir::new()?;
        let (bitcoin_child, bitcoin_client, bitcoin_rpc_url, zmq_port) =
            run_bitcoin(bitcoin_data_dir.path()).await?;

        // Create a funded identity for transaction building
        let mut seed = [0u8; 64];
        match funding_seed {
            Some(s) => seed = s,
            None => rand::thread_rng().fill_bytes(&mut seed),
        }
        let taproot_path = taproot_derivation_path(Network::Regtest);
        let bls_path = bls_derivation_path(Network::Regtest);
        let keypair = derive_taproot_keypair_from_seed(&seed, &taproot_path)?;
        let secp = Secp256k1::new();
        let (x_only_public_key, ..) = keypair.x_only_public_key();
        let address = Address::p2tr(&secp, x_only_public_key, None, Network::Regtest);
        let bls_sk = derive_bls_secret_key_eip2333(&seed, &bls_path)?;
        let bls_secret_key = bls_sk.to_bytes();
        let bls_pubkey = bls_sk.sk_to_pk().to_bytes();
        let block_hashes = bitcoin_client
            .generate_to_address(101, &address.to_string())
            .await?;
        let block_hash =
            BlockHash::from_str(block_hashes.first().ok_or(anyhow!("No blocks created"))?)?;
        let block = bitcoin_client.get_block(&block_hash).await?;
        let identity = Identity {
            address,
            keypair,
            next_funding_utxo: (
                OutPoint {
                    txid: block.txdata[0].compute_txid(),
                    vout: 0,
                },
                block.txdata[0].output[0].clone(),
            ),
            bls_secret_key,
            bls_pubkey,
        };

        // Same derivation path operators run via `kontor keygen`. Distinct
        // master seed from the in-process cluster so the two test setups
        // produce different keys (avoids accidental cross-test coupling).
        const REGTEST_MASTER_SEED: [u8; 32] = [0xABu8; 32];
        let validator_keys: Vec<keygen::ValidatorKeys> = (0..total)
            .map(|i| keygen::derive_validator(&REGTEST_MASTER_SEED, i as u32))
            .collect();
        let ed25519_keys: Vec<Ed25519PrivateKey> = validator_keys
            .iter()
            .map(|k| Ed25519PrivateKey::from(k.ed25519_private))
            .collect();

        // Write genesis file (only genesis_count validators)
        let genesis_config = GenesisConfig {
            validators: validator_keys
                .iter()
                .take(genesis_count)
                .map(|k| GenesisValidatorConfig {
                    x_only_pubkey: hex::encode(k.x_only_pubkey),
                    stake: "100".to_string(),
                    ed25519_pubkey: hex::encode(k.ed25519_pubkey),
                })
                .collect(),
        };
        let genesis_dir = TempDir::new()?;
        let genesis_path = genesis_dir.path().join("genesis.json");
        std::fs::write(&genesis_path, serde_json::to_string(&genesis_config)?)?;

        // Allocate API ports up front (the harness connects to each node's
        // HTTP API by port). Consensus nodes bind `:0` instead — the OS
        // assigns the port atomically at bind time, so there is no
        // probe-then-release window for a parallel test to race into. The
        // resolved port is read back from node 0 (the seed) and discovered by
        // everyone else via libp2p.
        let api_ports = allocate_ports(total)?;

        let mut node_configs: Vec<NodeConfig> = (0..total)
            .map(|i| NodeConfig {
                api_port: api_ports[i],
                ed25519_key: ed25519_keys[i].clone(),
                data_dir: TempDir::new().expect("Failed to create temp dir"),
                running: None,
            })
            .collect();

        // Seed-first bring-up, no fixed ports. The seed (node 0) boots with no
        // peers; we wait only for its *listen address* — a lone node can't
        // decide a block (no quorum) so it never becomes "available", and
        // waiting for that here would deadlock against the very followers it's
        // meant to seed. The address is read from the ungated
        // `/api/status` endpoint (answers before availability).
        assert!(
            active >= 1,
            "cluster needs at least the seed node (index 0)"
        );
        let (seed_child, seed_client) = Self::spawn_node(
            &node_configs[0],
            &[],
            &genesis_path,
            &bitcoin_rpc_url,
            zmq_port,
            kontor_bin,
        )
        .await?;
        let seed_addr = Self::wait_for_listen_addr(&seed_client, Duration::from_secs(30)).await?;
        node_configs[0].running = Some(ClusterNode {
            client: seed_client,
            child: seed_child,
        });

        // Spawn the remaining active nodes, all bootstrapping from the seed and
        // discovering each other. Spawn first, then wait for availability: with
        // the seed already participating they reach quorum together, so each
        // does become available (unlike the lone seed).
        let spawns = node_configs.iter().skip(1).take(active - 1).map(|nc| {
            Self::spawn_node(
                nc,
                std::slice::from_ref(&seed_addr),
                &genesis_path,
                &bitcoin_rpc_url,
                zmq_port,
                kontor_bin,
            )
        });
        for (offset, result) in futures_util::future::join_all(spawns)
            .await
            .into_iter()
            .enumerate()
        {
            let (child, client) = result?;
            node_configs[offset + 1].running = Some(ClusterNode { client, child });
        }

        // Now wait for *every* active node — seed included — to become available.
        // The seed was only waited for its listen address above (so its bootstrap
        // address could be handed to the followers before they existed); now that
        // the full active set is running it reaches quorum and they all go
        // available together. For a single-node devnet (no followers) this is the
        // only availability barrier — without it, bring-up races ahead of the lone
        // seed and the first `/api` poll 503s.
        let active_clients: Vec<KontorClient> = node_configs
            .iter()
            .take(active)
            .filter_map(|nc| nc.running.as_ref().map(|cn| cn.client.clone()))
            .collect();
        futures_util::future::try_join_all(active_clients.iter().map(Self::wait_for_available))
            .await?;

        // Mine a block so we can verify all nodes process it (proves peer connectivity).
        bitcoin_client
            .generate_to_address(1, &identity.address.to_string())
            .await?;

        // Start the auto-miner
        let (miner_cmd_tx, mut miner_cmd_rx) = tokio::sync::mpsc::channel::<MinerCmd>(16);
        let miner_client = bitcoin_client.clone();
        let miner_address = identity.address.to_string();
        let miner_handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = tokio::time::sleep(std::time::Duration::from_secs(10)) => {
                        let _ = miner_client.generate_to_address(1, &miner_address).await;
                    }
                    cmd = miner_cmd_rx.recv() => {
                        match cmd {
                            Some(MinerCmd::Reset) => continue,
                            Some(MinerCmd::Pause(done)) => {
                                let _ = done.send(());
                                // Wait for Resume
                                while let Some(cmd) = miner_cmd_rx.recv().await {
                                    if let MinerCmd::Resume(done) = cmd {
                                        let _ = done.send(());
                                        break;
                                    }
                                }
                            }
                            Some(MinerCmd::Resume(_)) => {}
                            None => break,
                        }
                    }
                }
            }
        });

        let pool = IdentityPool::new();

        let client = &node_configs[0]
            .running
            .as_ref()
            .expect("Node 0 not running")
            .client;
        let mine_address = identity.address.to_string();
        let inner = RegTesterInner::with_port(
            bitcoin_client.clone(),
            client.clone(),
            mine_address,
            pool.clone(),
        )
        .await?;

        let reg_tester = RegTester {
            inner: Arc::new(Mutex::new(inner)),
        };

        let mut cluster = Self {
            bitcoin_client,
            node_configs,
            identity,
            reg_tester,
            pool,
            bitcoin_rpc_url,
            zmq_port,
            node_counter: AtomicUsize::new(0),
            genesis_path,
            kontor_bin: kontor_bin.to_path_buf(),
            seed_addr,
            miner_cmd_tx,
            _miner_handle: miner_handle,
            _bitcoin_child: bitcoin_child,
            _bitcoin_data_dir: bitcoin_data_dir,
            _genesis_dir: genesis_dir,
        };

        // 120s instead of 60s — under parallel cluster-test load (many
        // bitcoinds + many indexer nodes per process), the post-mine
        // follow-up for height 102 can exceed 60s purely from IO/CPU
        // contention. On healthy runs this completes in <10s; the
        // longer ceiling only matters when something is actually wrong.
        cluster.poll_all_nodes_height(102, 120).await?;

        if registered > 0 || unregistered > 0 {
            cluster
                .pre_create_identity_pools(registered, unregistered)
                .await?;
        }

        Ok(cluster)
    }

    /// Poll a node's `GET /api/status` until it reports a bound consensus listen
    /// address (the libp2p bind is async, so it lands shortly after the API
    /// comes up). Used to read back the seed's OS-assigned `:0` port.
    async fn wait_for_listen_addr(client: &KontorClient, timeout: Duration) -> Result<String> {
        let deadline = tokio::time::Instant::now() + timeout;
        loop {
            // Ungated endpoint — answers as soon as the swarm binds, well before
            // the node is "available" (which needs quorum, hence the followers
            // we're about to bootstrap from this very address).
            if let Ok(status) = client.status().await
                && let Some(addr) = status.consensus_listen_addr
            {
                return Ok(addr);
            }
            if tokio::time::Instant::now() >= deadline {
                bail!(
                    "seed node never reported a bound consensus listen address within {timeout:?}"
                );
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    /// Spawn a validator node, binding an OS-assigned consensus port
    /// (`/tcp/0`, no probe/release race). `peers` is the bootstrap seed set —
    /// empty for the seed itself, `[seed_addr]` for everyone else, who learn
    /// the rest of the cluster via discovery. Returns immediately; the caller
    /// waits for whatever it needs.
    async fn spawn_node(
        nc: &NodeConfig,
        peers: &[String],
        genesis_path: &std::path::Path,
        bitcoin_rpc_url: &str,
        zmq_port: u16,
        kontor_bin: &Path,
    ) -> Result<(Child, KontorClient)> {
        let consensus_config = ConsensusNodeConfig {
            private_key_hex: hex::encode(nc.ed25519_key.inner().to_bytes()),
            listen_addr: "/ip4/127.0.0.1/tcp/0".to_string(),
            peers: peers.to_vec(),
            genesis_file: genesis_path.to_string_lossy().into_owned(),
        };
        run_kontor(
            nc.data_dir.path(),
            nc.api_port,
            bitcoin_rpc_url,
            zmq_port,
            Some(&consensus_config),
            kontor_bin,
        )
        .await
    }

    /// Wait until a node's `/api/` reports available — i.e. consensus has
    /// decided a block. Only meaningful once quorum can form (the seed can't
    /// satisfy this alone). Extended budget: cluster tests run several indexer
    /// processes in parallel, so DB init + mempool sync + initial fee
    /// projection + consensus startup can exceed the standard ~25s budget.
    /// `client.index()` errors while the indexer 503s (`require_available`),
    /// so a successful response is the availability signal.
    async fn wait_for_available(client: &KontorClient) -> Result<()> {
        retry_extended(async || {
            let _ = client.index().await?;
            Ok::<_, anyhow::Error>(())
        })
        .await
    }

    /// Bitcoin Core regtest RPC endpoint with the fixed `rpc:rpc`
    /// credentials embedded (see `regtest_conf`) — a directly-usable URL.
    pub fn bitcoin_rpc_endpoint(&self) -> String {
        self.bitcoin_rpc_url
            .replacen("http://", "http://rpc:rpc@", 1)
    }

    /// Get the client for a running node.
    pub fn client(&self, index: usize) -> &KontorClient {
        &self.node_configs[index]
            .running
            .as_ref()
            .expect("Node not running")
            .client
    }

    /// Kill a node's process.
    pub async fn kill_node(&mut self, index: usize) -> Result<()> {
        let nc = &mut self.node_configs[index];
        let node = nc
            .running
            .as_mut()
            .ok_or(anyhow!("Node {index} not running"))?;
        node.child.start_kill()?;
        node.child.wait().await?;
        nc.running = None;
        Ok(())
    }

    /// Start or restart a node. Restarted/late-joining nodes bootstrap from
    /// the seed (node 0) and rediscover the rest of the cluster; node 0 itself
    /// is never restarted (see [`Self::seed_addr`]).
    pub async fn start_node(&mut self, index: usize) -> Result<()> {
        let nc = &self.node_configs[index];
        let (child, client) = Self::spawn_node(
            nc,
            std::slice::from_ref(&self.seed_addr),
            &self.genesis_path,
            &self.bitcoin_rpc_url,
            self.zmq_port,
            &self.kontor_bin,
        )
        .await?;
        // A restart/late-joiner joins an existing quorum, so it does become
        // available.
        Self::wait_for_available(&client).await?;
        self.node_configs[index].running = Some(ClusterNode { client, child });
        Ok(())
    }

    /// Get a `RegTester` for the cluster. Returns a clone of the shared
    /// node 0 RegTester (same pools, same state via Arc<Mutex>).
    pub fn reg_tester(&self) -> RegTester {
        self.reg_tester.clone()
    }

    /// Split the dev identity's funding UTXO into `parts` roughly-equal
    /// outputs back to the dev address, broadcast + mine, and return
    /// them. Lets independent regtest tests each spend a distinct UTXO
    /// without colliding on one shared funding output. The dev
    /// identity's `next_funding_utxo` is left pointing at the first.
    pub async fn split_dev_funding(&mut self, parts: usize) -> Result<Vec<(OutPoint, TxOut)>> {
        assert!(parts >= 1, "split_dev_funding: need at least one part");
        let secp = Secp256k1::new();
        let (in_point, in_txout) = self.identity.next_funding_utxo.clone();
        let fee = Amount::from_sat(1000 + parts as u64 * 50);
        let each = (in_txout.value.to_sat() - fee.to_sat()) / parts as u64;
        let mut tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: in_point,
                ..Default::default()
            }],
            output: (0..parts)
                .map(|_| TxOut {
                    value: Amount::from_sat(each),
                    script_pubkey: self.identity.address.script_pubkey(),
                })
                .collect(),
        };
        test_utils::sign_key_spend(
            &secp,
            &mut tx,
            std::slice::from_ref(&in_txout),
            &self.identity.keypair,
            0,
            None,
        )?;
        let txid = tx.compute_txid();
        self.reg_tester
            .send_to_mempool(&[hex::encode(serialize_tx(&tx))])
            .await?;
        self.mine(1).await?;
        let utxos: Vec<(OutPoint, TxOut)> = tx
            .output
            .iter()
            .enumerate()
            .map(|(i, o)| {
                (
                    OutPoint {
                        txid,
                        vout: i as u32,
                    },
                    o.clone(),
                )
            })
            .collect();
        self.identity.next_funding_utxo = utxos[0].clone();
        Ok(utxos)
    }

    /// Create an independent `RegTester` for a test module. Round-robins across
    /// running nodes. Pops a funding identity from the shared pool. Each returned
    /// `RegTester` has its own websocket, UTXO chain, and publish cache.
    pub async fn new_module_reg_tester(&self) -> Result<RegTester> {
        let running: Vec<usize> = self
            .node_configs
            .iter()
            .enumerate()
            .filter(|(_, nc)| nc.running.is_some())
            .map(|(i, _)| i)
            .collect();
        assert!(!running.is_empty(), "No running nodes");
        let idx = self.node_counter.fetch_add(1, Ordering::Relaxed) % running.len();
        let node_idx = running[idx];

        let nc = &self.node_configs[node_idx];
        let kontor_client = KontorClient::new(format!("http://localhost:{}/api", nc.api_port))?;
        let bitcoin_config = RegtestConfig {
            bitcoin_rpc_url: self.bitcoin_rpc_url.clone(),
            ..RegtestConfig::default()
        };
        let bitcoin_client = BitcoinClient::new_from_config(&bitcoin_config)?;
        let inner = RegTesterInner::with_port(
            bitcoin_client,
            kontor_client,
            self.identity.address.to_string(),
            self.pool.clone(),
        )
        .await?;

        Ok(RegTester {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Pre-create identity pools using the admin identity for funding.
    /// Populates the cluster's shared IdentityPool.
    async fn pre_create_identity_pools(
        &mut self,
        registered: usize,
        unregistered: usize,
    ) -> Result<()> {
        let total = registered + unregistered;
        if total == 0 {
            return Ok(());
        }

        let secp = Secp256k1::new();
        let per_identity_amount = Amount::from_sat(1_000_000);

        let mut identities: Vec<Identity> = Vec::with_capacity(total);
        let mut outputs = Vec::with_capacity(total + 1);
        for _ in 0..total {
            let mut seed = [0u8; 64];
            rand::thread_rng().fill_bytes(&mut seed);
            let taproot_path = taproot_derivation_path(Network::Regtest);
            let bls_path = bls_derivation_path(Network::Regtest);
            let keypair = derive_taproot_keypair_from_seed(&seed, &taproot_path)?;
            let (x_only_public_key, ..) = keypair.x_only_public_key();
            let address = Address::p2tr(&secp, x_only_public_key, None, Network::Regtest);
            let bls_sk = derive_bls_secret_key_eip2333(&seed, &bls_path)?;

            outputs.push(TxOut {
                value: per_identity_amount,
                script_pubkey: address.script_pubkey(),
            });
            identities.push(Identity {
                address: address.clone(),
                keypair,
                next_funding_utxo: (
                    OutPoint::null(),
                    TxOut {
                        value: Amount::ZERO,
                        script_pubkey: address.script_pubkey(),
                    },
                ),
                bls_secret_key: bls_sk.to_bytes(),
                bls_pubkey: bls_sk.sk_to_pk().to_bytes(),
            });
        }

        // Change output back to the admin identity
        let fee = Amount::from_sat(1000 + (total as u64) * 50);
        let total_needed = per_identity_amount * total as u64 + fee;
        let change = self.identity.next_funding_utxo.1.value - total_needed;
        outputs.push(TxOut {
            value: change,
            script_pubkey: self.identity.address.script_pubkey(),
        });

        let mut funding_tx = Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: self.identity.next_funding_utxo.0,
                ..Default::default()
            }],
            output: outputs,
        };
        test_utils::sign_key_spend(
            &secp,
            &mut funding_tx,
            std::slice::from_ref(&self.identity.next_funding_utxo.1),
            &self.identity.keypair,
            0,
            None,
        )?;

        let funding_txid = funding_tx.compute_txid();
        let raw_tx = hex::encode(serialize_tx(&funding_tx));
        self.reg_tester.send_to_mempool(&[raw_tx]).await?;

        // Update admin identity's UTXO to the change output
        self.identity.next_funding_utxo = (
            OutPoint {
                txid: funding_txid,
                vout: total as u32,
            },
            funding_tx.output[total].clone(),
        );

        // Set each identity's funding UTXO
        for (i, ident) in identities.iter_mut().enumerate() {
            ident.next_funding_utxo = (
                OutPoint {
                    txid: funding_txid,
                    vout: i as u32,
                },
                funding_tx.output[i].clone(),
            );
        }

        // Mine once to confirm all funding outputs
        self.mine(1).await?;

        // Split: unregistered go straight to pool, registered get BLS + issuance
        let unregistered_identities = identities.split_off(registered);
        self.pool.extend_unregistered(unregistered_identities).await;

        // Bundle Issuance + RegisterBlsKey into a single tx so the reactor
        // processes them in declaration order. Issuance must come first so
        // the signer has tokens to pay the gas hold for the registry.registered
        // contract call. Sibling txs can't guarantee this — Bitcoin block
        // ordering between non-dependent reveal txs is ambiguous.
        let mut txids = Vec::with_capacity(registered);
        for ident in &mut identities {
            let proof = RegistrationProof::new(&ident.keypair, &ident.bls_secret_key)?;
            let insts = Insts::direct(vec![
                Inst {
                    gas_limit: 10_000,
                    kind: InstKind::Issuance,
                },
                Inst {
                    gas_limit: 10_000,
                    kind: InstKind::RegisterBlsKey {
                        bls_pubkey: proof.bls_pubkey.to_vec(),
                        schnorr_sig: proof.schnorr_sig.to_vec(),
                        bls_sig: proof.bls_sig.to_vec(),
                    },
                },
            ]);
            let sent = self.reg_tester.send_insts(ident, insts).await?;
            txids.push(sent.reveal_txid.to_string());
        }

        if !txids.is_empty() {
            self.reg_tester.wait_for_txids(&txids).await?;
        }

        // Ensure all nodes have caught up before making identities available.
        // Same 120s ceiling as the post-mine wait — under parallel
        // cluster-test load this catch-up can also exceed 60s.
        let info = self.reg_tester.info().await?;
        self.poll_all_nodes_height(info.height, 120).await?;
        if let Some(consensus_height) = info.consensus_height {
            self.poll_all_nodes_consensus_height(consensus_height, 120)
                .await?;
        }

        self.pool.extend_registered(identities).await;
        tracing::info!(registered, unregistered, "Pre-created identity pools");

        Ok(())
    }

    /// Pop a pre-created identity (with BLS registration and issuance) from the shared pool.
    pub async fn identity(&self) -> Result<(RegTester, Identity)> {
        let rt = self.reg_tester();
        let identity = self.pool.pop_registered().await?;
        Ok((rt, identity))
    }

    /// Mine blocks using the funded identity. Resets the auto-miner cooldown.
    pub async fn mine(&self, count: u64) -> Result<()> {
        self.bitcoin_client
            .generate_to_address(count, &self.identity.address.to_string())
            .await?;
        let _ = self.miner_cmd_tx.send(MinerCmd::Reset).await;
        Ok(())
    }

    /// Pause the auto-miner. Blocks until the miner confirms it's stopped.
    pub async fn pause_auto_miner(&self) {
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let _ = self.miner_cmd_tx.send(MinerCmd::Pause(done_tx)).await;
        let _ = done_rx.await;
    }

    /// Resume the auto-miner. Blocks until the miner confirms it's resumed.
    pub async fn resume_auto_miner(&self) {
        let (done_tx, done_rx) = tokio::sync::oneshot::channel();
        let _ = self.miner_cmd_tx.send(MinerCmd::Resume(done_tx)).await;
        let _ = done_rx.await;
    }

    /// Poll all running nodes until a view call satisfies the check function.
    pub async fn poll_all_nodes_view(
        &self,
        contract: &ContractAddress,
        expr: &str,
        timeout_secs: u64,
        check: impl Fn(&str) -> bool,
    ) -> Result<()> {
        poll_nodes!(self, timeout_secs, format!("{expr}"), |node| {
            matches!(
                node.view(contract, expr).await?,
                indexer_types::ViewResult::Ok { value } if check(&value)
            )
        })
    }

    /// Poll all running nodes until they all reach at least the expected height.
    pub async fn poll_all_nodes_height(
        &self,
        expected_height: u64,
        timeout_secs: u64,
    ) -> Result<()> {
        poll_nodes!(
            self,
            timeout_secs,
            format!("height >= {expected_height}"),
            |node| { node.index().await?.height >= expected_height }
        )
    }

    /// Poll all running nodes until they all reach at least the expected consensus height.
    pub async fn poll_all_nodes_consensus_height(
        &self,
        expected: u64,
        timeout_secs: u64,
    ) -> Result<()> {
        poll_nodes!(
            self,
            timeout_secs,
            format!("consensus_height >= {expected}"),
            |node| { node.index().await?.consensus_height.unwrap_or(0) >= expected }
        )
    }

    /// Assert all running nodes agree on state, by comparing each node's checkpoint
    /// at a common past height. Returns that checkpoint hash.
    ///
    /// Comparing nodes' *current* checkpoints is racy — the auto-miner keeps
    /// advancing block height and a late joiner may still be catching up, so two
    /// nodes read back-to-back can be at different heights (different checkpoints).
    /// Instead we anchor on the lowest height any node has reached and compare each
    /// node's checkpoint *as of* that height: a past checkpoint is immutable once
    /// processed, so it's comparable regardless of how far each node has advanced.
    pub async fn assert_checkpoints_match(&self) -> Result<String> {
        let mut min_height = u64::MAX;
        for nc in &self.node_configs {
            if let Some(cn) = &nc.running {
                min_height = min_height.min(cn.client.index().await?.height);
            }
        }

        let mut reference: Option<(usize, String)> = None;
        for (i, nc) in self.node_configs.iter().enumerate() {
            if let Some(cn) = &nc.running {
                let cp = cn.client.checkpoint_at(min_height).await?;
                match &reference {
                    None => reference = Some((i, cp.hash)),
                    Some((ref_node, ref_hash)) => assert_eq!(
                        &cp.hash, ref_hash,
                        "Node {i} checkpoint diverges from node {ref_node} at height {min_height}"
                    ),
                }
            }
        }
        Ok(reference
            .expect("no running nodes to compare checkpoints")
            .1)
    }

    /// Shut down all nodes.
    pub async fn teardown(mut self) -> Result<()> {
        for nc in &mut self.node_configs {
            if let Some(cn) = &mut nc.running {
                cn.child.kill().await?;
            }
        }
        self._bitcoin_child.kill().await?;
        Ok(())
    }
}

impl Drop for RegTesterCluster {
    fn drop(&mut self) {
        let _ = self._bitcoin_child.start_kill();
        for nc in &mut self.node_configs {
            if let Some(cn) = &mut nc.running {
                let _ = cn.child.start_kill();
            }
        }
    }
}
