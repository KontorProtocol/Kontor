use std::{collections::HashMap, path::Path, str::FromStr, sync::Arc};

use backon::BackoffBuilder;

use crate::{
    api::{client::Client as KontorClient, ws_client::WebSocketClient},
    bitcoin_client::{
        self, Client as BitcoinClient,
        client::RegtestRpc,
        types::{GetMempoolInfoResult, TestMempoolAcceptResult},
    },
    bls::{
        RegistrationProof, bls_derivation_path, derive_bls_secret_key_eip2333,
        taproot_derivation_path,
    },
    config::{GenesisConfig, GenesisValidatorConfig, RegtestConfig},
    consensus::signing::PrivateKey as Ed25519PrivateKey,
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
    bip32::{DerivationPath, Xpriv},
    consensus::serialize as serialize_tx,
    key::rand::RngCore,
    key::{Keypair, PrivateKey, Secp256k1, rand},
    taproot::TaprootBuilder,
    transaction::Version,
};
use indexer_types::{
    ComposeOutputs, ComposeQuery, Event, Info, Inst, InstructionQuery, Insts, OpWithResult,
    ResultRow, RevealOutputs, RevealQuery, TransactionHex, ViewResult, WsResponse,
};
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

/// Derive a BLS12-381 secret key from a BIP-39 seed using EIP-2333.
///
/// EIP-2333 defines a tree-structured key derivation for BLS12-381 that operates natively
/// on BLS12-381 scalars (unlike BIP-32, which is secp256k1-specific). All EIP-2333 child
/// derivation is hardened by design, so paths are written without the `'` marker.
///
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

struct ConsensusNodeConfig {
    private_key_hex: String,
    listen_addr: String,
    peers: Vec<String>,
    genesis_file: String,
}

async fn run_kontor(
    data_dir: &Path,
    api_port: u16,
    consensus: Option<&ConsensusNodeConfig>,
) -> Result<(Child, KontorClient)> {
    let config = RegtestConfig::default();
    let program = format!("{}/../target/release/kontor", env!("CARGO_MANIFEST_DIR"));
    let mut cmd = Command::new(program);
    cmd.arg("--api-port")
        .arg(api_port.to_string())
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
        .arg(config.bitcoin_rpc_password);

    if let Some(c) = consensus {
        cmd.arg("--consensus-private-key")
            .arg(&c.private_key_hex)
            .arg("--consensus-listen-addr")
            .arg(&c.listen_addr)
            .arg("--genesis-file")
            .arg(&c.genesis_file)
            .arg("--consensus-propose-timeout-ms")
            .arg("500");
        for peer in &c.peers {
            cmd.arg("--consensus-peers").arg(peer);
        }
    }

    let process = cmd.spawn()?;
    let client = KontorClient::new(format!("http://localhost:{api_port}/api"))?;
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
    /// When true, batchable ops skip mining and rely on consensus batching.
    /// Set for RegTesters created from a RegTesterCluster (which has an auto-miner).
    pub cluster_mode: bool,
    /// Cache of published contracts by name — enables idempotent publish.
    pub published_contracts: HashMap<String, ContractAddress>,
    /// Pre-created identities with BLS registration and issuance complete.
    pub identity_pool: std::collections::VecDeque<Identity>,
    /// Pre-created funded identities without BLS registration or issuance.
    pub unregistered_identity_pool: std::collections::VecDeque<Identity>,
}

pub struct SendInstructionResult {
    pub reveal_txid: bitcoin::Txid,
    pub commit_tx_hex: String,
    pub reveal_tx_hex: String,
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
        Self::with_port(identity, bitcoin_client, kontor_client, 9333).await
    }

    pub async fn with_port(
        identity: Identity,
        bitcoin_client: BitcoinClient,
        kontor_client: KontorClient,
        api_port: u16,
    ) -> Result<Self> {
        let ws_client = WebSocketClient::new(api_port).await?;
        Ok(Self {
            identity,
            ws_client,
            bitcoin_client,
            kontor_client,
            cluster_mode: false,
            published_contracts: HashMap::new(),
            identity_pool: std::collections::VecDeque::new(),
            unregistered_identity_pool: std::collections::VecDeque::new(),
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

    /// Mine blocks, sending coinbase rewards to the initial identity's address.
    pub async fn mine(&mut self, count: u64) -> Result<()> {
        self.bitcoin_client
            .generate_to_address(count, &self.identity.address.to_string())
            .await?;
        Ok(())
    }

    pub async fn mempool_info(&self) -> Result<GetMempoolInfoResult> {
        let result = self.bitcoin_client.get_mempool_info().await?;
        Ok(result)
    }

    pub async fn compose_instruction(
        &mut self,
        ident: &mut Identity,
        inst: Inst,
    ) -> Result<(ComposeOutputs, String, String)> {
        self.compose_insts(ident, Insts::single(inst)).await
    }

    pub async fn compose_insts(
        &mut self,
        ident: &mut Identity,
        insts: Insts,
    ) -> Result<(ComposeOutputs, String, String)> {
        let instructions = InstructionQuery::builder()
            .address(ident.address.to_string())
            .x_only_public_key(ident.x_only_public_key().to_string())
            .funding_utxo_ids(outpoint_to_utxo_id(&ident.next_funding_utxo.0))
            .insts(insts)
            .build();
        let query = ComposeQuery::builder()
            .instructions(vec![instructions])
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
        let tap_script = &compose_res.per_participant[0].commit_tap_leaf_script.script;
        let taproot_spend_info = TaprootBuilder::new()
            .add_leaf(0, tap_script.clone())
            .map_err(|e| anyhow!("Failed to add leaf: {}", e))?
            .finalize(&secp, ident.x_only_public_key())
            .map_err(|e| anyhow!("Failed to finalize Taproot tree: {:?}", e))?;
        test_utils::sign_script_spend(
            &secp,
            &taproot_spend_info,
            &compose_res.per_participant[0].commit_tap_leaf_script.script,
            &mut compose_res.reveal_transaction,
            &[compose_res.commit_transaction.output[0].clone()],
            &ident.keypair,
            0,
        )?;

        let commit_tx_hex = hex::encode(serialize_tx(&compose_res.commit_transaction));
        let reveal_tx_hex = hex::encode(serialize_tx(&compose_res.reveal_transaction));

        self.mempool_accept(&[commit_tx_hex.clone(), reveal_tx_hex.clone()])
            .await?;
        Ok((compose_res, commit_tx_hex, reveal_tx_hex))
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
        let (compose_res, commit_tx_hex, reveal_tx_hex) = self.compose_insts(ident, insts).await?;
        let reveal_txid = compose_res.reveal_transaction.compute_txid();
        let txids = self
            .send_to_mempool(&[commit_tx_hex.clone(), reveal_tx_hex.clone()])
            .await?;

        ident.next_funding_utxo = (
            OutPoint {
                txid: txids[0],
                vout: (compose_res.commit_transaction.output.len() - 1) as u32,
            },
            compose_res
                .commit_transaction
                .output
                .last()
                .unwrap()
                .clone(),
        );

        Ok(SendInstructionResult {
            reveal_txid,
            commit_tx_hex,
            reveal_tx_hex,
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
        let needs_mine = !self.cluster_mode
            || insts
                .ops
                .iter()
                .any(|inst| matches!(inst, Inst::Publish { .. }));
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
    pub async fn unregistered_identity(&mut self) -> Result<Identity> {
        self.unregistered_identity_pool
            .pop_front()
            .ok_or_else(|| anyhow!("Unregistered identity pool exhausted — increase pre_create_unregistered_identities count"))
    }

    /// Wait for multiple txids to appear in websocket events (batch or block).
    async fn wait_for_txids(&mut self, target_txids: &[String]) -> Result<()> {
        let mut remaining: std::collections::HashSet<&str> =
            target_txids.iter().map(|s| s.as_str()).collect();
        while !remaining.is_empty() {
            let response = self
                .ws_client
                .next()
                .await
                .context("Failed to receive response from websocket")?;
            let txids = match &response {
                WsResponse::Event {
                    event: Event::Processed { txids, .. },
                } => txids,
                WsResponse::Event {
                    event: Event::BatchProcessed { txids },
                } => txids,
                _ => continue,
            };
            for txid in txids {
                remaining.remove(txid.as_str());
            }
        }
        Ok(())
    }

    /// Pop a pre-created identity with BLS registration and issuance from the pool.
    pub async fn identity(&mut self) -> Result<Identity> {
        self.identity_pool.pop_front().ok_or_else(|| {
            anyhow!("Identity pool exhausted — increase pre_create_identities count")
        })
    }

    /// Pre-create both identity pools in a single funding transaction.
    /// One tx with (registered + unregistered) outputs, one mine, then
    /// pipelines RegisterBlsKey + Issuance for the registered subset.
    pub async fn pre_create_identity_pools(
        &mut self,
        registered: usize,
        unregistered: usize,
    ) -> Result<()> {
        let total = registered + unregistered;
        if total == 0 {
            return Ok(());
        }

        let secp = Secp256k1::new();
        let per_identity_amount = Amount::from_sat(100_000);

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

        // Change output back to the main identity. Fee scales with outputs (~34 bytes each).
        let fee = Amount::from_sat(1000 + (total as u64) * 50);
        let total_needed = per_identity_amount * total as u64 + fee;
        let change = self.identity.next_funding_utxo.1.value - total_needed;
        outputs.push(TxOut {
            value: change,
            script_pubkey: self.identity.address.script_pubkey(),
        });

        // Build and sign the funding tx
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
        self.send_to_mempool(&[raw_tx]).await?;

        // Update main identity's UTXO to the change output
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
        self.unregistered_identity_pool
            .extend(unregistered_identities);

        // Pipeline RegisterBlsKey + Issuance for registered identities
        let mut txids = Vec::with_capacity(registered * 2);
        for ident in &mut identities {
            let proof = RegistrationProof::new(&ident.keypair, &ident.bls_secret_key)?;
            let reg = self
                .send_instruction(
                    ident,
                    Inst::RegisterBlsKey {
                        bls_pubkey: proof.bls_pubkey.to_vec(),
                        schnorr_sig: proof.schnorr_sig.to_vec(),
                        bls_sig: proof.bls_sig.to_vec(),
                    },
                )
                .await?;
            let iss = self.send_instruction(ident, Inst::Issuance).await?;
            txids.push(reg.reveal_txid.to_string());
            txids.push(iss.reveal_txid.to_string());
        }

        if !txids.is_empty() {
            self.wait_for_txids(&txids).await?;
        }

        self.identity_pool.extend(identities);
        tracing::info!(registered, unregistered, "Pre-created identity pools");

        Ok(())
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
        let txids = self.send_to_mempool(&[raw_tx]).await?;
        let txid = txids[0];
        self.mine(1).await?;

        // Refresh self.identity's funding UTXO from the newly matured coinbase
        let info = self.bitcoin_client.get_blockchain_info().await?;
        let block_hash = self
            .bitcoin_client
            .get_block_hash(info.blocks - 100)
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
        Ok(())
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

    pub async fn compose_instruction(
        &mut self,
        ident: &mut Identity,
        inst: Inst,
    ) -> Result<(ComposeOutputs, String, String)> {
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
    ) -> Result<(ComposeOutputs, String, String)> {
        self.inner.lock().await.compose_insts(ident, insts).await
    }

    pub async fn send_instruction(
        &mut self,
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

    pub async fn identity(&mut self) -> Result<Identity> {
        self.inner.lock().await.identity().await
    }

    pub async fn pre_create_identity_pools(
        &self,
        registered: usize,
        unregistered: usize,
    ) -> Result<()> {
        self.inner
            .lock()
            .await
            .pre_create_identity_pools(registered, unregistered)
            .await
    }

    pub async fn cluster_mode(&self) -> bool {
        self.inner.lock().await.cluster_mode
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

    pub async fn get_published(&self, name: &str) -> Option<ContractAddress> {
        self.inner
            .lock()
            .await
            .published_contracts
            .get(name)
            .cloned()
    }

    pub async fn set_published(&self, name: String, address: ContractAddress) {
        self.inner
            .lock()
            .await
            .published_contracts
            .insert(name, address);
    }

    pub async fn checkpoint(&mut self) -> Result<Option<String>> {
        self.inner.lock().await.checkpoint().await
    }

    pub async fn info(&mut self) -> Result<Info> {
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
    pub consensus_port: u16,
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
    genesis_path: std::path::PathBuf,
    miner_cmd_tx: tokio::sync::mpsc::Sender<MinerCmd>,
    _miner_handle: tokio::task::JoinHandle<()>,
    _bitcoin_child: Child,
    _bitcoin_data_dir: TempDir,
    _genesis_dir: TempDir,
}

impl RegTesterCluster {
    /// Start a cluster of `n` validators, all in genesis, all started.
    pub async fn setup(n: usize) -> Result<Self> {
        Self::setup_with(n, n, n).await
    }

    /// Create a cluster with `total` keys, `genesis_count` in genesis, `active` started.
    pub async fn setup_with(total: usize, genesis_count: usize, active: usize) -> Result<Self> {
        assert!(genesis_count <= total, "genesis_count must be <= total");
        assert!(active <= total, "active must be <= total");

        let bitcoin_data_dir = TempDir::new()?;
        let (bitcoin_child, bitcoin_client) = run_bitcoin(bitcoin_data_dir.path()).await?;

        // Create a funded identity for transaction building
        let mut seed = [0u8; 64];
        rand::thread_rng().fill_bytes(&mut seed);
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

        // Generate Ed25519 keypairs for all validators (including inactive)
        let ed25519_keys: Vec<Ed25519PrivateKey> = (0..total)
            .map(|i| {
                let mut key_seed = [0u8; 32];
                key_seed[0] = i as u8;
                key_seed[1] = 0xAB;
                Ed25519PrivateKey::from(key_seed)
            })
            .collect();

        // Write genesis file (only genesis_count validators)
        let genesis_config = GenesisConfig {
            validators: ed25519_keys
                .iter()
                .take(genesis_count)
                .enumerate()
                .map(|(i, key)| GenesisValidatorConfig {
                    x_only_pubkey: format!("{:064x}", i + 1),
                    stake: "100".to_string(),
                    ed25519_pubkey: hex::encode(key.public_key().as_bytes()),
                })
                .collect(),
        };
        let genesis_dir = TempDir::new()?;
        let genesis_path = genesis_dir.path().join("genesis.json");
        std::fs::write(&genesis_path, serde_json::to_string(&genesis_config)?)?;

        // Allocate ports and build NodeConfigs
        let api_ports = allocate_ports(total)?;
        let consensus_ports = allocate_ports(total)?;

        let mut node_configs: Vec<NodeConfig> = (0..total)
            .map(|i| NodeConfig {
                api_port: api_ports[i],
                consensus_port: consensus_ports[i],
                ed25519_key: ed25519_keys[i].clone(),
                data_dir: TempDir::new().expect("Failed to create temp dir"),
                running: None,
            })
            .collect();

        // Start active nodes
        let all_consensus_ports: Vec<u16> =
            node_configs.iter().map(|nc| nc.consensus_port).collect();
        let launch_futures: Vec<_> = node_configs
            .iter()
            .enumerate()
            .take(active)
            .map(|(i, nc)| Self::launch_node(nc, i, &all_consensus_ports, &genesis_path))
            .collect();
        let results = futures_util::future::join_all(launch_futures).await;
        for (i, result) in results.into_iter().enumerate() {
            let (child, client) = result?;
            node_configs[i].running = Some(ClusterNode { client, child });
        }

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

        let cluster = Self {
            bitcoin_client,
            node_configs,
            identity,
            genesis_path,
            miner_cmd_tx,
            _miner_handle: miner_handle,
            _bitcoin_child: bitcoin_child,
            _bitcoin_data_dir: bitcoin_data_dir,
            _genesis_dir: genesis_dir,
        };

        cluster.poll_all_nodes_height(102, 60).await?;

        Ok(cluster)
    }

    async fn launch_node(
        nc: &NodeConfig,
        index: usize,
        all_consensus_ports: &[u16],
        genesis_path: &std::path::Path,
    ) -> Result<(Child, KontorClient)> {
        let consensus_config = ConsensusNodeConfig {
            private_key_hex: hex::encode(nc.ed25519_key.inner().to_bytes()),
            listen_addr: format!("/ip4/127.0.0.1/tcp/{}", nc.consensus_port),
            peers: all_consensus_ports
                .iter()
                .enumerate()
                .filter(|(j, _)| *j != index)
                .map(|(_, &port)| format!("/ip4/127.0.0.1/tcp/{port}"))
                .collect(),
            genesis_file: genesis_path.to_string_lossy().into_owned(),
        };
        run_kontor(nc.data_dir.path(), nc.api_port, Some(&consensus_config)).await
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

    /// Start or restart a node.
    pub async fn start_node(&mut self, index: usize) -> Result<()> {
        let all_consensus_ports: Vec<u16> = self
            .node_configs
            .iter()
            .map(|nc| nc.consensus_port)
            .collect();
        let nc = &self.node_configs[index];
        let (child, client) =
            Self::launch_node(nc, index, &all_consensus_ports, &self.genesis_path).await?;
        self.node_configs[index].running = Some(ClusterNode { client, child });

        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            if self.node_configs[index]
                .running
                .as_ref()
                .unwrap()
                .client
                .index()
                .await
                .is_ok()
            {
                return Ok(());
            }
            if tokio::time::Instant::now() >= deadline {
                bail!("Node {index} failed to become available within 30s");
            }
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
        }
    }

    /// Create a `RegTester` targeting a specific running node.
    /// Cluster-created RegTesters skip mining for batchable ops.
    pub async fn reg_tester(&self, node_index: usize) -> Result<RegTester> {
        let nc = &self.node_configs[node_index];
        let client = &nc.running.as_ref().expect("Node not running").client;
        let mut inner = RegTesterInner::with_port(
            self.identity.clone(),
            self.bitcoin_client.clone(),
            client.clone(),
            nc.api_port,
        )
        .await?;
        inner.cluster_mode = true;
        Ok(RegTester {
            inner: Arc::new(Mutex::new(inner)),
        })
    }

    /// Create an identity with issuance via node 0.
    /// Returns the RegTester and Identity for subsequent operations.
    pub async fn funded_identity(&self) -> Result<(RegTester, Identity)> {
        let mut rt = self.reg_tester(0).await?;
        let mut identity = rt.identity().await?;
        rt.instruction(&mut identity, Inst::Issuance).await?;
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
        expected_height: i64,
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
        expected: i64,
        timeout_secs: u64,
    ) -> Result<()> {
        poll_nodes!(
            self,
            timeout_secs,
            format!("consensus_height >= {expected}"),
            |node| { node.index().await?.consensus_height.unwrap_or(0) >= expected }
        )
    }

    /// Assert all running nodes have matching non-empty checkpoints. Returns the checkpoint value.
    pub async fn assert_checkpoints_match(&self) -> Result<String> {
        let mut checkpoints = Vec::new();
        for (i, nc) in self.node_configs.iter().enumerate() {
            if let Some(cn) = &nc.running {
                let info = cn.client.index().await?;
                let checkpoint = info
                    .checkpoint
                    .unwrap_or_else(|| panic!("Node {i} should have a checkpoint"));
                checkpoints.push((i, info.height, info.consensus_height, checkpoint));
            }
        }
        let (ref_node, _, _, ref_cp) = &checkpoints[0];
        for (i, height, consensus_height, cp) in &checkpoints[1..] {
            assert_eq!(
                cp, ref_cp,
                "Node {i} checkpoint mismatch with node {ref_node} (height={height}, consensus_height={consensus_height:?})"
            );
        }
        Ok(checkpoints.into_iter().next().unwrap().3)
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
