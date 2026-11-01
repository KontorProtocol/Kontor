use std::path::Path;

use crate::runtime::GenesisParameters;
use anyhow::{Context, Result, anyhow};
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::{
    OP_0, OP_FALSE,
    all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Keypair, Secp256k1};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, Block, BlockHash, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut,
    Txid, Witness,
};
use indexer_types::{Insts, serialize};
use malachitebft_app_channel::app::types::ProposedValue;
use malachitebft_core_types::{CommitSignature, NilOrVal, Round, Validity};
use tokio::sync::{mpsc, watch};

use super::engine::EngineConfig;
use super::executor::RuntimeExecutor;
use super::mempool_fee_index::MempoolFeeIndex;
use super::{PruneConfig, Reactor, create_executor_session, start_linked_consensus};
use crate::bitcoin_client::Client;
use crate::bitcoin_follower::block::BlockInput;
use crate::consensus::signing::PrivateKey;
use crate::consensus::{Address, CommitCertificate, Ctx, Height, Value, Vote};
use crate::database::Writer;
use crate::runtime::ownership::OwnerService;
use crate::stopper::Shutdown;

pub(super) async fn reactor(
    directory: &Path,
    genesis: &GenesisParameters,
    key: PrivateKey,
    first_height: u64,
) -> Result<Reactor<RuntimeExecutor>> {
    let writer = Writer::new(directory, "certified-fixture.db").await?;
    let service = OwnerService::new();
    let (executor, session, height, hash) = create_executor_session(
        first_height,
        &writer,
        &service,
        Client::new("http://127.0.0.1:1".into(), String::new(), String::new())?,
        None,
        genesis,
        Network::Regtest,
    )
    .await?;
    let consensus = start_linked_consensus(
        EngineConfig {
            private_key: key,
            listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
            persistent_peers: Vec::new(),
            data_dir: directory.to_path_buf(),
            consensus_enabled: false,
            discovery: Default::default(),
        },
        &session,
        &service,
        Network::Regtest,
        None,
        None,
        height,
        MempoolFeeIndex::new(None),
    )
    .await?;
    let (_, blocks) = mpsc::channel(1);
    let (_, mempool) = mpsc::channel(1);
    let (address, _) = watch::channel(None);
    Ok(Reactor::from_session(
        executor,
        session,
        Network::Regtest,
        service,
        blocks,
        mempool,
        Shutdown::new().signal(),
        None,
        None,
        None,
        consensus,
        PruneConfig {
            enabled: false,
            retain_blocks: 144,
        },
        height,
        hash,
        address,
    ))
}

// These bodies exercise retention/recognition, not Bitcoin proof-of-work or UTXO validation.
pub(super) fn block(
    height: u64,
    parent: BlockHash,
    nonce: u32,
    transactions: Vec<Transaction>,
) -> BlockInput {
    let mut block = genesis_block(Network::Regtest);
    block.header.prev_blockhash = parent;
    block.header.nonce = nonce;
    block.txdata[0].input[0].script_sig = Builder::new()
        .push_int(height as i64)
        .push_int(i64::from(nonce))
        .into_script();
    block.txdata.extend(transactions);
    if block
        .txdata
        .iter()
        .any(|tx| tx.input.iter().any(|input| !input.witness.is_empty()))
    {
        block.txdata[0].input[0].witness = Witness::from_slice(&[[0; 32]]);
        let commitment =
            Block::compute_witness_commitment(&block.witness_root().unwrap(), &[0; 32]);
        let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
        script.extend_from_slice(&commitment.to_byte_array());
        block.txdata[0].output.push(TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::from_bytes(script),
        });
    }
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    BlockInput::from_bitcoin(height, block.block_hash(), block)
}

pub(super) fn empty_block(height: u64) -> BlockInput {
    let mut parent = BlockHash::all_zeros();
    let mut result = block(0, parent, 0, Vec::new());
    for height in 1..=height {
        result = block(height, parent, 0, Vec::new());
        parent = result.hash;
    }
    result
}

pub(super) fn certificate(
    key: &PrivateKey,
    value: &Value,
    height: Height,
    round: Round,
) -> CommitCertificate<Ctx> {
    let address = Address::from_public_key(&key.public_key());
    let vote = Vote::new_precommit(height, round, NilOrVal::Val(value.id()), address);
    CommitCertificate {
        height,
        round,
        value_id: value.id(),
        commit_signatures: vec![CommitSignature::new(
            address,
            key.sign(&vote.to_sign_bytes()),
        )],
    }
}

pub(super) fn proposal(
    reactor: &mut Reactor<RuntimeExecutor>,
    value: Value,
    height: Height,
    round: Round,
) {
    reactor
        .consensus
        .undecided
        .entry(height)
        .or_default()
        .insert(
            round,
            ProposedValue {
                height,
                round,
                valid_round: Round::Nil,
                proposer: reactor.consensus.address,
                value,
                validity: Validity::Valid,
            },
        );
}

pub(super) fn transaction(key: &Keypair, instructions: Insts, nonce: u32) -> Result<Transaction> {
    let secp = Secp256k1::new();
    let public = key.x_only_public_key().0;
    let mut script = Builder::new()
        .push_slice(public.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0);
    for chunk in serialize(&instructions)?.chunks(520) {
        script = script.push_slice(PushBytesBuf::try_from(chunk.to_vec())?);
    }
    let script = script.push_opcode(OP_ENDIF).into_script();
    let spend = TaprootBuilder::new()
        .add_leaf(0, script.clone())?
        .finalize(&secp, public)
        .map_err(|_| anyhow!("fixture taproot tree"))?;
    let control = spend
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .context("fixture control block")?;
    let witness = Witness::from_slice(&[vec![0; 64], script.into_bytes(), control.serialize()]);
    Ok(Transaction {
        version: Version::TWO,
        lock_time: LockTime::from_consensus(nonce),
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_byte_array([1; 32]),
                vout: nonce,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: ScriptBuf::new(),
        }],
    })
}
