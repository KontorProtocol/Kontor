use std::collections::BTreeSet;
use std::str::FromStr;

use anyhow::{Context, Result, ensure};
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::{
    Address, Block as BitcoinBlock, BlockHash, Network, OutPoint, Transaction, TxOut,
    XOnlyPublicKey,
};
use indexer_types::{Block, ContractAddress, Inst, InstKind};
use serde_json::json;
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::super::{ANCHOR_HEIGHT, BitcoinProcess, FUNDING_SEED, GAS_LIMIT, decode_block};
use super::{many, sequence_funding};
use crate::bitcoin_client::Client;
use crate::bitcoin_client::client::RegtestRpc;
use crate::bls::taproot_derivation_path;
use crate::reg_tester::{derive_taproot_keypair_from_seed, workload_bitcoin};

type Funding = (OutPoint, TxOut);

#[derive(Clone)]
pub(super) struct BlockInput {
    pub(super) raw: Vec<u8>,
    pub(super) block: Block,
    pub(super) reveals: Vec<Transaction>,
}

impl BlockInput {
    pub(super) fn decode(
        raw: Vec<u8>,
        height: u64,
        parent: BlockHash,
        funding: &[Funding],
        instructions: &[Inst],
        signer: XOnlyPublicKey,
    ) -> Result<Self> {
        ensure!(matches!(funding.len(), 50 | 500));
        ensure!(instructions.len() == funding.len() * 2);
        let bitcoin: BitcoinBlock = deserialize(&raw)?;
        ensure!(bitcoin.weight().to_wu() <= 4_000_000);
        ensure!(bitcoin.txdata.len() == funding.len() * 2 + 1);
        let block = decode_block(&raw, height, bitcoin.block_hash(), parent)?;
        ensure!(block.transactions.len() == funding.len());
        let mut reveals = Vec::new();
        let mut seen = BTreeSet::new();
        for (index, (transaction, funding)) in block.transactions.iter().zip(funding).enumerate() {
            ensure!(seen.insert(funding.0), "duplicate block funding");
            let commit = &bitcoin.txdata[index * 2 + 1];
            let reveal = &bitcoin.txdata[index * 2 + 2];
            ensure!(commit.input.len() == 1 && commit.input[0].previous_output == funding.0);
            ensure!(!commit.output.is_empty() && reveal.input.len() == 1);
            ensure!(
                reveal.input[0].previous_output
                    == OutPoint {
                        txid: commit.compute_txid(),
                        vout: 0
                    }
            );
            ensure!(transaction.index == u32::try_from(index * 2 + 2)?);
            ensure!(transaction.txid == reveal.compute_txid() && transaction.inputs.len() == 1);
            let input = &transaction.inputs[0];
            ensure!(
                input.input_index == 0
                    && input.previous_output == reveal.input[0].previous_output
                    && input.x_only_pubkey == signer
                    && input.insts.aggregate.is_none()
                    && input.insts.ops == instructions[index * 2..index * 2 + 2],
                "sequence decoded operations or signer differ at transaction {index}"
            );
            reveals.push(reveal.clone());
        }
        Ok(Self {
            raw,
            block,
            reveals,
        })
    }
}

pub(super) async fn generate(
    client: &Client,
    key: &Keypair,
    address: &Address,
    funding: &[Vec<Funding>],
    instructions: &[Vec<Inst>],
) -> Result<Vec<BlockInput>> {
    ensure!(matches!(funding.len(), 2 | 6 | 7) && instructions.len() == funding.len());
    let mut distinct = BTreeSet::new();
    for (funding, instructions) in funding.iter().zip(instructions) {
        ensure!(matches!(funding.len(), 50 | 500) && instructions.len() == funding.len() * 2);
        for (outpoint, output) in funding {
            ensure!(
                distinct.insert(*outpoint),
                "sequence reuses a funding output"
            );
            ensure!(output.script_pubkey == address.script_pubkey());
        }
    }
    ensure!(client.get_blockchain_info().await?.blocks == ANCHOR_HEIGHT);
    ensure!(client.get_raw_mempool().await?.is_empty());
    let mut parent = client.get_block_hash(ANCHOR_HEIGHT).await?;
    let mut inputs = Vec::new();
    let mut txids = BTreeSet::new();
    for (ordinal, (funding, instructions)) in funding.iter().zip(instructions).enumerate() {
        let height = ANCHOR_HEIGHT
            .checked_add(u64::try_from(ordinal)? + 1)
            .context("sequence height overflow")?;
        let (raw, reveals) =
            many::block(client, key, address, funding.clone(), instructions.clone()).await?;
        let input = BlockInput::decode(
            serialize(&raw),
            height,
            parent,
            funding,
            instructions,
            key.x_only_public_key().0,
        )?;
        ensure!(input.reveals == reveals);
        ensure!(client.get_blockchain_info().await?.blocks == height);
        ensure!(client.get_block_hash(height).await? == input.block.hash);
        ensure!(client.get_raw_mempool().await?.is_empty());
        for transaction in &input.block.transactions {
            ensure!(
                txids.insert(transaction.txid),
                "sequence repeats a transaction"
            );
        }
        parent = input.block.hash;
        eprintln!(
            "workload_sequence_input={}",
            json!({
                "ordinal":ordinal,"height":height,"hash":input.block.hash,"parent":input.block.prev_hash,
                "reveals":input.reveals.len(),"operations":instructions.len(),
                "raw_sha256":hex::encode(Sha256::digest(&input.raw)),
            })
        );
        inputs.push(input);
    }
    Ok(inputs)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind; signed sequence input generation and decoding, not execution qualification"]
async fn workload_sequence_inputs_preserve_chain_and_operations() -> Result<()> {
    for (blocks, transactions) in [(2, 50), (7, 500)] {
        let directory = TempDir::new()?;
        let (child, client) = workload_bitcoin(directory.path()).await?;
        let mut bitcoin = BitcoinProcess(child);
        let key = derive_taproot_keypair_from_seed(
            &FUNDING_SEED,
            &taproot_derivation_path(Network::Regtest),
        )?;
        let address = Address::p2tr(
            &Secp256k1::new(),
            key.x_only_public_key().0,
            None,
            Network::Regtest,
        );
        let mined = client
            .generate_to_address(ANCHOR_HEIGHT - 1, &address.to_string())
            .await?;
        let first = client.get_block(&BlockHash::from_str(&mined[0])?).await?;
        let funding = (
            OutPoint {
                txid: first.txdata[0].compute_txid(),
                vout: 0,
            },
            first.txdata[0].output[0].clone(),
        );
        let funding =
            sequence_funding::prepare(&client, &key, &address, funding, blocks, transactions)
                .await?;
        let contract = ContractAddress {
            name: "mixedcounter".into(),
            height: ANCHOR_HEIGHT,
            tx_index: 7,
        };
        let instructions: Vec<Vec<Inst>> = (0..blocks)
            .map(|block| {
                (0..transactions * 2)
                    .map(|op| Inst {
                        gas_limit: GAS_LIMIT,
                        kind: InstKind::Call {
                            contract: contract.clone(),
                            expr: if op % 2 == 0 {
                                "increment()".into()
                            } else {
                                format!("fill-blob({})", block * transactions + op / 2)
                            },
                        },
                    })
                    .collect()
            })
            .collect();
        let mut duplicate = funding.clone();
        duplicate[1][0] = duplicate[0][0].clone();
        ensure!(
            generate(&client, &key, &address, &duplicate, &instructions)
                .await
                .is_err()
        );
        ensure!(
            client.get_blockchain_info().await?.blocks == ANCHOR_HEIGHT
                && client.get_raw_mempool().await?.is_empty()
        );
        let inputs = generate(&client, &key, &address, &funding, &instructions).await?;
        ensure!(inputs.len() == blocks);
        for (ordinal, input) in inputs.iter().enumerate() {
            let mut wrong = instructions[ordinal].clone();
            wrong[0].gas_limit += 1;
            ensure!(
                BlockInput::decode(
                    input.raw.clone(),
                    input.block.height,
                    input.block.prev_hash,
                    &funding[ordinal],
                    &wrong,
                    key.x_only_public_key().0
                )
                .is_err()
            );
            ensure!(
                BlockInput::decode(
                    input.raw.clone(),
                    input.block.height,
                    input.block.hash,
                    &funding[ordinal],
                    &instructions[ordinal],
                    key.x_only_public_key().0
                )
                .is_err()
            );
        }
        bitcoin.0.kill().await?;
    }
    Ok(())
}
