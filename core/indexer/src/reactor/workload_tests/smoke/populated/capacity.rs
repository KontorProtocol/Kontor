use std::str::FromStr;

use anyhow::{Context, Result, ensure};
use bitcoin::consensus::encode::VarInt;
use bitcoin::consensus::{deserialize, serialize};
use bitcoin::key::Keypair;
use bitcoin::{Address, Block, BlockHash, OutPoint, Transaction, TxOut};
use indexer_types::Inst;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::super::checked_signed_instructions;
use super::ANCHOR_HEIGHT;
use crate::bitcoin_client::Client;

pub(super) const FUNDING_OUTPUTS: usize = 10_000;
const MAX_BLOCK_WEIGHT: u64 = 4_000_000;

fn weight(coinbase_weight: u64, transaction_weight: u64, transactions: usize) -> Result<u64> {
    let count = u64::try_from(transactions)?
        .checked_add(1)
        .context("transaction count overflow")?;
    let framing = u64::try_from(80 + VarInt(count).size())? * 4;
    coinbase_weight
        .checked_add(transaction_weight)
        .and_then(|weight| weight.checked_add(framing))
        .context("block weight overflow")
}

async fn mine(
    client: &Client,
    address: &Address,
    ordered: &[Transaction],
    submit: bool,
) -> Result<Block> {
    let raw: Vec<_> = ordered
        .iter()
        .map(|tx| hex::encode(serialize(tx)))
        .collect();
    let result: Value = client
        .call(
            "generateblock",
            vec![json!(address.to_string()), json!(raw), json!(submit)],
        )
        .await?;
    let hash = BlockHash::from_str(
        result["hash"]
            .as_str()
            .context("missing capacity block hash")?,
    )?;
    let block: Block = if submit {
        client.get_block(&hash).await?
    } else {
        deserialize(&hex::decode(
            result["hex"]
                .as_str()
                .context("missing unsubmitted capacity block bytes")?,
        )?)?
    };
    ensure!(block.block_hash() == hash);
    ensure!(
        block.txdata[1..] == *ordered,
        "capacity block changed input order"
    );
    Ok(block)
}

pub(super) async fn block(
    client: &Client,
    key: &Keypair,
    address: &Address,
    funding: Vec<(OutPoint, TxOut)>,
    instruction: Inst,
) -> Result<(Block, Vec<Transaction>)> {
    ensure!(funding.len() == FUNDING_OUTPUTS);
    let anchor = client.get_block_hash(ANCHOR_HEIGHT).await?;
    ensure!(client.get_blockchain_info().await?.blocks == ANCHOR_HEIGHT);
    ensure!(client.get_raw_mempool().await?.is_empty());
    let mut funding = funding.into_iter();
    let (commit, reveal, _) = checked_signed_instructions(
        client,
        key,
        funding.next().context("missing capacity funding")?,
        vec![instruction.clone()],
    )
    .await?;
    let mut ordered = vec![commit, reveal.clone()];
    let mut reveals = vec![reveal];
    // Have Bitcoin validate and construct the witness coinbase at the target
    // height without submitting the probe or changing the funding anchor.
    let probe = mine(client, address, &ordered, false).await?;
    ensure!(probe.header.prev_blockhash == anchor);
    ensure!(client.get_blockchain_info().await?.blocks == ANCHOR_HEIGHT);
    ensure!(client.get_block_hash(ANCHOR_HEIGHT).await? == anchor);
    ensure!(client.get_raw_mempool().await?.is_empty());
    let coinbase_weight = probe.txdata[0].weight().to_wu();
    let mut transaction_weight: u64 = ordered.iter().map(|tx| tx.weight().to_wu()).sum();
    let expected_pair_weight = transaction_weight;
    let mut next_pair = None;
    for funding in funding {
        let (commit, reveal, _) =
            checked_signed_instructions(client, key, funding, vec![instruction.clone()]).await?;
        let pair_weight = commit.weight().to_wu() + reveal.weight().to_wu();
        ensure!(
            pair_weight == expected_pair_weight,
            "capacity pair framing changed"
        );
        let candidate_weight = weight(
            coinbase_weight,
            transaction_weight + pair_weight,
            ordered.len() + 2,
        )?;
        if candidate_weight > MAX_BLOCK_WEIGHT {
            next_pair = Some((pair_weight, candidate_weight));
            break;
        }
        transaction_weight += pair_weight;
        reveals.push(reveal.clone());
        ordered.extend([commit, reveal]);
    }
    let (next_pair_weight, next_block_weight) =
        next_pair.context("capacity funding exhausted before the block was full")?;
    let expected_weight = weight(coinbase_weight, transaction_weight, ordered.len())?;
    let block = mine(client, address, &ordered, true).await?;
    ensure!(block.header.prev_blockhash == anchor);
    ensure!(
        block.txdata[0].weight().to_wu() == coinbase_weight,
        "coinbase framing changed after probe"
    );
    ensure!(block.weight().to_wu() == expected_weight && expected_weight <= MAX_BLOCK_WEIGHT);
    ensure!(client.get_raw_mempool().await?.is_empty());
    let bytes = serialize(&block);
    eprintln!(
        "workload_block_capacity={}",
        json!({
            "reveals": reveals.len(), "operations": reveals.len(), "operations_per_reveal": 1,
            "instruction": instruction,
            "bitcoin_transactions": block.txdata.len(), "block_bytes": bytes.len(),
            "block_weight": expected_weight, "max_block_weight": MAX_BLOCK_WEIGHT,
            "coinbase_weight": coinbase_weight, "next_pair_weight": next_pair_weight,
            "weight_with_next_pair": next_block_weight,
            "raw_block_sha256": hex::encode(Sha256::digest(bytes)),
            "claim": "maximum prefix of admitted one-operation commit/reveal pairs; not all possible Bitcoin encodings"
        })
    );
    Ok((block, reveals))
}
