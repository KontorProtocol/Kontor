use std::str::FromStr;

use anyhow::{Context, Result, ensure};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::serialize;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, Block, BlockHash, OutPoint, Transaction, TxIn, TxOut};
use indexer_types::Inst;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::super::signed_instructions;
use crate::bitcoin_client::Client;
use crate::test_utils::sign_key_spend;

pub(super) async fn fund(
    client: &Client,
    key: &Keypair,
    address: &Address,
    funding: (OutPoint, TxOut),
    count: usize,
) -> Result<Vec<(OutPoint, TxOut)>> {
    ensure!(matches!(count, 50 | 500));
    let count_u64 = u64::try_from(count)?;
    let available = funding
        .1
        .value
        .to_sat()
        .checked_sub(1000 + count_u64 * 50)
        .context("insufficient fanout funding")?;
    let mut split = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: funding.0,
            ..Default::default()
        }],
        output: (0..count)
            .map(|index| TxOut {
                value: Amount::from_sat(
                    available / count_u64 + if index == 0 { available % count_u64 } else { 0 },
                ),
                script_pubkey: address.script_pubkey(),
            })
            .collect(),
    };
    sign_key_spend(&Secp256k1::new(), &mut split, &[funding.1], key, 0, None)?;
    let raw = hex::encode(serialize(&split));
    let verdict = client
        .test_mempool_accept(std::slice::from_ref(&raw))
        .await?;
    ensure!(
        verdict.len() == 1 && verdict[0].allowed,
        "fanout rejected: {verdict:?}"
    );
    client.send_raw_transaction(&raw).await?;
    // Confirm the fanout before creating children, so the stress case does not
    // depend on relaxing Bitcoin's shared-ancestor/descendant mempool limits.
    let block = mine(client, address, std::slice::from_ref(&split)).await?;
    ensure!(block.txdata.len() == 2 && block.txdata[1] == split);
    let txid = split.compute_txid();
    split
        .output
        .into_iter()
        .enumerate()
        .map(|(index, output)| {
            Ok((
                OutPoint {
                    txid,
                    vout: u32::try_from(index)?,
                },
                output,
            ))
        })
        .collect()
}

pub(super) async fn block(
    client: &Client,
    key: &Keypair,
    address: &Address,
    funding: Vec<(OutPoint, TxOut)>,
    instructions: Vec<Inst>,
) -> Result<(Block, Vec<Transaction>)> {
    ensure!(instructions.len() == funding.len() * 2);
    let mut ordered = Vec::new();
    let mut reveals = Vec::new();
    for (funding, ops) in funding.into_iter().zip(instructions.as_chunks::<2>().0) {
        let (commit, reveal, _) = signed_instructions(client, key, funding, ops.to_vec()).await?;
        ordered.extend([commit, reveal.clone()]);
        reveals.push(reveal);
    }
    let block = mine(client, address, &ordered).await?;
    ensure!(
        block.txdata[1..] == ordered,
        "Bitcoin changed the workload order"
    );
    ensure!(block.weight().to_wu() <= 4_000_000);
    let bytes = serialize(&block);
    eprintln!(
        "workload_transaction_shape={}",
        json!({
            "reveals": reveals.len(), "operations": instructions.len(),
            "inputs_per_reveal": 1, "operations_per_input": 2,
            "bitcoin_transactions": block.txdata.len(), "block_bytes": bytes.len(),
            "block_weight": block.weight().to_wu(),
            "raw_block_sha256": hex::encode(Sha256::digest(&bytes)),
        })
    );
    Ok((block, reveals))
}

async fn mine(client: &Client, address: &Address, ordered: &[Transaction]) -> Result<Block> {
    let txids: Vec<_> = ordered
        .iter()
        .map(|tx| tx.compute_txid().to_string())
        .collect();
    let response: Value = client
        .call(
            "generateblock",
            vec![json!(address.to_string()), json!(txids)],
        )
        .await?;
    let hash = BlockHash::from_str(
        response["hash"]
            .as_str()
            .context("missing generated block hash")?,
    )?;
    Ok(client.get_block(&hash).await?)
}
