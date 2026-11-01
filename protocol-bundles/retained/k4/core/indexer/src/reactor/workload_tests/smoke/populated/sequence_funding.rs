use std::collections::BTreeSet;
use std::str::FromStr;

use anyhow::{Context, Result, ensure};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::serialize;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::transaction::Version;
use bitcoin::{Address, Amount, BlockHash, Network, OutPoint, Transaction, TxIn, TxOut};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::TempDir;

use super::super::{ANCHOR_HEIGHT, BitcoinProcess, FUNDING_SEED};
use crate::bitcoin_client::Client;
use crate::bitcoin_client::client::RegtestRpc;
use crate::bls::taproot_derivation_path;
use crate::reg_tester::{derive_taproot_keypair_from_seed, workload_bitcoin};
use crate::test_utils::sign_key_spend;

type Funding = (OutPoint, TxOut);

fn outputs(transaction: &Transaction) -> Result<Vec<Funding>> {
    let txid = transaction.compute_txid();
    transaction
        .output
        .iter()
        .enumerate()
        .map(|(index, output)| {
            Ok((
                OutPoint {
                    txid,
                    vout: u32::try_from(index)?,
                },
                output.clone(),
            ))
        })
        .collect()
}

fn split(key: &Keypair, address: &Address, funding: Funding, count: usize) -> Result<Transaction> {
    ensure!((1..=500).contains(&count));
    let count = u64::try_from(count)?;
    let fee = count
        .checked_mul(50)
        .and_then(|fee| fee.checked_add(1000))
        .context("sequence funding fee overflow")?;
    let available = funding
        .1
        .value
        .to_sat()
        .checked_sub(fee)
        .context("insufficient sequence funding")?;
    ensure!(available / count > 0);
    let mut transaction = Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: funding.0,
            ..Default::default()
        }],
        output: (0..count)
            .map(|index| TxOut {
                value: Amount::from_sat(
                    available / count + if index == 0 { available % count } else { 0 },
                ),
                script_pubkey: address.script_pubkey(),
            })
            .collect(),
    };
    sign_key_spend(
        &Secp256k1::new(),
        &mut transaction,
        &[funding.1],
        key,
        0,
        None,
    )?;
    ensure!(transaction.weight().to_wu() <= 400_000);
    ensure!(
        transaction
            .output
            .iter()
            .map(|output| output.value.to_sat())
            .sum::<u64>()
            == available
    );
    Ok(transaction)
}

async fn admitted(client: &Client, transaction: &Transaction) -> Result<()> {
    let verdict = client
        .test_mempool_accept(&[hex::encode(serialize(transaction))])
        .await?;
    ensure!(
        verdict.len() == 1 && verdict[0].txid == transaction.compute_txid() && verdict[0].allowed,
        "sequence funding rejected: {verdict:?}"
    );
    Ok(())
}

pub(super) async fn prepare(
    client: &Client,
    key: &Keypair,
    address: &Address,
    funding: Funding,
    blocks: usize,
    transactions: usize,
) -> Result<Vec<Vec<Funding>>> {
    ensure!(matches!(blocks, 2 | 6 | 7) && matches!(transactions, 50 | 500));
    prepare_groups(client, key, address, funding, &vec![transactions; blocks]).await
}

pub(super) async fn prepare_groups(
    client: &Client,
    key: &Keypair,
    address: &Address,
    funding: Funding,
    counts: &[usize],
) -> Result<Vec<Vec<Funding>>> {
    prepare_to_groups(
        client,
        key,
        address,
        funding,
        counts,
        &vec![address.clone(); counts.len()],
    )
    .await
}

pub(super) async fn prepare_with_api(
    client: &Client,
    key: &Keypair,
    address: &Address,
    funding: Funding,
    counts: &[usize],
    api_address: &Address,
) -> Result<Vec<Vec<Funding>>> {
    let mut counts = counts.to_vec();
    let mut destinations = vec![address.clone(); counts.len()];
    counts.push(1);
    destinations.push(api_address.clone());
    prepare_to_groups(client, key, address, funding, &counts, &destinations).await
}

async fn prepare_to_groups(
    client: &Client,
    key: &Keypair,
    address: &Address,
    funding: Funding,
    counts: &[usize],
    destinations: &[Address],
) -> Result<Vec<Vec<Funding>>> {
    ensure!(!counts.is_empty() && counts.iter().all(|count| *count > 0));
    ensure!(counts.len() == destinations.len());
    let total = counts.iter().try_fold(0usize, |sum, count| {
        sum.checked_add(*count).context("funding count overflow")
    })?;
    ensure!(
        total <= 20_000,
        "funding horizon exceeds bounded setup capacity"
    );
    let chunks: Vec<_> = counts
        .iter()
        .zip(destinations)
        .flat_map(|(count, destination)| {
            (0..*count)
                .step_by(500)
                .map(move |start| ((*count - start).min(500), destination))
        })
        .collect();
    ensure!(client.get_blockchain_info().await?.blocks == ANCHOR_HEIGHT - 1);
    ensure!(client.get_raw_mempool().await?.is_empty());
    let previous = client.get_block_hash(ANCHOR_HEIGHT - 1).await?;
    let parent = split(key, address, funding, chunks.len())?;
    admitted(client, &parent).await?;
    client
        .send_raw_transaction(&hex::encode(serialize(&parent)))
        .await?;
    let mut ordered = vec![parent.clone()];
    let mut flat = Vec::with_capacity(total);
    let mut distinct = BTreeSet::new();
    for (funding, (count, destination)) in outputs(&parent)?.into_iter().zip(chunks) {
        let child = split(key, destination, funding, count)?;
        // Retaining siblings would exceed Bitcoin's connected-cluster size limit.
        // Each child is admission-checked with only its parent in the mempool.
        ensure!(client.get_raw_mempool().await? == [parent.compute_txid()]);
        admitted(client, &child).await?;
        ensure!(client.get_raw_mempool().await? == [parent.compute_txid()]);
        let fundings = outputs(&child)?;
        for (outpoint, _) in &fundings {
            ensure!(distinct.insert(*outpoint), "reused sequence funding output");
        }
        flat.extend(fundings);
        ordered.push(child);
    }
    let raw: Vec<_> = ordered
        .iter()
        .map(|tx| hex::encode(serialize(tx)))
        .collect();
    let generated: Value = client
        .call(
            "generateblock",
            vec![json!(address.to_string()), json!(raw)],
        )
        .await?;
    let hash = BlockHash::from_str(
        generated["hash"]
            .as_str()
            .context("missing funding block")?,
    )?;
    let block = client.get_block(&hash).await?;
    ensure!(client.get_blockchain_info().await?.blocks == ANCHOR_HEIGHT);
    ensure!(client.get_block_hash(ANCHOR_HEIGHT).await? == hash);
    ensure!(block.header.prev_blockhash == previous && block.txdata[1..] == ordered);
    ensure!(block.weight().to_wu() <= 4_000_000);
    ensure!(client.get_raw_mempool().await?.is_empty());
    ensure!(flat.len() == total && distinct.len() == total);
    let mut offset = 0;
    let result = counts
        .iter()
        .map(|count| {
            let group = flat[offset..offset + count].to_vec();
            offset += count;
            group
        })
        .collect();
    eprintln!(
        "workload_sequence_funding={}",
        json!({"groups":counts,
            "confirmed_outputs":distinct.len(),"anchor_height":ANCHOR_HEIGHT,
            "anchor_hash":hash,"raw_block_sha256":hex::encode(Sha256::digest(serialize(&block))),
            "transaction_weights":ordered.iter().map(|tx|tx.weight().to_wu()).collect::<Vec<_>>(),
            "admission":"each child individually with only parent present; entire tree accepted in block"})
    );
    Ok(result)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind; sequence funding setup only, not workload qualification"]
async fn workload_sequence_funding_confirms_before_first_step() -> Result<()> {
    for (blocks, transactions) in [(2, 50), (6, 500), (7, 500)] {
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
        let funding = outputs(&first.txdata[0])?.remove(0);
        let result = prepare(&client, &key, &address, funding, blocks, transactions).await?;
        for fundings in &result {
            ensure!(fundings.len() == transactions);
            for (outpoint, output) in [fundings.first(), fundings.last()].into_iter().flatten() {
                let unspent: Value = client
                    .call(
                        "gettxout",
                        vec![json!(outpoint.txid), json!(outpoint.vout), json!(false)],
                    )
                    .await?;
                ensure!(unspent["confirmations"].as_u64() == Some(1));
                ensure!(
                    unspent["scriptPubKey"]["hex"].as_str()
                        == Some(hex::encode(&output.script_pubkey).as_str())
                );
            }
        }
        bitcoin.0.kill().await?;
    }
    Ok(())
}
