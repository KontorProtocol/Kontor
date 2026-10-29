use std::time::Duration;

use anyhow::{Context, Result};
use bitcoin::absolute::LockTime;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::{deserialize, serialize as serialize_bitcoin};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::{Block as BitcoinBlock, Network, Transaction, Witness};
use indexer_types::Block;
use libsql::{Connection, Value, params};
use malachitebft_engine::node::NodeRef;
use testlib::sample_provenance;
use tokio::time::timeout;

use super::aggregate_error_tests::reactor;
use crate::block::filter_map;
use crate::consensus::Height;
use crate::consensus::signing::PrivateKey;
use crate::database::confirmation::get_confirmation_position;
use crate::database::queries::get_transaction_by_txid;
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{
    ContractAddress, Decimal, GenesisValidator, Runtime, TransactionContext, from_wave_expr,
};
use crate::test_utils::{new_mock_block_hash, signed_confirmation_call, test_runtime_with_genesis};

struct StopEngine(NodeRef);

impl Drop for StopEngine {
    fn drop(&mut self) {
        self.0.stop(None);
    }
}

// Synthetic raw blocks exercise parsing and coordinator behavior. Constructed
// prevouts and headers do not establish Bitcoin consensus or mempool acceptance.
fn confirmation_block(tx: &Transaction, position: usize) -> Result<Block> {
    assert!(position >= 2);
    let mut raw = genesis_block(Network::Regtest);
    raw.header.prev_blockhash = new_mock_block_hash(1);
    for index in 1..position {
        let mut unrelated = tx.clone();
        unrelated.input[0].witness = Witness::new();
        unrelated.lock_time = LockTime::from_consensus(index as u32);
        raw.txdata.push(unrelated);
    }
    raw.txdata.push(tx.clone());
    raw.header.merkle_root = raw.compute_merkle_root().context("fixture merkle root")?;
    let raw: BitcoinBlock = deserialize(&serialize_bitcoin(&raw))?;
    assert!(raw.txdata[0].is_coinbase());
    assert!(raw.check_merkle_root());
    let hash = raw.block_hash();
    let parsed: Vec<_> = raw
        .txdata
        .into_iter()
        .enumerate()
        .filter_map(filter_map)
        .collect();
    assert_eq!(parsed.len(), 1);
    assert_eq!(parsed[0].index, position as u32);
    Ok(Block {
        height: 2,
        hash,
        prev_hash: new_mock_block_hash(1),
        transactions: parsed,
    })
}

async fn effects(conn: &Connection) -> Result<Vec<Vec<Vec<Value>>>> {
    let mut snapshot = Vec::new();
    for table in [
        "contracts",
        "contract_provenance",
        "contract_state",
        "current_contract_state",
        "contract_results",
        "transaction_execution_usage",
        "depositor_footprint",
    ] {
        let mut rows = conn
            .query(&format!("SELECT * FROM {table} ORDER BY 1, 2"), ())
            .await?;
        let count = rows.column_count();
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(
                (0..count)
                    .map(|column| row.get_value(column))
                    .collect::<libsql::Result<Vec<_>>>()?,
            );
        }
        snapshot.push(values);
    }
    Ok(snapshot)
}

async fn assert_successful_write(
    runtime: &mut Runtime,
    txid: &str,
    address: &ContractAddress,
) -> Result<()> {
    let conn = runtime.get_storage_conn();
    let mut rows = conn
        .query(
            "SELECT r.status, r.value, r.func, r.gas FROM contract_results r
         JOIN transactions t ON t.id = r.tx_id WHERE t.txid = ?",
            params![txid],
        )
        .await?;
    let row = rows.next().await?.context("successful write receipt")?;
    assert_eq!(row.get::<String>(0)?, "Ok");
    assert_eq!(row.get::<String>(1)?, "\"é\\n\"");
    assert_eq!(row.get::<String>(2)?, "write-result-payload");
    assert!(row.get::<u64>(3)? > 0);
    assert!(rows.next().await?.is_none());
    let state: Vec<u64> = from_wave_expr(
        &runtime
            .execute(None, None, address, "storage-state()")
            .await?,
    );
    assert_eq!(state, [1, 0, 0, 1]);
    Ok(())
}

async fn run_case(batched: bool) -> Result<()> {
    let secp = Secp256k1::new();
    let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[71; 32])?);
    let public_key = key.x_only_public_key().0.to_string();
    let (mut runtime, dir, _name) = test_runtime_with_genesis(&[GenesisValidator {
        x_only_pubkey: public_key.clone(),
        ed25519_pubkey: PrivateKey::from([17; 32]).public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }])
    .await?;
    let core = Signer::Core(Box::new(Signer::Nobody));
    token::issue_to(
        &mut runtime,
        &core,
        HolderRef::XOnlyPubkey(public_key),
        Decimal::from("100"),
    )
    .await??;
    runtime
        .set_context(
            1,
            Some(TransactionContext::builder().tx_index(0).build()),
            None,
            None,
        )
        .await;
    runtime
        .publish(
            &core,
            runtime.core_payment(),
            "confirmation-fixture",
            include_bytes!("../../../../test-contracts/binaries/error_test.wasm.br"),
            &sample_provenance(),
        )
        .await?;
    let address = ContractAddress {
        name: "confirmation-fixture".into(),
        height: 1,
        tx_index: 0,
    };
    let raw = signed_confirmation_call(&key, address.clone())?;
    let txid = raw.compute_txid().to_string();
    let mut reactor = reactor(runtime, &dir).await?;
    let cleanup = StopEngine(reactor.consensus.engine_handle.actor.clone());
    let conn = reactor.db_conn();
    let original = effects(&conn).await?;
    let result = async {
        if batched {
            reactor
                .process_decided_batch(
                    1,
                    new_mock_block_hash(1),
                    Height::new(1),
                    &[],
                    &[raw.clone()],
                    None,
                )
                .await?;
            let row = get_transaction_by_txid(&conn, &txid)
                .await?
                .context("batch executed")?;
            assert_eq!(row.height, 1);
            assert_eq!(row.batch_height, Some(1));
            assert_eq!(row.confirmed_height, None);
            assert_eq!(get_confirmation_position(&conn, &txid).await?, None);
            assert_successful_write(&mut reactor.runtime, &txid, &address).await?;
        }
        let before_confirmation = effects(&conn).await?;
        let block = confirmation_block(&raw, 2)?;
        let (count, ops, failures) = reactor.execute_block(&block).await?;
        assert_eq!(count, usize::from(!batched));
        assert_eq!(ops, u64::from(!batched));
        assert!(failures.iter().flatten().flatten().all(Option::is_none));
        let row = get_transaction_by_txid(&conn, &txid)
            .await?
            .context("confirmed transaction")?;
        assert_eq!(row.confirmed_height, Some(2));
        assert_eq!(row.tx_index, Some(0));
        assert_eq!(get_confirmation_position(&conn, &txid).await?, Some(2));
        assert_successful_write(&mut reactor.runtime, &txid, &address).await?;
        let applied = effects(&conn).await?;
        assert_ne!(applied, original);
        if batched {
            assert_eq!(
                applied, before_confirmation,
                "confirmation must not execute or charge again"
            );
            reactor.rollback(1).await?;
            let rolled_back = get_transaction_by_txid(&conn, &txid)
                .await?
                .context("batch survives reorg")?;
            assert_eq!(rolled_back.id, row.id);
            assert_eq!(rolled_back.height, 1);
            assert_eq!(rolled_back.batch_height, Some(1));
            assert_eq!(rolled_back.confirmed_height, None);
            assert_eq!(get_confirmation_position(&conn, &txid).await?, None);
            assert_eq!(effects(&conn).await?, applied);
            let replacement = confirmation_block(&raw, 4)?;
            assert_ne!(replacement.hash, block.hash);
            let (count, ops, _) = reactor.execute_block(&replacement).await?;
            assert_eq!((count, ops), (0, 0));
            assert_eq!(get_confirmation_position(&conn, &txid).await?, Some(4));
            let reconfirmed = get_transaction_by_txid(&conn, &txid).await?.unwrap();
            assert_eq!(reconfirmed.id, row.id);
            assert_eq!(reconfirmed.tx_index, Some(0));
            assert_eq!(effects(&conn).await?, applied);
        }
        Ok(())
    }
    .await;
    cleanup.0.stop(None);
    timeout(
        Duration::from_secs(30),
        &mut reactor.consensus.engine_handle.handle,
    )
    .await??;
    result
}

#[tokio::test]
async fn unbatched_raw_confirmation_position_differs_from_legacy_ordinal() -> Result<()> {
    run_case(false).await
}

#[tokio::test]
async fn batched_confirmation_reorg_and_reconfirmation_preserve_execution_effects() -> Result<()> {
    run_case(true).await
}
