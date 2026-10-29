use anyhow::{Context, Result, anyhow};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::{deserialize, serialize as serialize_bitcoin};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::taproot::TaprootBuilder;
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use indexer_types::{Inst, InstKind, Insts, TransactionRow, serialize};
use libsql::params;

use super::balance;
use crate::bitcoin_client::Client;
use crate::block::filter_map;
use crate::database::queries::{get_contract_bytes_by_id, insert_transaction};
use crate::reactor::executor::{Executor, RuntimeExecutor, is_batchable};
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{ContractAddress, Decimal, native_provenance};
use crate::test_utils::{
    PublicKey, build_inscription, new_mock_transaction, sign_script_spend, test_runtime,
};

fn publish(name: &str, bytes: &[u8]) -> Result<Inst> {
    Ok(Inst {
        gas_limit: 100_000,
        kind: InstKind::Publish {
            name: name.into(),
            bytes: bytes.to_vec(),
            provenance: native_provenance()?,
        },
    })
}

// Signed witness fixtures exercise decoding and execution, not bitcoind policy
// or mining. The prevouts are constructed locally and never broadcast.
fn signed_transaction(
    keys: &[Keypair],
    inputs: Vec<Vec<Inst>>,
    outpoint_seed: u32,
) -> Result<Transaction> {
    assert_eq!(keys.len(), inputs.len());
    let secp = Secp256k1::new();
    let mut scripts = Vec::new();
    let mut spends = Vec::new();
    let mut prevouts = Vec::new();
    let mut tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: Vec::new(),
        output: vec![TxOut {
            value: Amount::from_sat(100_000),
            script_pubkey: ScriptBuf::new(),
        }],
    };
    for (index, (key, ops)) in keys.iter().zip(inputs).enumerate() {
        let xonly = key.x_only_public_key().0;
        let script = build_inscription(
            serialize(&Insts {
                ops,
                aggregate: None,
            })?,
            PublicKey::Taproot(&xonly),
        )?;
        let spend = TaprootBuilder::new()
            .add_leaf(0, script.clone())?
            .finalize(&secp, xonly)
            .map_err(|_| anyhow!("invalid test taproot tree"))?;
        prevouts.push(TxOut {
            value: Amount::from_sat(1_000_000),
            script_pubkey: ScriptBuf::new_p2tr_tweaked(spend.output_key()),
        });
        tx.input.push(TxIn {
            previous_output: OutPoint {
                txid: new_mock_transaction(outpoint_seed + index as u32).txid,
                vout: 0,
            },
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        });
        scripts.push(script);
        spends.push(spend);
    }
    for (index, key) in keys.iter().enumerate() {
        sign_script_spend(
            &secp,
            &spends[index],
            &scripts[index],
            &mut tx,
            &prevouts,
            key,
            index,
        )?;
    }
    Ok(deserialize(&serialize_bitcoin(&tx))?)
}

#[tokio::test]
async fn p1_decoded_multi_input_publication_preserves_duplicate_noop_and_distinct_names()
-> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let secp = Secp256k1::new();
    let keys = [
        Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[22; 32])?),
        Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[23; 32])?),
    ];
    let mut actors = Vec::new();
    for key in &keys {
        let actor = Signer::Id(
            runtime
                .get_or_create_identity(&key.x_only_public_key().0.to_string())
                .await?,
        );
        token::issue_to(
            &mut runtime,
            &Signer::Core(Box::new(Signer::Nobody)),
            HolderRef::from(&actor),
            Decimal::from("100"),
        )
        .await??;
        actors.push(actor);
    }
    let bytes = include_bytes!("../../../../../../test-contracts/binaries/error_test.wasm.br");
    let raw = signed_transaction(
        &keys,
        vec![
            vec![
                publish("decoded-first", bytes)?,
                publish("decoded-first", b"invalid replacement")?,
                publish("decoded-other", bytes)?,
            ],
            vec![publish("decoded-first", b"another invalid replacement")?],
        ],
        400,
    )?;
    let parsed = filter_map((7, raw)).context("recognized publication transaction")?;
    assert_eq!(parsed.index, 7);
    assert_eq!(parsed.inputs.len(), 2);
    assert!(!is_batchable(&parsed.inputs));
    let conn = runtime.get_storage_conn();
    let tx_id = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(1)
            .confirmed_height(1)
            .tx_index(0)
            .txid(parsed.txid.to_string())
            .build(),
    )
    .await?;
    let other_before = balance(&mut runtime, HolderRef::from(&actors[1])).await?;
    let executor = RuntimeExecutor::new(Client::new(
        "http://127.0.0.1:1".into(),
        String::new(),
        String::new(),
    )?);
    let failures = executor
        .execute_transaction(&mut runtime, 1, tx_id, &parsed)
        .await?;
    assert_eq!(failures.iter().map(Vec::len).collect::<Vec<_>>(), [3, 1]);
    assert!(failures.iter().flatten().all(Option::is_none));
    assert_eq!(
        balance(&mut runtime, HolderRef::from(&actors[1])).await?,
        other_before
    );
    let mut receipts = conn
        .query(
            "SELECT input_index, op_index, status FROM contract_results WHERE tx_id = ? ORDER BY input_index, op_index, result_index",
            params![tx_id],
        )
        .await?;
    let mut positions = Vec::new();
    while let Some(row) = receipts.next().await? {
        positions.push((
            row.get::<u32>(0)?,
            row.get::<u32>(1)?,
            row.get::<String>(2)?,
        ));
    }
    assert_eq!(positions, [(0, 0, "Ok".into()), (0, 2, "Ok".into())]);
    for name in ["decoded-first", "decoded-other"] {
        let address = ContractAddress {
            name: name.into(),
            height: 1,
            tx_index: 7,
        };
        let id = runtime.storage.contract_id(&address).await?.unwrap();
        assert_eq!(get_contract_bytes_by_id(&conn, id).await?.unwrap(), bytes);
        assert_eq!(
            runtime.execute(None, None, &address, "succeed()").await?,
            "42"
        );
    }

    let first_address = ContractAddress {
        name: "decoded-first".into(),
        height: 1,
        tx_index: 7,
    };
    let first_id = runtime.storage.contract_id(&first_address).await?.unwrap();
    let next_raw = signed_transaction(
        &keys[..1],
        vec![vec![publish("decoded-first", bytes)?]],
        500,
    )?;
    let next = filter_map((8, next_raw)).context("recognized second publication transaction")?;
    assert_ne!(next.txid, parsed.txid);
    let next_tx_id = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(1)
            .confirmed_height(1)
            .tx_index(1)
            .txid(next.txid.to_string())
            .build(),
    )
    .await?;
    let next_failures = executor
        .execute_transaction(&mut runtime, 1, next_tx_id, &next)
        .await?;
    assert_eq!(next_failures.len(), 1);
    assert_eq!(next_failures[0].len(), 1);
    assert!(next_failures[0][0].is_none());
    let next_address = ContractAddress {
        tx_index: 8,
        ..first_address.clone()
    };
    assert_eq!(
        runtime.storage.contract_id(&first_address).await?,
        Some(first_id)
    );
    assert_eq!(
        get_contract_bytes_by_id(&conn, first_id).await?.unwrap(),
        bytes
    );
    let next_id = runtime.storage.contract_id(&next_address).await?.unwrap();
    assert_ne!(next_id, first_id);
    assert_eq!(
        get_contract_bytes_by_id(&conn, next_id).await?.unwrap(),
        bytes
    );
    assert_eq!(
        runtime
            .execute(None, None, &next_address, "succeed()")
            .await?,
        "42"
    );
    let mut next_receipts = conn
        .query(
            "SELECT contract_id, input_index, op_index, status FROM contract_results WHERE tx_id = ?",
            params![next_tx_id],
        )
        .await?;
    let row = next_receipts
        .next()
        .await?
        .context("second transaction receipt")?;
    assert_eq!(row.get::<u64>(0)?, next_id);
    assert_eq!(row.get::<u32>(1)?, 0);
    assert_eq!(row.get::<u32>(2)?, 0);
    assert_eq!(row.get::<String>(3)?, "Ok");
    assert!(next_receipts.next().await?.is_none());
    assert!(runtime.stack.is_empty().await);
    assert!(runtime.storage.savepoint_stack.is_empty().await);
    Ok(())
}
