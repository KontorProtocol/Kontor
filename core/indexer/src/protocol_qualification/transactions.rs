use std::sync::Arc;

use anyhow::{Context, Result, anyhow, ensure};
use bitcoin::absolute::LockTime;
use bitcoin::consensus::serialize as bitcoin_bytes;
use bitcoin::opcodes::{
    OP_0, OP_FALSE,
    all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, BlockHash, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness,
    hashes::Hash,
};
use indexer_types::{
    BlockRow, BuildProvenance, CommitId, ContractAddress, Forge, Inst, InstKind, Insts, Platform,
    Source, TransactionRow, serialize,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::{NETWORK, state};
use crate::database::queries::{insert_block, insert_transaction};
use crate::protocol::coordinator::linked::{
    begin_canonical_unit, execute_transaction, finish_canonical_unit, recognize_transaction,
};
use crate::protocol::coordinator::selection::{ApplicationPosition, select_legacy_p1};
use crate::runtime::ownership::OwnerService;
use crate::runtime::ownership::adapter::HostFailure;
use crate::runtime::pool::LinkedSession;

const COUNTER: &[u8] = include_bytes!("../../../../test-contracts/binaries/counter.wasm.br");
const HEIGHT: u64 = 3;
const TX_INDEX: u32 = 7;

fn counter() -> ContractAddress {
    ContractAddress {
        name: "counter".into(),
        height: HEIGHT,
        tx_index: TX_INDEX,
    }
}

fn fixture() -> Result<Transaction> {
    let call = |expr: &str, gas_limit| Inst {
        gas_limit,
        kind: InstKind::Call {
            contract: counter(),
            expr: expr.into(),
        },
    };
    // Like testlib's sample_provenance, this is a deliberately synthetic claim.
    // Fixture reproducibility is checked by the pinned contract build workflow.
    let provenance = BuildProvenance {
        source: Source {
            forge: Forge::GitHub,
            owner: "kontor".into(),
            repo: "test".into(),
            commit: CommitId::Sha1([0; 20]),
        },
        image: "kontorprotocol/kontor-build@sha256:test".into(),
        platform: Platform::LinuxArm64,
    };
    let instructions = Insts::direct(vec![
        Inst {
            gas_limit: 100_000,
            kind: InstKind::Issuance,
        },
        Inst {
            gas_limit: 100_000,
            kind: InstKind::Publish {
                name: "counter".into(),
                bytes: COUNTER.to_vec(),
                provenance,
            },
        },
        call("increment()", 100_000),
        call("set-entry(\"alpha\", \"value\")", 100_000),
        call("set-blob-then-fail(\"must roll back\")", 100_000),
        call("missing-function()", 100_000),
        call("fill-blob(16)", 1),
        call("increment()", 100_000),
    ]);
    let secp = Secp256k1::new();
    let key = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[38; 32])?);
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
        .map_err(|_| anyhow!("qualification taproot leaf failed to finalize"))?;
    let control = spend
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .context("missing fixture leaf")?;
    let mut witness = Witness::new();
    // Bitcoin signature acceptance belongs to ingestion, outside this execution check.
    witness.push([0u8; 64]);
    witness.push(script.as_bytes());
    witness.push(control.serialize());
    Ok(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
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

pub(super) async fn run(service: &OwnerService, session: &LinkedSession) -> Result<Value> {
    let conn = &session.conn;
    let raw = fixture()?;
    let bytes = bitcoin_bytes(&raw);
    let before = state(conn).await?;
    let preparation = select_legacy_p1(
        conn,
        NETWORK,
        ApplicationPosition::Preparation {
            anchor_height: HEIGHT - 1,
            anchor_hash: Some(BlockHash::from_byte_array([2; 32])),
        },
    )
    .await?;
    let recognized =
        recognize_transaction(&session.executor, &preparation, NETWORK, bytes.clone())?
            .map_err(|e| anyhow!(e))?
            .context("qualification transaction was not recognized")?;
    ensure!(
        recognized.txid == raw.compute_txid(),
        "recognition changed txid"
    );
    ensure!(
        recognized.inputs == [(0, 8)],
        "recognition changed operation positions"
    );
    let mut trailing = bytes.clone();
    trailing.push(1);
    ensure!(
        recognize_transaction(&session.executor, &preparation, NETWORK, trailing)?.is_err(),
        "trailing data accepted"
    );
    let mut ordinary = raw.clone();
    ordinary.input[0].witness = Witness::new();
    ensure!(
        recognize_transaction(
            &session.executor,
            &preparation,
            NETWORK,
            bitcoin_bytes(&ordinary)
        )?
        .map_err(|e| anyhow!(e))?
        .is_none(),
        "ordinary Bitcoin input recognized as Kontor"
    );

    let mut observations: Vec<Value> = Vec::new();
    let mut inspected = None;
    for (simulation, commit) in [(true, false), (false, false), (false, true)] {
        let selection = select_legacy_p1(
            conn,
            NETWORK,
            if simulation {
                ApplicationPosition::Simulation { height: HEIGHT }
            } else {
                ApplicationPosition::Block {
                    height: HEIGHT,
                    hash: BlockHash::from_byte_array([3; 32]),
                    consensus_height: HEIGHT,
                }
            },
        )
        .await?;
        ensure!(
            execute_transaction(session, &selection, NETWORK, &recognized, TX_INDEX, 1)
                .await
                .is_err(),
            "unadmitted transaction ran"
        );
        let lease = begin_canonical_unit(service, session, &selection, NETWORK, simulation).await?;
        let result = async {
            insert_block(conn, BlockRow::builder().height(HEIGHT).hash(BlockHash::from_byte_array([3; 32])).build()).await?;
            let tx_id = insert_transaction(conn, TransactionRow::builder().height(HEIGHT).tx_index(TX_INDEX)
                .txid(recognized.txid.to_string()).build()).await?;
            ensure!((session.executor.operations.transaction)(session.executor.owner.clone(), selection.envelope(), Arc::new(()), TX_INDEX, tx_id).await.is_err(),
                    "unrelated parsed transaction accepted");
            let failures = execute_transaction(session, &selection, NETWORK, &recognized, TX_INDEX, tx_id).await?;
            ensure!(failures.len() == 1 && failures[0].len() == 8, "transaction result positions differ");
            for (index, failure) in failures[0].iter().enumerate() {
                ensure!(failure.is_some() == matches!(index, 5 | 6), "unexpected operation {index} result: {failure:?}");
            }
            let contract_error = conn.query("SELECT status FROM contract_results WHERE tx_id = ? AND op_index = 4 AND func = 'set-blob-then-fail'", [tx_id]).await?
                .next().await?.context("missing contract-error receipt")?;
            ensure!(contract_error.get::<String>(0)? == "ContractErr", "contract result error lost its receipt classification");
            let usage = conn.query("SELECT user_fuel, system_fuel, deposit_fuel FROM transaction_execution_usage WHERE tx_id = ?", [tx_id]).await?
                .next().await?.context("missing transaction usage")?;
            let usage: (i64, i64, i64) = (usage.get(0)?, usage.get(1)?, usage.get(2)?);
            ensure!(usage.0 > 0 && usage.1 > 0 && usage.2 > 0, "transaction did not exercise all fuel categories: {usage:?}");
            if simulation {
                let result = (session.executor.operations.inspect)(session.executor.owner.clone(), selection.envelope(), recognized.payload(&selection, NETWORK)?, TX_INDEX)
                    .await.map_err(HostFailure::from)?;
                inspected = Some(serde_json::from_slice::<Value>(&result)?);
            }
            Ok(json!({"failures":failures,"usage":usage,"state":state(conn).await?}))
        }.await;
        let observed = finish_canonical_unit(lease, result, commit).await?;
        ensure!(conn.is_autocommit(), "transaction retained SQL authority");
        ensure!(
            service.active_roots().await == 0,
            "transaction retained owner root"
        );
        if !commit {
            ensure!(
                state(conn).await? == before,
                "simulation or rollback changed canonical state"
            );
        }
        if let Some(previous) = observations.first() {
            ensure!(
                &observed == previous,
                "simulation, rollback replay and commit disagree"
            );
        }
        observations.push(observed);
    }
    Ok(
        json!({"raw_sha256":hex::encode(Sha256::digest(&bytes)),"counter_sha256":hex::encode(Sha256::digest(COUNTER)),
        "recognition":{"txid":recognized.txid.to_string(),"batchable":recognized.batchable,"inputs":recognized.inputs},
        "inspection":inspected,"executions":observations}),
    )
}
