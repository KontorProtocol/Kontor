use std::collections::BTreeMap;

use anyhow::{Context, Result, anyhow};
use bitcoin::absolute::LockTime;
use bitcoin::opcodes::{
    OP_0, OP_FALSE,
    all::{OP_CHECKSIG, OP_ENDIF, OP_IF},
};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{Amount, Network, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use indexer_types::{
    BuildProvenance, CommitId, ContractAddress, Forge, Inst, InstKind, Insts, Platform, Source,
    serialize,
};
use libsql::{Connection, Value as SqlValue};
use sha2::{Digest, Sha256};

use crate::consensus::signing::PrivateKey;

pub(super) const NETWORK: Network = Network::Regtest;
type GenesisInput = (String, Vec<(String, String, Vec<u8>)>);

pub(super) const COUNTER: &[u8] =
    include_bytes!("../../../../test-contracts/binaries/counter.wasm.br");
pub(super) const PROXY: &[u8] = include_bytes!("../../../../test-contracts/binaries/proxy.wasm.br");
pub(super) const OP_COUNT: usize = 12;
pub(super) const HEIGHT: u64 = 3;
pub(super) const TX_INDEX: u32 = 7;

fn counter() -> ContractAddress {
    ContractAddress {
        name: "counter".into(),
        height: HEIGHT,
        tx_index: TX_INDEX,
    }
}

fn proxy_call(expr: &str) -> Inst {
    Inst {
        gas_limit: 100_000,
        kind: InstKind::Call {
            contract: ContractAddress {
                name: "proxy".into(),
                height: HEIGHT,
                tx_index: TX_INDEX,
            },
            expr: expr.into(),
        },
    }
}

pub(super) fn transaction() -> Result<Transaction> {
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
                provenance: provenance.clone(),
            },
        },
        call("increment()", 100_000),
        call("set-entry(\"alpha\", \"value\")", 100_000),
        call("set-blob-then-fail(\"must roll back\")", 100_000),
        call("missing-function()", 100_000),
        call("fill-blob(16)", 1),
        Inst {
            gas_limit: 100_000,
            kind: InstKind::Publish {
                name: "proxy".into(),
                bytes: PROXY.to_vec(),
                provenance,
            },
        },
        proxy_call(&format!(
            "set-contract-address({})",
            stdlib::to_wave_expr(counter())
        )),
        proxy_call("set-blob-then-fail(\"nested rollback\")"),
        proxy_call("missing-function()"),
        call("increment()", 100_000),
    ]);
    raw_transaction(instructions)
}

pub(crate) fn issuance_transaction() -> Result<Transaction> {
    raw_transaction(Insts::direct(vec![Inst {
        gas_limit: 100_000,
        kind: InstKind::Issuance,
    }]))
}

fn raw_transaction(instructions: Insts) -> Result<Transaction> {
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

pub(super) fn genesis() -> GenesisInput {
    (
        "1".into(),
        vec![(
            "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798".into(),
            "100.9999999".into(),
            PrivateKey::from([7; 32]).public_key().as_bytes().to_vec(),
        )],
    )
}

// Hash typed, length-delimited values rather than database file bytes, which
// include SQLite allocation and WAL details unrelated to execution semantics.
pub(super) async fn state(conn: &Connection) -> Result<BTreeMap<String, (u64, String)>> {
    let mut state = BTreeMap::new();
    for table in [
        "blocks",
        "contracts",
        "contract_provenance",
        "contract_state",
        "current_contract_state",
        "transactions",
        "contract_results",
        "depositor_footprint",
        "block_execution_usage",
        "transaction_execution_usage",
        "signers",
        "x_only_pubkeys",
        "bls_keys",
        "nonces",
    ] {
        let order = if table == "current_contract_state" {
            "contract_id, path"
        } else {
            "rowid"
        };
        let mut rows = conn
            .query(&format!("SELECT * FROM {table} ORDER BY {order}"), ())
            .await?;
        let mut digest = Sha256::new();
        let mut count = 0;
        while let Some(row) = rows.next().await? {
            digest.update(rows.column_count().to_le_bytes());
            for i in 0..rows.column_count() {
                let (tag, bytes) = match row.get_value(i)? {
                    SqlValue::Null => (0u8, Vec::new()),
                    SqlValue::Integer(n) => (1, n.to_le_bytes().to_vec()),
                    SqlValue::Real(n) => (2, n.to_bits().to_le_bytes().to_vec()),
                    SqlValue::Text(s) => (3, s.into_bytes()),
                    SqlValue::Blob(b) => (4, b),
                };
                digest.update([tag]);
                digest.update((bytes.len() as u64).to_le_bytes());
                digest.update(bytes);
            }
            count += 1;
        }
        state.insert(table.into(), (count, hex::encode(digest.finalize())));
    }
    Ok(state)
}
