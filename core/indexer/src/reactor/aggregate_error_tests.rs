use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Result, anyhow};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use blst::min_sig::AggregateSignature;
use indexer_types::{
    AggregateInfo, AggregateSigner, Block, Input, Inst, InstKind, Insts, SignerRef, Transaction,
};
use libsql::{AuthAction, AuthContext, Authorization, Connection, Value as SqlValue};
use stdlib::to_wave_expr;
use tempfile::TempDir;
use tokio::sync::{mpsc, watch};

use super::consensus_state::DeferredDecision;
use super::engine::EngineConfig;
use super::executor::{RuntimeExecutor, process_input};
use super::mempool_fee_index::MempoolFeeIndex;
use super::{PruneConfig, Reactor, start_consensus};
use crate::bitcoin_client::Client;
use crate::block::TxWalker;
use crate::bls::{KONTOR_BLS_DST, RegistrationProof};
use crate::consensus::signing::PrivateKey;
use crate::consensus::{Height, Value};
use crate::database::queries::{ensure_identity, get_identity};
use crate::runtime::token::{address as token_address, api as token};
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{Decimal, GenesisValidator, Runtime};
use crate::stopper::Shutdown;
use crate::test_utils::bls_test::derive_test_key;
use crate::test_utils::{
    new_mock_block_hash, new_mock_transaction, test_runtime, test_runtime_with_genesis,
};

#[derive(Clone, Copy, Debug)]
enum Fault {
    PubkeyRead,
    NonceInsert,
    CallSignerRead,
    RegisterSignerRead,
}

pub(super) async fn reactor(
    mut runtime: Runtime,
    dir: &TempDir,
) -> Result<Reactor<RuntimeExecutor>> {
    let consensus = start_consensus(
        EngineConfig {
            private_key: PrivateKey::from([17; 32]),
            listen_addr: "/ip4/127.0.0.1/tcp/0".into(),
            persistent_peers: Vec::new(),
            data_dir: dir.path().to_path_buf(),
            consensus_enabled: false,
            discovery: Default::default(),
        },
        &mut runtime,
        None,
        None,
        1,
        MempoolFeeIndex::new(None),
    )
    .await?;
    let shutdown = Shutdown::new();
    let (_block_tx, block_rx) = mpsc::channel(1);
    let (_mempool_tx, mempool_rx) = mpsc::channel(1);
    let (addr_tx, _addr_rx) = watch::channel(None);
    let client = Client::new(
        "http://127.0.0.1:1".to_owned(),
        String::new(),
        String::new(),
    )?;
    Ok(Reactor::new(
        RuntimeExecutor::new(client),
        runtime,
        block_rx,
        mempool_rx,
        shutdown.signal(),
        None,
        None,
        None,
        consensus,
        PruneConfig {
            enabled: false,
            retain_blocks: 144,
        },
        1,
        Some(new_mock_block_hash(1)),
        addr_tx,
    ))
}

pub(super) async fn snapshot(conn: &Connection) -> Result<Vec<Vec<Vec<SqlValue>>>> {
    let mut tables = Vec::new();
    for table in [
        "blocks",
        "batches",
        "transactions",
        "signers",
        "x_only_pubkeys",
        "nonces",
        "bls_keys",
        "contract_state",
        "current_contract_state",
        "contract_results",
        "transaction_execution_usage",
        "block_execution_usage",
        "depositor_footprint",
        "checkpoints",
        "node_meta",
    ] {
        let mut rows = conn
            .query(&format!("SELECT * FROM {table} ORDER BY 1, 2"), ())
            .await?;
        let count = rows.column_count();
        let mut values = Vec::new();
        while let Some(row) = rows.next().await? {
            values.push(
                (0..count)
                    .map(|index| row.get_value(index))
                    .collect::<libsql::Result<Vec<_>>>()?,
            );
        }
        tables.push(values);
    }
    Ok(tables)
}

async fn fails_and_recovers(fault: Fault) -> Result<()> {
    let secp = Secp256k1::new();
    let publisher = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[31; 32])?);
    let claimant = Keypair::from_secret_key(&secp, &SecretKey::from_slice(&[32; 32])?);
    let publisher_key = publisher.x_only_public_key().0;
    let claimant_key = claimant.x_only_public_key().0;
    let (mut runtime, dir, _name) = test_runtime_with_genesis(&[GenesisValidator {
        x_only_pubkey: publisher_key.to_string(),
        ed25519_pubkey: PrivateKey::from([17; 32]).public_key().as_bytes().to_vec(),
        stake: Decimal::from("100"),
    }])
    .await?;
    let conn = runtime.get_storage_conn();
    token::issue_to(
        &mut runtime,
        &Signer::Core(Box::new(Signer::Nobody)),
        HolderRef::XOnlyPubkey(publisher_key.to_string()),
        Decimal::from("1000000"),
    )
    .await??;
    let bls_key = derive_test_key(33);
    let proof = RegistrationProof::new(&claimant, &bls_key.to_bytes())?;
    let claim = if matches!(fault, Fault::CallSignerRead | Fault::RegisterSignerRead) {
        let identity = ensure_identity(&conn, &claimant_key.to_string(), 1).await?;
        if matches!(fault, Fault::CallSignerRead) {
            identity
                .register_bls_key(&conn, &proof.bls_pubkey, 1)
                .await?;
        }
        SignerRef::SignerId(identity.signer_id())
    } else {
        SignerRef::XOnlyPubkey(claimant_key)
    };
    let kind = if matches!(fault, Fault::CallSignerRead) {
        InstKind::Call {
            contract: token_address(),
            expr: format!("mint({})", to_wave_expr(Decimal::from("1"))),
        }
    } else {
        InstKind::RegisterBlsKey {
            bls_pubkey: proof.bls_pubkey.to_vec(),
            schnorr_sig: proof.schnorr_sig.to_vec(),
            bls_sig: proof.bls_sig.to_vec(),
        }
    };
    let op = Inst {
        gas_limit: 10_000,
        kind,
    };
    let message = op.aggregate_signing_message(&claim, 0, true)?;
    let signature = bls_key.sign(&message, KONTOR_BLS_DST, &[]);
    let aggregate = AggregateSignature::aggregate(&[&signature], true)
        .map_err(|e| anyhow!("aggregate: {e:?}"))?;
    let txid = new_mock_transaction(42).txid;
    let block = Block {
        height: 2,
        hash: new_mock_block_hash(2),
        prev_hash: new_mock_block_hash(1),
        transactions: vec![Transaction {
            txid,
            index: 0,
            op_return_raw: None,
            inputs: vec![Input {
                previous_output: bitcoin::OutPoint::null(),
                input_index: 0,
                x_only_pubkey: publisher_key,
                insts: Insts {
                    ops: vec![op],
                    aggregate: Some(AggregateInfo {
                        signers: vec![AggregateSigner {
                            identity: claim,
                            nonce: 0,
                            sponsored: true,
                        }],
                        signature: aggregate.to_signature().to_bytes().to_vec(),
                    }),
                },
            }],
        }],
    };
    let decision = DeferredDecision {
        consensus_height: Height::new(1),
        value: Value::new_block(2, block.hash),
        certificate: Vec::new(),
        certified_txs: None,
    };
    let mut reactor = reactor(runtime, &dir).await?;
    let saved = snapshot(&conn).await?;
    let denials = Arc::new(AtomicUsize::new(0));
    let observed = denials.clone();
    let allocation = Arc::new(AtomicUsize::new(0));
    let allocated = allocation.clone();
    conn.authorizer(Some(Arc::new(move |context: &AuthContext<'_>| {
        if matches!(
            context.action,
            AuthAction::Insert {
                table_name: "signers"
            }
        ) {
            allocated.fetch_or(1, Ordering::SeqCst);
        }
        if matches!(
            context.action,
            AuthAction::Insert {
                table_name: "x_only_pubkeys"
            }
        ) {
            allocated.fetch_or(2, Ordering::SeqCst);
        }
        let reject = match fault {
            Fault::PubkeyRead => matches!(
                context.action,
                AuthAction::Read {
                    table_name: "x_only_pubkeys",
                    ..
                }
            ),
            Fault::NonceInsert => matches!(
                context.action,
                AuthAction::Insert {
                    table_name: "nonces"
                }
            ),
            Fault::CallSignerRead | Fault::RegisterSignerRead => matches!(
                context.action,
                AuthAction::Read {
                    table_name: "bls_keys",
                    ..
                }
            ),
        };
        if reject
            && observed
                .compare_exchange(0, 1, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            Authorization::Deny
        } else {
            Authorization::Allow
        }
    })))?;
    let result = reactor.handle_block(block.clone(), &decision).await;
    conn.authorizer(None)?;
    assert!(
        denials.load(Ordering::SeqCst) > 0,
        "fault did not reach aggregate lookup: {fault:?}"
    );
    assert!(
        result.is_err(),
        "aggregate infrastructure error was committed as a rejection: {fault:?}, {result:?}"
    );
    let error = format!("{:#}", result.unwrap_err());
    assert!(error.contains("execute_transaction failed"), "{error}");
    assert!(!error.contains("run_block_lifecycle failed"), "{error}");
    if matches!(fault, Fault::NonceInsert) {
        assert_eq!(allocation.load(Ordering::SeqCst), 3);
    }
    assert_eq!(reactor.last_height, 1);
    assert_eq!(reactor.last_hash, Some(new_mock_block_hash(1)));
    assert!(conn.is_autocommit());
    assert_eq!(
        snapshot(&conn).await?,
        saved,
        "block rollback did not restore {fault:?}"
    );
    reactor.handle_block(block, &decision).await?;
    assert_eq!(reactor.last_height, 2);
    let identity = get_identity(&conn, &claimant_key.to_string())
        .await?
        .unwrap();
    assert_eq!(identity.next_nonce(&conn).await?, 1);
    assert_eq!(
        identity.bls_pubkey(&conn).await?,
        Some(proof.bls_pubkey.to_vec())
    );
    if matches!(fault, Fault::CallSignerRead) {
        let mut rows = conn.query(
            "SELECT r.status FROM contract_results r JOIN transactions t ON t.id = r.tx_id WHERE t.txid = ? AND r.input_index = 0 AND r.op_index = 0 AND r.func = 'mint' ORDER BY r.result_index",
            [txid.to_string()],
        ).await?;
        let row = rows.next().await?.expect("retry must execute mint");
        assert_eq!(row.get::<String>(0)?, "Ok");
        assert!(rows.next().await?.is_none());
    }
    Ok(())
}

#[tokio::test]
async fn aggregate_database_pubkey_read_failure_aborts_block() -> Result<()> {
    fails_and_recovers(Fault::PubkeyRead).await
}

#[tokio::test]
async fn aggregate_database_nonce_insert_failure_aborts_block() -> Result<()> {
    fails_and_recovers(Fault::NonceInsert).await
}

#[tokio::test]
async fn aggregate_database_call_signer_read_failure_aborts_block() -> Result<()> {
    fails_and_recovers(Fault::CallSignerRead).await
}

#[tokio::test]
async fn aggregate_database_registration_signer_read_failure_aborts_block() -> Result<()> {
    fails_and_recovers(Fault::RegisterSignerRead).await
}

#[tokio::test]
async fn aggregate_rejections_preserve_positional_errors_and_text() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let conn = runtime.get_storage_conn();
    let keypair = Keypair::from_secret_key(&Secp256k1::new(), &SecretKey::from_slice(&[32; 32])?);
    let key = keypair.x_only_public_key().0;
    let identity = ensure_identity(&conn, &key.to_string(), 1).await?;
    let bls_key = derive_test_key(33);
    let proof = RegistrationProof::new(&keypair, &bls_key.to_bytes())?;
    let op = Inst {
        gas_limit: 10_000,
        kind: InstKind::RegisterBlsKey {
            bls_pubkey: proof.bls_pubkey.to_vec(),
            schnorr_sig: proof.schnorr_sig.to_vec(),
            bls_sig: proof.bls_sig.to_vec(),
        },
    };
    let valid_bytes_wrong_message = bls_key.sign(b"different message", KONTOR_BLS_DST, &[]);
    let input = Input {
        previous_output: bitcoin::OutPoint::null(),
        input_index: 0,
        x_only_pubkey: key,
        insts: Insts {
            ops: vec![op.clone(), op],
            aggregate: Some(AggregateInfo {
                signers: vec![
                    AggregateSigner {
                        identity: SignerRef::SignerId(identity.signer_id()),
                        nonce: 0,
                        sponsored: true,
                    };
                    2
                ],
                signature: valid_bytes_wrong_message.to_bytes().to_vec(),
            }),
        },
    };
    let before = snapshot(&conn).await?;
    for (case, expected) in [
        (
            0,
            "aggregate sponsored op has Inst.gas_limit = 0; the publisher's commitment must be a positive cap",
        ),
        (1, "invalid aggregate signature bytes: BLST_BAD_ENCODING"),
        (2, "unknown signer_id 999999"),
        (3, "unknown signer_id 999999"),
        (
            4,
            "BLS aggregate signature verification failed: BLST_VERIFY_FAIL",
        ),
    ] {
        let mut input = input.clone();
        match case {
            0 => input.insts.ops[0].gas_limit = 0,
            1 => input.insts.aggregate.as_mut().unwrap().signature.fill(0),
            2 | 3 => {
                input.insts.aggregate.as_mut().unwrap().signers[0].identity =
                    SignerRef::SignerId(999999);
                if case == 2 {
                    input.insts.ops[0].kind = InstKind::Call {
                        contract: token_address(),
                        expr: "mint(1)".into(),
                    };
                }
            }
            _ => {}
        }
        let errors = process_input(
            &mut runtime,
            &mut TxWalker::new(),
            &input,
            1,
            None,
            0,
            new_mock_transaction(43).txid,
            None,
        )
        .await?;
        assert_eq!(errors.len(), 2);
        for error in errors {
            assert_eq!(
                format!("{:#}", error.unwrap()),
                format!("aggregate verification failed: {expected}")
            );
        }
        assert_eq!(
            snapshot(&conn).await?,
            before,
            "rejection case {case} wrote state"
        );
    }
    Ok(())
}
