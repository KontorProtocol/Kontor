use std::time::Duration;

use anyhow::{Result, anyhow};
use axum::{Router, http::StatusCode, routing::post};
use axum_test::TestServer;
use bitcoin::absolute::LockTime;
use bitcoin::consensus::encode::serialize_hex;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::Builder;
use bitcoin::secp256k1::SecretKey;
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use indexer_types::{ErrorResponse, Inst, InstKind, Insts, TransactionHex, serialize};
use tokio::sync::mpsc;
use tokio::time::timeout;

use super::new_test_env;
use crate::api::handlers::post_simulate;
use crate::test_utils::{PublicKey, build_inscription};

fn transaction() -> Transaction {
    Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness: Witness::new(),
        }],
        output: vec![TxOut {
            value: Amount::ZERO,
            script_pubkey: Builder::new()
                .push_opcode(OP_RETURN)
                .push_slice(b"first")
                .push_slice(b"second")
                .into_script(),
        }],
    }
}

fn inscription_input(payload: Vec<u8>) -> Result<TxIn> {
    let secp = Secp256k1::new();
    let key = SecretKey::from_slice(&[23; 32])?;
    let (public_key, _) = Keypair::from_secret_key(&secp, &key).x_only_public_key();
    let script = build_inscription(payload, PublicKey::Taproot(&public_key))?;
    let spend = TaprootBuilder::new()
        .add_leaf(0, script.clone())?
        .finalize(&secp, public_key)
        .map_err(|_| anyhow!("single-leaf fixture must finalize"))?;
    let control = spend
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .expect("fixture leaf exists");
    let mut input = transaction().input.remove(0);
    // This fixture exercises recognition, not Bitcoin signature validity.
    input.witness.push([0u8; 64]);
    input.witness.push(script.as_bytes());
    input.witness.push(control.serialize());
    Ok(input)
}

#[tokio::test]
async fn malformed_bitcoin_simulation_is_bad_request_without_queueing() -> Result<()> {
    let (mut env, _conn, _dir) = new_test_env().await?;
    let (sender, mut receiver) = mpsc::channel(1);
    env.simulate_tx = sender;
    let server = TestServer::new(
        Router::new()
            .route("/simulate", post(post_simulate))
            .with_state(env),
    );
    for hex in ["zz".to_owned(), "00".to_owned()] {
        let response = timeout(Duration::from_secs(5), async {
            server.post("/simulate").json(&TransactionHex { hex }).await
        })
        .await?;
        assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
        let error: ErrorResponse = serde_json::from_slice(response.as_bytes())?;
        assert!(error.error.starts_with("Bad request: "));
        assert!(matches!(
            receiver.try_recv(),
            Err(mpsc::error::TryRecvError::Empty)
        ));
    }
    Ok(())
}

#[tokio::test]
async fn simulation_preserves_raw_witnesses_and_reactor_error() -> Result<()> {
    let (mut env, _conn, _dir) = new_test_env().await?;
    let (sender, mut receiver) = mpsc::channel(1);
    env.simulate_tx = sender;
    let server = TestServer::new(
        Router::new()
            .route("/simulate", post(post_simulate))
            .with_state(env),
    );
    let instructions = Insts::direct(vec![Inst {
        gas_limit: 123,
        kind: InstKind::Sponsor,
    }]);
    let mut raw = transaction();
    raw.input
        .push(inscription_input(serialize(&instructions)?)?);
    raw.input.push(inscription_input(vec![0xff])?);
    raw.input[1].previous_output.vout = 1;
    let request = TransactionHex {
        hex: serialize_hex(&raw),
    };
    let pending = server.post("/simulate").json(&request);
    let inspect_queue = async {
        let (queued, reply) = receiver.recv().await.expect("simulation queued");
        assert_eq!(
            queued, raw,
            "recognition must not discard any input at RPC arrival"
        );
        assert!(
            reply
                .send(Err(anyhow!("fixture simulation rejection")))
                .is_ok()
        );
    };
    let (response, ()) = timeout(Duration::from_secs(5), async {
        tokio::join!(async { pending.await }, inspect_queue)
    })
    .await?;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let error: ErrorResponse = serde_json::from_slice(response.as_bytes())?;
    assert_eq!(error.error, "Bad request: fixture simulation rejection");
    Ok(())
}

#[tokio::test]
async fn unrecognized_simulation_is_bad_request_after_admission() -> Result<()> {
    let (mut env, _conn, _dir) = new_test_env().await?;
    let (sender, mut receiver) = mpsc::channel(1);
    env.simulate_tx = sender;
    let server = TestServer::new(
        Router::new()
            .route("/simulate", post(post_simulate))
            .with_state(env),
    );
    let raw = transaction();
    let request = TransactionHex {
        hex: serialize_hex(&raw),
    };
    let pending = server.post("/simulate").json(&request);
    let reject_at_admission = async {
        let (queued, reply) = receiver.recv().await.expect("raw simulation queued");
        assert_eq!(queued, raw);
        assert!(reply.send(Ok(None)).is_ok());
    };
    let (response, ()) = timeout(Duration::from_secs(5), async {
        tokio::join!(async { pending.await }, reject_at_admission)
    })
    .await?;
    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let error: ErrorResponse = serde_json::from_slice(response.as_bytes())?;
    assert_eq!(error.error, "Bad request: Not a valid Kontor transaction");
    Ok(())
}
