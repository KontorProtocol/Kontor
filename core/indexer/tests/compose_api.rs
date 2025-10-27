use anyhow::{Result, anyhow};
use axum::routing::post;
use axum::{Router, http::StatusCode, routing::get};
use axum_test::{TestResponse, TestServer};

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as base64_engine;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF};
use bitcoin::opcodes::{OP_0, OP_FALSE};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{Address, Amount, FeeRate, KnownHrp, Network, OutPoint, TapSighashType, TxOut, Txid};
use bitcoin::{
    consensus::encode::serialize as serialize_tx,
    key::{Keypair, Secp256k1},
};
use clap::Parser;
use indexer::api::compose::{
    ComposeInputs, ComposeOutputs, ComposeQuery, InstructionInputs, InstructionQuery, RevealInputs,
    RevealParticipantInputs, compose, compose_reveal,
};
use indexer::api::handlers::post_compose;
use indexer::legacy_test_utils;
use indexer::reactor::results::ResultSubscriber;
use indexer::runtime::Runtime;
use indexer::witness_data::{TokenBalance, WitnessData};
use indexer::{
    api::{
        Env,
        handlers::{get_compose, get_compose_commit, get_compose_reveal},
    },
    bitcoin_client::Client,
    config::{Config, TestConfig},
    test_utils,
    test_utils::new_test_db,
};
use serde::{Deserialize, Serialize};
use std::str::FromStr;

use tokio_util::sync::CancellationToken;

#[derive(Debug, Serialize, Deserialize)]
struct ComposeResponse {
    result: ComposeOutputs,
}

async fn create_test_app(bitcoin_client: Client) -> Result<Router> {
    let config = Config::try_parse()?;
    let (reader, _, _temp_dir) = new_test_db(&config).await?;

    let env = Env {
        bitcoin: bitcoin_client,
        config,
        cancel_token: CancellationToken::new(),
        result_subscriber: ResultSubscriber::default(),
        runtime: Runtime::new_read_only(&reader).await?,
        reader,
    };

    // Create router with only the compose endpoints
    Ok(Router::new()
        .route("/compose", get(get_compose))
        .route("/compose", post(post_compose))
        .route("/compose/commit", get(get_compose_commit))
        .route("/compose/reveal", get(get_compose_reveal))
        .with_state(env))
}

/// Helper to encode Vec<InstructionQuery> as base64-encoded JSON
fn encode_addresses(addresses: Vec<InstructionQuery>) -> Result<String> {
    let json_bytes = serde_json::to_vec(&addresses)?;
    Ok(base64_engine.encode(json_bytes))
}

#[tokio::test]
async fn test_compose() -> Result<()> {
    let bitcoin_client = Client::new_from_config(&Config::try_parse()?)?;

    // Arrange
    let app = create_test_app(bitcoin_client.clone()).await?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) = test_utils::generate_taproot_address_from_mnemonic(
        &secp,
        Network::Bitcoin,
        &config.taproot_key_path,
        0,
    )?;
    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    let token_data = WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    };

    let mut token_data_bytes = Vec::new();
    ciborium::into_writer(&token_data, &mut token_data_bytes).unwrap();

    let server = TestServer::new(app)?;

    let addresses_vec = vec![InstructionQuery {
        address: seller_address.to_string(),
        x_only_public_key: internal_key.to_string(),
        funding_utxo_ids: "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0"
            .to_string(),
        script_data: token_data_bytes.clone(),
    }];
    let addresses_b64 = encode_addresses(addresses_vec)?;

    let response: TestResponse = server
        .get(&format!(
            "/compose?addresses={}&sat_per_vbyte=2",
            urlencoding::encode(&addresses_b64),
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let result: ComposeResponse = serde_json::from_slice(response.as_bytes()).unwrap();

    let compose_outputs = result.result;

    let mut commit_transaction = compose_outputs.commit_transaction;

    let tap_script = compose_outputs.per_participant[0].commit.tap_script.clone();

    let mut derived_token_data = Vec::new();
    ciborium::into_writer(&token_data, &mut derived_token_data).unwrap();

    let derived_tap_script = Builder::new()
        .push_slice(internal_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0)
        .push_slice(PushBytesBuf::try_from(derived_token_data)?)
        .push_opcode(OP_ENDIF)
        .into_script();

    assert_eq!(derived_tap_script, tap_script);

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .map_err(|e| anyhow!("Failed to add leaf: {}", e))?
        .finalize(&secp, internal_key)
        .map_err(|e| anyhow!("Failed to finalize Taproot tree: {:?}", e))?;
    let script_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), KnownHrp::Mainnet);

    assert_eq!(commit_transaction.input.len(), 1);
    assert_eq!(commit_transaction.output.len(), 2);
    assert_eq!(
        commit_transaction.output[0].script_pubkey,
        script_address.script_pubkey()
    );
    assert!(commit_transaction.output[0].value.to_sat() >= 330);

    let mut reveal_transaction = compose_outputs.reveal_transaction;

    assert_eq!(reveal_transaction.input.len(), 1);
    assert_eq!(
        reveal_transaction.input[0].previous_output.txid,
        commit_transaction.compute_txid()
    );
    assert_eq!(reveal_transaction.input[0].previous_output.vout, 0);

    assert_eq!(reveal_transaction.output.len(), 1);
    assert_eq!(
        reveal_transaction.output[0].script_pubkey,
        seller_address.script_pubkey()
    );

    let commit_previous_output = TxOut {
        value: Amount::from_sat(9000),
        script_pubkey: seller_address.script_pubkey(),
    };

    test_utils::sign_key_spend(
        &secp,
        &mut commit_transaction,
        &[commit_previous_output],
        &keypair,
        0,
        Some(TapSighashType::All),
    )?;

    let reveal_previous_output = commit_transaction.output[0].clone();

    test_utils::sign_script_spend(
        &secp,
        &taproot_spend_info,
        &tap_script,
        &mut reveal_transaction,
        &[reveal_previous_output],
        &keypair,
        0,
    )?;

    let commit_tx_hex = hex::encode(serialize_tx(&commit_transaction));
    let reveal_tx_hex = hex::encode(serialize_tx(&reveal_transaction));

    let result = bitcoin_client
        .test_mempool_accept(&[commit_tx_hex, reveal_tx_hex])
        .await?;

    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Commit transaction was rejected");
    assert!(result[1].allowed, "Reveal transaction was rejected");
    Ok(())
}

#[tokio::test]
async fn test_compose_all_fields() -> Result<()> {
    let bitcoin_client = Client::new_from_config(&Config::try_parse()?)?;

    let app = create_test_app(bitcoin_client.clone()).await?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) = test_utils::generate_taproot_address_from_mnemonic(
        &secp,
        Network::Bitcoin,
        &config.taproot_key_path,
        0,
    )?;
    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    let token_data = WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    };

    let mut token_data_bytes = Vec::new();
    ciborium::into_writer(&token_data, &mut token_data_bytes).unwrap();

    let _chained_script_data_base64 = test_utils::base64_serialize(&b"Hello, World!");

    let server = TestServer::new(app)?;

    let addresses_vec = vec![InstructionQuery {
        address: seller_address.to_string(),
        x_only_public_key: internal_key.to_string(),
        funding_utxo_ids: "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0"
            .to_string(),
        script_data: token_data_bytes.clone(),
    }];
    let addresses_b64 = encode_addresses(addresses_vec)?;

    let response: TestResponse = server
        .get(&format!(
            "/compose?addresses={}&sat_per_vbyte=2&envelope=600&chained_script_data={}",
            urlencoding::encode(&addresses_b64),
            urlencoding::encode(&_chained_script_data_base64),
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let result: ComposeResponse = serde_json::from_slice(response.as_bytes()).unwrap();

    let compose_outputs = result.result;

    let mut commit_transaction = compose_outputs.commit_transaction;

    let tap_script = compose_outputs.per_participant[0].commit.tap_script.clone();

    let mut derived_token_data = Vec::new();
    ciborium::into_writer(&token_data, &mut derived_token_data).unwrap();

    let derived_tap_script = Builder::new()
        .push_slice(internal_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0)
        .push_slice(PushBytesBuf::try_from(derived_token_data)?)
        .push_opcode(OP_ENDIF)
        .into_script();

    assert_eq!(derived_tap_script, tap_script);

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, derived_tap_script.clone())
        .map_err(|e| anyhow!("Failed to add leaf: {}", e))?
        .finalize(&secp, internal_key)
        .map_err(|e| anyhow!("Failed to finalize Taproot tree: {:?}", e))?;
    let script_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), KnownHrp::Mainnet);

    assert_eq!(commit_transaction.input.len(), 1);
    assert_eq!(commit_transaction.output.len(), 2);
    assert!(commit_transaction.output[0].value.to_sat() >= 600);
    assert_eq!(
        commit_transaction.output[0].script_pubkey,
        script_address.script_pubkey()
    );
    if commit_transaction.output.len() > 1 {
        assert_eq!(
            commit_transaction.output[1].script_pubkey,
            seller_address.script_pubkey()
        );
    }

    let mut reveal_transaction = compose_outputs.reveal_transaction;

    let chained_tap_script = compose_outputs.per_participant[0]
        .chained
        .as_ref()
        .unwrap()
        .tap_script
        .clone();

    let mut derived_chained_tap_script = Vec::new();
    ciborium::into_writer(&b"Hello, World!", &mut derived_chained_tap_script).unwrap();

    let derived_chained_tap_script = Builder::new()
        .push_slice(internal_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0)
        .push_slice(PushBytesBuf::try_from(derived_chained_tap_script)?)
        .push_opcode(OP_ENDIF)
        .into_script();

    assert_eq!(derived_chained_tap_script, chained_tap_script);

    let chained_taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, derived_chained_tap_script.clone())
        .map_err(|e| anyhow!("Failed to add leaf: {}", e))?
        .finalize(&secp, internal_key)
        .map_err(|e| anyhow!("Failed to finalize Taproot tree: {:?}", e))?;
    let chained_script_address =
        Address::p2tr_tweaked(chained_taproot_spend_info.output_key(), KnownHrp::Mainnet);

    assert_eq!(reveal_transaction.input.len(), 1);
    assert_eq!(
        reveal_transaction.input[0].previous_output.txid,
        commit_transaction.compute_txid()
    );
    assert_eq!(reveal_transaction.input[0].previous_output.vout, 0);

    assert_eq!(reveal_transaction.output.len(), 1);
    assert_eq!(reveal_transaction.output[0].value.to_sat(), 600);
    assert_eq!(
        reveal_transaction.output[0].script_pubkey,
        chained_script_address.script_pubkey()
    );
    if reveal_transaction.output.len() > 1 {
        assert_eq!(
            reveal_transaction.output[1].script_pubkey,
            seller_address.script_pubkey()
        );
    }

    let commit_previous_output = TxOut {
        value: Amount::from_sat(9000),
        script_pubkey: seller_address.script_pubkey(),
    };

    test_utils::sign_key_spend(
        &secp,
        &mut commit_transaction,
        &[commit_previous_output],
        &keypair,
        0,
        Some(TapSighashType::All),
    )?;

    let reveal_previous_outputs = [commit_transaction.output[0].clone()];

    test_utils::sign_script_spend(
        &secp,
        &taproot_spend_info,
        &tap_script,
        &mut reveal_transaction,
        &reveal_previous_outputs,
        &keypair,
        0,
    )?;

    // Reveal only spends the script output now

    let commit_tx_hex = hex::encode(serialize_tx(&commit_transaction));
    let reveal_tx_hex = hex::encode(serialize_tx(&reveal_transaction));

    let result = bitcoin_client
        .test_mempool_accept(&[commit_tx_hex, reveal_tx_hex])
        .await?;

    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Commit transaction was rejected");
    assert!(result[1].allowed, "Reveal transaction was rejected");
    Ok(())
}

#[tokio::test]
async fn test_compose_missing_params() -> Result<()> {
    let bitcoin_client = Client::new_from_config(&Config::try_parse()?)?;

    let app = create_test_app(bitcoin_client.clone()).await?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) = test_utils::generate_taproot_address_from_mnemonic(
        &secp,
        Network::Bitcoin,
        &config.taproot_key_path,
        0,
    )?;
    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    let token_data = WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    };

    let _token_data_base64 = test_utils::base64_serialize(&token_data);

    let _chained_script_data_base64 = test_utils::base64_serialize(&b"Hello, World!");

    let server = TestServer::new(app)?;

    // Create a manually constructed JSON without script_data field to test missing field
    let addresses_json = serde_json::json!([{
        "address": seller_address.to_string(),
        "x_only_public_key": internal_key.to_string(),
        "funding_utxo_ids": "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0",
        // no script_data on purpose
    }]);
    let addresses_b64 = base64_engine.encode(serde_json::to_vec(&addresses_json)?);

    let response: TestResponse = server
        .get(&format!(
            "/compose?addresses={}&sat_per_vbyte=2&envelope=600&chained_script_data=",
            urlencoding::encode(&addresses_b64),
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let error_body = response.text();
    assert!(error_body.contains("script_data") || error_body.contains("missing field"));

    Ok(())
}

#[tokio::test]
async fn test_compose_duplicate_address_and_duplicate_utxo() -> Result<()> {
    let bitcoin_client = Client::new_from_config(&Config::try_parse()?)?;

    let app = create_test_app(bitcoin_client.clone()).await?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (addr, child_key, _) = test_utils::generate_taproot_address_from_mnemonic(
        &secp,
        Network::Bitcoin,
        &config.taproot_key_path,
        0,
    )?;
    let keypair = Keypair::from_secret_key(&secp, &child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    let token_data = WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1,
            name: "T".to_string(),
        },
    };
    let mut token_data_bytes = Vec::new();
    ciborium::into_writer(&token_data, &mut token_data_bytes).unwrap();

    let server = TestServer::new(app)?;

    // duplicate address provided twice
    let addresses_vec = vec![
        InstructionQuery {
            address: addr.to_string(),
            x_only_public_key: internal_key.to_string(),
            funding_utxo_ids: "01587d31f4144ab80432d8a48641ff6a0db29dc397ced675823791368e6eac7b:0"
                .to_string(),
            script_data: token_data_bytes.clone(),
        },
        InstructionQuery {
            address: addr.to_string(),
            x_only_public_key: internal_key.to_string(),
            funding_utxo_ids: "01587d31f4144ab80432d8a48641ff6a0db29dc397ced675823791368e6eac7b:0"
                .to_string(),
            script_data: token_data_bytes.clone(),
        },
    ];
    let addresses_b64 = encode_addresses(addresses_vec)?;

    let response: TestResponse = server
        .get(&format!(
            "/compose?addresses={}&sat_per_vbyte=2",
            urlencoding::encode(&addresses_b64),
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let error_body = response.text();
    assert!(error_body.contains("duplicate address provided"));

    // duplicate utxo within a participant
    let addresses_vec2 = vec![InstructionQuery {
        address: addr.to_string(),
        x_only_public_key: internal_key.to_string(),
        funding_utxo_ids: "01587d31f4144ab80432d8a48641ff6a0db29dc397ced675823791368e6eac7b:0,01587d31f4144ab80432d8a48641ff6a0db29dc397ced675823791368e6eac7b:0".to_string(),
        script_data: token_data_bytes.clone(),
    }];
    let addresses_b64_2 = encode_addresses(addresses_vec2)?;

    let response2: TestResponse = server
        .get(&format!(
            "/compose?addresses={}&sat_per_vbyte=2",
            urlencoding::encode(&addresses_b64_2),
        ))
        .await;

    assert_eq!(response2.status_code(), StatusCode::BAD_REQUEST);
    let error_body2 = response2.text();
    assert!(error_body2.contains("duplicate funding outpoint provided for participant"));

    Ok(())
}

#[tokio::test]
async fn test_compose_param_bounds_and_fee_rate() -> Result<()> {
    let bitcoin_client = Client::new_from_config(&Config::try_parse()?)?;
    let app = create_test_app(bitcoin_client.clone()).await?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (addr, child_key, _) = test_utils::generate_taproot_address_from_mnemonic(
        &secp,
        Network::Bitcoin,
        &config.taproot_key_path,
        0,
    )?;
    let keypair = Keypair::from_secret_key(&secp, &child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    let server = TestServer::new(app)?;

    // Oversized script_data
    let oversized = vec![0u8; 387 * 1024 + 1];
    let addresses_vec = vec![InstructionQuery {
        address: addr.to_string(),
        x_only_public_key: internal_key.to_string(),
        funding_utxo_ids: "01587d31f4144ab80432d8a48641ff6a0db29dc397ced675823791368e6eac7b:0"
            .to_string(),
        script_data: oversized,
    }];
    let query = ComposeQuery {
        instructions: addresses_vec,
        sat_per_vbyte: 2,
        envelope: None,
        chained_script_data: None,
    };

    let resp: TestResponse = server.post("/compose").json(&query).await;
    assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
    assert!(resp.text().contains("script data size invalid"));

    // Oversized chained_script_data
    let chained_oversized_b64 = vec![0u8; 387 * 1024 + 1];
    let addresses_vec2 = vec![InstructionQuery {
        address: addr.to_string(),
        x_only_public_key: internal_key.to_string(),
        funding_utxo_ids: "01587d31f4144ab80432d8a48641ff6a0db29dc397ced675823791368e6eac7b:0"
            .to_string(),
        script_data: b"x".to_vec(),
    }];
    let query = ComposeQuery {
        instructions: addresses_vec2.clone(),
        sat_per_vbyte: 2,
        envelope: None,
        chained_script_data: Some(chained_oversized_b64),
    };

    let resp2: TestResponse = server.post("/compose").json(&query).await;
    assert_eq!(resp2.status_code(), StatusCode::BAD_REQUEST);
    assert!(resp2.text().contains("chained script data size invalid"));

    // Invalid fee rate (0)
    let addresses_b64_3 = encode_addresses(addresses_vec2)?;
    let resp3: TestResponse = server
        .get(&format!(
            "/compose?addresses={}&sat_per_vbyte=0",
            urlencoding::encode(&addresses_b64_3),
        ))
        .await;
    assert_eq!(resp3.status_code(), StatusCode::BAD_REQUEST);
    assert!(resp3.text().contains("Invalid fee rate"));

    Ok(())
}

#[tokio::test]
async fn test_reveal_with_op_return_mempool_accept() -> Result<()> {
    let bitcoin_client = Client::new_from_config(&Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) = test_utils::generate_taproot_address_from_mnemonic(
        &secp,
        Network::Bitcoin,
        &config.taproot_key_path,
        0,
    )?;
    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    // Build compose with small script and one UTXO
    let out_point = OutPoint {
        txid: Txid::from_str("dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8")?,
        vout: 0,
    };
    let utxo_for_output = TxOut {
        value: Amount::from_sat(9000),
        script_pubkey: seller_address.script_pubkey(),
    };

    let compose_params = ComposeInputs::builder()
        .instructions(vec![InstructionInputs {
            address: seller_address.clone(),
            x_only_public_key: internal_key,
            funding_utxos: vec![(out_point, utxo_for_output.clone())],
            script_data: b"Hello, world!".to_vec(),
        }])
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .envelope(546)
        .build();

    let compose_outputs = compose(compose_params)?;

    let mut commit_tx = compose_outputs.commit_transaction;
    let tap_script = compose_outputs.per_participant[0].commit.tap_script.clone();
    // Initial reveal tx (unused after recomposition with OP_RETURN)
    let _initial_reveal_tx = compose_outputs.reveal_transaction;

    // Add OP_RETURN data (within 77 bytes total payload minus tag)
    let inputs = RevealInputs::builder()
        .commit_txid(commit_tx.compute_txid())
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .participants(vec![RevealParticipantInputs {
            address: seller_address.clone(),
            x_only_public_key: internal_key,
            commit_outpoint: OutPoint {
                txid: commit_tx.compute_txid(),
                vout: 0,
            },
            commit_prevout: commit_tx.output[0].clone(),
            commit_script_data: compose_outputs.per_participant[0]
                .commit
                .script_data_chunk
                .clone(),
        }])
        .op_return_data(vec![0xAB; 10])
        .envelope(546)
        .build();

    let reveal_outputs = compose_reveal(inputs)?;

    // Sign commit
    test_utils::sign_key_spend(
        &secp,
        &mut commit_tx,
        &[utxo_for_output],
        &keypair,
        0,
        Some(TapSighashType::All),
    )?;

    // Sign reveal
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .map_err(|e| anyhow!("Failed to add leaf: {}", e))?
        .finalize(&secp, internal_key)
        .map_err(|e| anyhow!("Failed to finalize Taproot tree: {:?}", e))?;
    let mut reveal_tx_signed = reveal_outputs.transaction.clone();
    test_utils::sign_script_spend(
        &secp,
        &taproot_spend_info,
        &tap_script,
        &mut reveal_tx_signed,
        &[commit_tx.output[0].clone()],
        &keypair,
        0,
    )?;

    let commit_tx_hex = hex::encode(serialize_tx(&commit_tx));
    let reveal_tx_hex = hex::encode(serialize_tx(&reveal_tx_signed));

    let result = bitcoin_client
        .test_mempool_accept(&[commit_tx_hex, reveal_tx_hex])
        .await?;
    assert_eq!(result.len(), 2);
    assert!(result[0].allowed);
    assert!(result[1].allowed);

    Ok(())
}
#[tokio::test]
async fn test_compose_nonexistent_utxo() -> Result<()> {
    let bitcoin_client = Client::new_from_config(&Config::try_parse()?)?;

    let app = create_test_app(bitcoin_client.clone()).await?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) = test_utils::generate_taproot_address_from_mnemonic(
        &secp,
        Network::Bitcoin,
        &config.taproot_key_path,
        0,
    )?;
    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    let token_data = WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    };
    let mut token_data_bytes = Vec::new();
    ciborium::into_writer(&token_data, &mut token_data_bytes).unwrap();

    let server = TestServer::new(app)?;

    let addresses_vec = vec![InstructionQuery {
        address: seller_address.to_string(),
        x_only_public_key: internal_key.to_string(),
        funding_utxo_ids: "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e7:0"
            .to_string(),
        script_data: token_data_bytes,
    }];
    let addresses_b64 = encode_addresses(addresses_vec)?;

    let response: TestResponse = server
        .get(&format!(
            "/compose?addresses={}&sat_per_vbyte=2",
            urlencoding::encode(&addresses_b64),
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    let error_body = response.text();
    assert!(error_body.contains("No such mempool or blockchain transaction"));

    Ok(())
}

#[tokio::test]
async fn test_compose_invalid_address() -> Result<()> {
    let bitcoin_client = Client::new_from_config(&Config::try_parse()?)?;

    let app = create_test_app(bitcoin_client.clone()).await?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) =
        legacy_test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    let token_data = WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    };
    let mut token_data_bytes = Vec::new();
    ciborium::into_writer(&token_data, &mut token_data_bytes).unwrap();

    let server = TestServer::new(app)?;

    let addresses_vec = vec![InstructionQuery {
        address: seller_address.to_string(),
        x_only_public_key: internal_key.to_string(),
        funding_utxo_ids: "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0"
            .to_string(),
        script_data: token_data_bytes,
    }];
    let addresses_b64 = encode_addresses(addresses_vec)?;

    let response: TestResponse = server
        .get(&format!(
            "/compose?addresses={}&sat_per_vbyte=2",
            urlencoding::encode(&addresses_b64),
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let error_body = response.text();

    assert!(error_body.contains("Invalid address type"));
    Ok(())
}

#[tokio::test]
async fn test_compose_insufficient_funds() -> Result<()> {
    let bitcoin_client = Client::new_from_config(&Config::try_parse()?)?;

    let app = create_test_app(bitcoin_client.clone()).await?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) = test_utils::generate_taproot_address_from_mnemonic(
        &secp,
        Network::Bitcoin,
        &config.taproot_key_path,
        0,
    )?;
    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    let token_data = WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    };
    let mut token_data_bytes = Vec::new();
    ciborium::into_writer(&token_data, &mut token_data_bytes).unwrap();

    let server = TestServer::new(app)?;

    let addresses_vec = vec![InstructionQuery {
        address: seller_address.to_string(),
        x_only_public_key: internal_key.to_string(),
        funding_utxo_ids: "01587d31f4144ab80432d8a48641ff6a0db29dc397ced675823791368e6eac7b:0"
            .to_string(),
        script_data: token_data_bytes,
    }];
    let addresses_b64 = encode_addresses(addresses_vec)?;

    let response: TestResponse = server
        .get(&format!(
            "/compose?addresses={}&sat_per_vbyte=4",
            urlencoding::encode(&addresses_b64),
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let error_body = response.text();

    assert!(
        error_body.contains("Insufficient inputs")
            || error_body.contains("Insufficient")
            || error_body.contains("Change amount is negative")
    );

    Ok(())
}
