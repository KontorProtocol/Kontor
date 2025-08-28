use anyhow::{Result, anyhow};
use axum::{Router, http::StatusCode, routing::get};
use axum_test::{TestResponse, TestServer};

use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF};
use bitcoin::opcodes::{OP_0, OP_FALSE};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{Address, Amount, KnownHrp, TapSighashType, TxOut};
use bitcoin::{
    consensus::encode::serialize as serialize_tx,
    key::{Keypair, Secp256k1},
};
use clap::Parser;
use indexer::api::compose_multi::ComposeMultiOutputs;
use indexer::reactor::events::EventSubscriber;
use indexer::witness_data::{TokenBalance, WitnessData};
use indexer::{
    api::{
        Env,
        handlers::{
            get_compose, get_compose_commit, get_compose_multi_batch, get_compose_multi_single,
            get_compose_reveal,
        },
    },
    bitcoin_client::Client,
    config::{Config, TestConfig},
    legacy_test_utils,
    // multi_psbt_test_utils::{get_node_addresses, mock_fetch_utxos_for_addresses},
    test_utils,
    test_utils::new_test_db,
};
use serde::{Deserialize, Serialize};

use base64::Engine;
use base64::engine::general_purpose::STANDARD as b64;
use tokio_util::sync::CancellationToken;

#[derive(Debug, Serialize, Deserialize)]
struct ComposeMultiResponse {
    result: ComposeMultiOutputs,
}

async fn create_test_app(bitcoin_client: Client) -> Result<Router> {
    let config = Config::try_parse()?;
    let (reader, _, _temp_dir) = new_test_db(&config).await?;

    let env = Env {
        bitcoin: bitcoin_client,
        reader,
        config,
        cancel_token: CancellationToken::new(),
        event_subscriber: EventSubscriber::new(),
    };

    // compose + compose_multi endpoints
    Ok(Router::new()
        .route("/compose", get(get_compose))
        .route("/compose/commit", get(get_compose_commit))
        .route("/compose/reveal", get(get_compose_reveal))
        .route("/compose/multi", get(get_compose_multi_single))
        .route("/compose/multi/batch", get(get_compose_multi_batch))
        .with_state(env))
}

#[tokio::test]
async fn test_compose_multi_single() -> Result<()> {
    let bitcoin_client = Client::new_from_config(&Config::try_parse()?)?;

    // Arrange
    let app = create_test_app(bitcoin_client.clone()).await?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    // Use the same working address/UTXO pair as compose_api
    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config, 0)?;
    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    // Build real script data
    let token_data = WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    };
    let token_data_base64 = test_utils::base64_serialize(&token_data);

    let server = TestServer::new(app)?;
    let response: TestResponse = server
        .get(&format!(
            "/compose/multi?address={}&x_only_public_key={}&funding_utxo_ids={}&script_data={}&sat_per_vbyte=2",
            seller_address,
            internal_key,
            "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0",
            urlencoding::encode(&token_data_base64),
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let result: ComposeMultiResponse = serde_json::from_slice(response.as_bytes()).unwrap();

    let compose_outputs = result.result;

    let mut commit_transaction = compose_outputs.commit_transaction;

    let tap_script = compose_outputs.tap_scripts[0].clone();

    // Verify tap script encoding
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

    // Structural assertions
    assert_eq!(commit_transaction.input.len(), 1);
    assert_eq!(commit_transaction.output.len(), 1);
    assert_eq!(
        commit_transaction.output[0].script_pubkey,
        script_address.script_pubkey()
    );

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

    // Sign and broadcast
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
async fn test_compose_multi_single_all_fields() -> Result<()> {
    let bitcoin_client = Client::new_from_config(&Config::try_parse()?)?;

    let app = create_test_app(bitcoin_client.clone()).await?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config, 0)?;
    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    let token_data = WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    };

    let token_data_base64 = test_utils::base64_serialize(&token_data);

    let chained_script_data_base64 = test_utils::base64_serialize(&b"Hello, World!");

    let server = TestServer::new(app)?;

    let response: TestResponse = server
        .get(&format!(
            "/compose/multi?address={}&x_only_public_key={}&funding_utxo_ids={}&script_data={}&sat_per_vbyte={}&change_output={}&envelope={}&chained_script_data={}",
            seller_address,
            internal_key,
            "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0",
            urlencoding::encode(&token_data_base64),
            "2",
            "true",
            "600",
            urlencoding::encode(&chained_script_data_base64),
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let result: ComposeMultiResponse = serde_json::from_slice(response.as_bytes()).unwrap();

    let compose_outputs = result.result;

    let mut commit_transaction = compose_outputs.commit_transaction;

    let tap_script = compose_outputs.tap_scripts[0].clone();

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
    assert_eq!(commit_transaction.output.len(), 1);
    assert_eq!(
        commit_transaction.output[0].script_pubkey,
        script_address.script_pubkey()
    );

    let mut reveal_transaction = compose_outputs.reveal_transaction;

    let chained_tap_script = compose_outputs.chained_tap_script.unwrap();

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
    assert_eq!(reveal_transaction.output.len(), 2);
    assert_eq!(
        reveal_transaction.output[0].script_pubkey,
        seller_address.script_pubkey()
    );
    assert_eq!(
        reveal_transaction.output[1].script_pubkey,
        chained_script_address.script_pubkey()
    );

    // Sign and broadcast
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

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config, 0)?;
    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    let chained_script_data_base64 = test_utils::base64_serialize(&b"Hello, World!");

    let server = TestServer::new(app)?;

    let response: TestResponse = server
        .get(&format!(
            "/compose/multi?address={}&x_only_public_key={}&funding_utxo_ids={}&sat_per_vbyte={}&change_output={}&envelope={}&chained_script_data={}",
            seller_address,
            internal_key,
            "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0",
            "2",
            "true",
            "600",
            urlencoding::encode(&chained_script_data_base64),
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let error_body = response.text();
    assert_eq!(
        error_body,
        "Failed to deserialize query string: missing field `script_data`"
    );

    Ok(())
}

#[tokio::test]
async fn test_compose_nonexistent_utxo() -> Result<()> {
    let bitcoin_client = Client::new_from_config(&Config::try_parse()?)?;

    let app = create_test_app(bitcoin_client.clone()).await?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config, 0)?;
    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    let token_data_base64 = test_utils::base64_serialize(&WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    });

    let server = TestServer::new(app)?;

    let response: TestResponse = server
        .get(&format!(
            "/compose/multi?address={}&x_only_public_key={}&funding_utxo_ids={}&script_data={}&sat_per_vbyte={}",
            seller_address,
            internal_key,
            "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e7:0",
            urlencoding::encode(&token_data_base64),
            "2",
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

    let error_body = response.text();
    assert!(error_body.contains("No funding transactions found"));

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

    let token_data_base64 = test_utils::base64_serialize(&WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    });

    let server = TestServer::new(app)?;

    let response: TestResponse = server
        .get(&format!(
            "/compose/multi?address={}&x_only_public_key={}&funding_utxo_ids={}&script_data={}&sat_per_vbyte={}",
            seller_address,
            internal_key,
            "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0",
            urlencoding::encode(&token_data_base64),
            "2",
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

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config, 0)?;
    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    let token_data_base64 = test_utils::base64_serialize(&WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    });

    let server = TestServer::new(app)?;

    let response: TestResponse = server
        .get(&format!(
            "/compose/multi?address={}&x_only_public_key={}&funding_utxo_ids={}&script_data={}&sat_per_vbyte={}",
            seller_address,
            internal_key,
            "01587d31f4144ab80432d8a48641ff6a0db29dc397ced675823791368e6eac7b:0",
            urlencoding::encode(&token_data_base64),
            "4",
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);
    let error_body = response.text();

    assert!(error_body.contains("Change amount is negative"));

    Ok(())
}

#[tokio::test]
async fn test_compose_multi_batch_two_participants() -> Result<()> {
    let bitcoin_client = Client::new_from_config(&Config::try_parse()?)?;
    let app = create_test_app(bitcoin_client.clone()).await?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    // Use seller address and known funding utxo for both participants (structural test only)
    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config, 0)?;
    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    #[derive(Serialize)]
    struct P<'a> {
        address: &'a str,
        x_only_public_key: String,
        funding_utxo_ids: String,
        script_data: String,
        change_output: bool,
    }
    let script_a_b64 = test_utils::base64_serialize(&b"A".to_vec());
    let script_b_b64 = test_utils::base64_serialize(&b"B".to_vec());
    let participants_json = serde_json::to_vec(&vec![
        P {
            address: &seller_address.to_string(),
            x_only_public_key: internal_key.to_string(),
            funding_utxo_ids: "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0"
                .to_string(),
            script_data: script_a_b64,
            change_output: false,
        },
        P {
            address: &seller_address.to_string(),
            x_only_public_key: internal_key.to_string(),
            funding_utxo_ids: "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0"
                .to_string(),
            script_data: script_b_b64,
            change_output: false,
        },
    ])?;
    let participants_b64 = b64.encode(participants_json);

    let server = TestServer::new(app)?;
    let response: TestResponse = server
        .get(&format!(
            "/compose/multi/batch?participants={}&sat_per_vbyte=2",
            urlencoding::encode(&participants_b64)
        ))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: ComposeMultiResponse = serde_json::from_slice(response.as_bytes()).unwrap();
    let out = result.result;

    // Commit: one output per participant
    assert_eq!(out.commit_transaction.output.len(), 2);
    // Reveal: one input per participant, one output per participant
    assert_eq!(out.reveal_transaction.input.len(), 2);
    assert_eq!(out.reveal_transaction.output.len(), 2);
    // Tap scripts present and in order
    assert_eq!(out.tap_scripts.len(), 2);

    // Verify tapscript[0]
    let mut cbor_a = Vec::new();
    ciborium::into_writer(&b"A".to_vec(), &mut cbor_a).unwrap();
    let derived_a = Builder::new()
        .push_slice(internal_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0)
        .push_slice(PushBytesBuf::try_from(cbor_a)?)
        .push_opcode(OP_ENDIF)
        .into_script();
    assert_eq!(derived_a, out.tap_scripts[0]);

    // Verify tapscript[1]
    let mut cbor_b = Vec::new();
    ciborium::into_writer(&b"B".to_vec(), &mut cbor_b).unwrap();
    let derived_b = Builder::new()
        .push_slice(internal_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0)
        .push_slice(PushBytesBuf::try_from(cbor_b)?)
        .push_opcode(OP_ENDIF)
        .into_script();
    assert_eq!(derived_b, out.tap_scripts[1]);

    Ok(())
}

#[tokio::test]
async fn test_compose_multi_batch_three_participants_chained() -> Result<()> {
    let bitcoin_client = Client::new_from_config(&Config::try_parse()?)?;
    let app = create_test_app(bitcoin_client.clone()).await?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config, 0)?;
    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    #[derive(Serialize)]
    struct P<'a> {
        address: &'a str,
        x_only_public_key: String,
        funding_utxo_ids: String,
        script_data: String,
        change_output: bool,
    }
    let pjson = serde_json::to_vec(&vec![
        P {
            address: &seller_address.to_string(),
            x_only_public_key: internal_key.to_string(),
            funding_utxo_ids: "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0"
                .to_string(),
            script_data: test_utils::base64_serialize(&b"X".to_vec()),
            change_output: false,
        },
        P {
            address: &seller_address.to_string(),
            x_only_public_key: internal_key.to_string(),
            funding_utxo_ids: "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0"
                .to_string(),
            script_data: test_utils::base64_serialize(&b"Y".to_vec()),
            change_output: false,
        },
        P {
            address: &seller_address.to_string(),
            x_only_public_key: internal_key.to_string(),
            funding_utxo_ids: "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0"
                .to_string(),
            script_data: test_utils::base64_serialize(&b"Z".to_vec()),
            change_output: false,
        },
    ])?;
    let p_b64 = b64.encode(pjson);
    let chained_b64 = test_utils::base64_serialize(&b"CHAIN".to_vec());

    let server = TestServer::new(app)?;
    let response: TestResponse = server
        .get(&format!(
            "/compose/multi/batch?participants={}&sat_per_vbyte=2&envelope=600&chained_script_data={}",
            urlencoding::encode(&p_b64),
            urlencoding::encode(&chained_b64),
        ))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: ComposeMultiResponse = serde_json::from_slice(response.as_bytes()).unwrap();
    let out = result.result;

    // Commit has 3 outputs, reveal has 3 participant outputs + 1 chained
    assert_eq!(out.commit_transaction.output.len(), 3);
    assert_eq!(out.reveal_transaction.input.len(), 3);
    assert_eq!(out.reveal_transaction.output.len(), 4);
    assert!(out.chained_tap_script.is_some());

    // Verify chained tapscript equals first participant key + CHAIN data
    let chained_ts = out.chained_tap_script.clone().unwrap();
    let mut cbor_chain = Vec::new();
    ciborium::into_writer(&b"CHAIN".to_vec(), &mut cbor_chain).unwrap();
    let derived_chain = Builder::new()
        .push_slice(internal_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0)
        .push_slice(PushBytesBuf::try_from(cbor_chain)?)
        .push_opcode(OP_ENDIF)
        .into_script();
    assert_eq!(derived_chain, chained_ts);

    Ok(())
}
