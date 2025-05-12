use anyhow::{Result, anyhow};
use axum::{Router, http::StatusCode, routing::get};
use axum_test::{TestResponse, TestServer};
use base64::engine::general_purpose::URL_SAFE as base64;
use base64::prelude::*;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF};
use bitcoin::opcodes::{OP_0, OP_FALSE};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{Address, Amount, KnownHrp, TxOut};
use bitcoin::{
    consensus::encode::serialize as serialize_tx,
    key::{Keypair, Secp256k1},
};
use clap::Parser;
use kontor::api::compose::{ComposeOutputs, RevealOutputs, RevealQuery, compose_reveal};
use kontor::reactor::events::EventSubscriber;
use kontor::witness_data::{TokenBalance, WitnessData};
use kontor::{
    api::{
        Env,
        compose::ComposeQuery,
        handlers::{get_compose, get_compose_commit, get_compose_reveal},
    },
    bitcoin_client::Client,
    config::{Config, TestConfig},
    test_utils,
    utils::new_test_db,
};
use serde::{Deserialize, Serialize};

use tokio_util::sync::CancellationToken;

#[derive(Debug, Serialize, Deserialize)]
struct ComposeResponse {
    result: ComposeOutputs,
}

async fn create_test_app(bitcoin_client: Client) -> Result<Router> {
    let (reader, _, _temp_dir) = new_test_db().await?;

    let env = Env {
        bitcoin: bitcoin_client,
        reader,
        config: Config::try_parse()?,
        cancel_token: CancellationToken::new(),
        event_subscriber: EventSubscriber::new(),
    };

    // Create router with only the compose endpoints
    Ok(Router::new()
        .route("/compose", get(get_compose))
        .route("/compose/commit", get(get_compose_commit))
        .route("/compose/reveal", get(get_compose_reveal))
        .with_state(env))
}

#[tokio::test]
async fn test_compose() -> Result<()> {
    let bitcoin_client = Client::new_from_config(Config::try_parse()?)?;

    // Arrange
    let app = create_test_app(bitcoin_client.clone()).await?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 0)?;
    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    let token_data = WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_data, &mut serialized_token_balance).unwrap();

    let token_data_base64 = base64.encode(serialized_token_balance.clone());

    let server = TestServer::new(app)?;

    let response: TestResponse = server
        .get(&format!(
            "/compose?address={}&x_only_public_key={}&funding_utxo_ids={}&script_data={}&sat_per_vbyte={}",
            seller_address,
            internal_key,
            "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0",
            token_data_base64,
            "2",
        ))
        .await;

    assert_eq!(response.status_code(), StatusCode::OK);
    let result: ComposeResponse = serde_json::from_slice(response.as_bytes()).unwrap();

    let compose_outputs = result.result;

    let mut commit_transaction = compose_outputs.commit_transaction;

    let tap_script = compose_outputs.tap_script;

    let derived_tap_script = Builder::new()
        .push_slice(internal_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0)
        .push_slice(PushBytesBuf::try_from(serialized_token_balance)?)
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
    assert_eq!(commit_transaction.output.len(), 1);
    assert_eq!(commit_transaction.output[0].value.to_sat(), 8778);
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
    assert_eq!(reveal_transaction.output[0].value.to_sat(), 8484);
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
    println!("Result: {:#?}", result);
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Commit transaction was rejected");
    assert!(result[1].allowed, "Reveal transaction was rejected");
    Ok(())
}

#[tokio::test]
async fn test_compose_commit_reveal_chained_reveal() -> Result<()> {
    let bitcoin_client = Client::new_from_config(Config::try_parse()?)?;

    // Arrange
    let app = create_test_app(bitcoin_client.clone()).await?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 0)?;
    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    let token_data = WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_data, &mut serialized_token_balance).unwrap();

    let token_data_base64 = base64.encode(serialized_token_balance.clone());

    let chained_script_data_base64 = base64.encode(b"Hello, World!");

    let server = TestServer::new(app)?;

    let response: TestResponse = server
        .get(&format!(
            "/compose?address={}&x_only_public_key={}&funding_utxo_ids={}&script_data={}&sat_per_vbyte={}&change_output={}&envelope={}&chained_script_data={}",
            seller_address,
            internal_key,
            "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0",
            token_data_base64,
            "2",
            "true",
            "600",
            chained_script_data_base64,
        ))
        .await;
    println!("Response: {:#?}", response);
    assert_eq!(response.status_code(), StatusCode::OK);
    let result: ComposeResponse = serde_json::from_slice(response.as_bytes()).unwrap();

    let compose_outputs = result.result;

    let mut commit_transaction = compose_outputs.commit_transaction;

    let tap_script = compose_outputs.tap_script;

    let derived_tap_script = Builder::new()
        .push_slice(internal_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0)
        .push_slice(PushBytesBuf::try_from(serialized_token_balance)?)
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
    assert_eq!(commit_transaction.output[0].value.to_sat(), 600);
    assert_eq!(
        commit_transaction.output[0].script_pubkey,
        script_address.script_pubkey()
    );
    assert_eq!(commit_transaction.output[1].value.to_sat(), 8092);
    assert_eq!(
        commit_transaction.output[1].script_pubkey,
        seller_address.script_pubkey()
    );

    let mut reveal_transaction = compose_outputs.reveal_transaction;
    println!("Reveal transaction: {:#?}", reveal_transaction);

    let chained_tap_script = compose_outputs.chained_tap_script.unwrap();

    let derived_chained_tap_script = Builder::new()
        .push_slice(internal_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0)
        .push_slice(b"Hello, World!")
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

    assert_eq!(reveal_transaction.input.len(), 2);
    assert_eq!(
        reveal_transaction.input[0].previous_output.txid,
        commit_transaction.compute_txid()
    );
    assert_eq!(reveal_transaction.input[0].previous_output.vout, 0);
    assert_eq!(
        reveal_transaction.input[1].previous_output.txid,
        commit_transaction.compute_txid()
    );
    assert_eq!(reveal_transaction.input[1].previous_output.vout, 1);

    assert_eq!(reveal_transaction.output.len(), 2);
    assert_eq!(reveal_transaction.output[0].value.to_sat(), 600);
    assert_eq!(
        reveal_transaction.output[0].script_pubkey,
        chained_script_address.script_pubkey()
    );
    assert_eq!(reveal_transaction.output[1].value.to_sat(), 7598);
    assert_eq!(
        reveal_transaction.output[1].script_pubkey,
        seller_address.script_pubkey()
    );

    let commit_tx_id = format!("{}:0", reveal_transaction.compute_txid());
    let funding_utxo_id = format!("{}:1", reveal_transaction.compute_txid());

    let chained_reveal_response: TestResponse = server
        .get(&format!(
            "/compose/reveal?address={}&x_only_public_key={}&funding_utxo_ids={}&commit_script_data={}&sat_per_vbyte={}&commit_output={}",
            seller_address,
            internal_key,
            funding_utxo_id,
            chained_script_data_base64,
            "2",
            commit_tx_id,
        ))
        .await;

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
    )?;

    let reveal_previous_outputs = [
        commit_transaction.output[0].clone(),
        commit_transaction.output[1].clone(),
    ];

    test_utils::sign_script_spend(
        &secp,
        &taproot_spend_info,
        &tap_script,
        &mut reveal_transaction,
        &reveal_previous_outputs,
        &keypair,
        0,
    )?;

    test_utils::sign_key_spend(
        &secp,
        &mut reveal_transaction,
        &reveal_previous_outputs,
        &keypair,
        1,
    )?;

    println!("Chained reveal response: {:#?}", chained_reveal_response);
    assert_eq!(chained_reveal_response.status_code(), StatusCode::OK);
    let chained_reveal_result: RevealOutputs =
        serde_json::from_slice(chained_reveal_response.as_bytes()).unwrap();

    let chained_reveal_transaction = chained_reveal_result.transaction;

    let commit_tx_hex = hex::encode(serialize_tx(&commit_transaction));
    let reveal_tx_hex = hex::encode(serialize_tx(&reveal_transaction));

    let result = bitcoin_client
        .test_mempool_accept(&[commit_tx_hex, reveal_tx_hex])
        .await?;
    println!("Result: {:#?}", result);
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Commit transaction was rejected");
    assert!(result[1].allowed, "Reveal transaction was rejected");
    Ok(())
}

// #[tokio::test]
// async fn test_compose_with_all_fields() -> Result<()> {
//     let bitcoin_client = Client::new_from_config(Config::try_parse()?)?;

//     // Arrange
//     let app = create_test_app(bitcoin_client.clone()).await?;
//     let config = TestConfig::try_parse()?;
//     let secp = Secp256k1::new();

//     let (seller_address, seller_child_key, _) =
//         test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 0)?;
//     let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
//     let (internal_key, _parity) = keypair.x_only_public_key();

//     let query = ComposeQuery {
//         address: seller_address.to_string(),
//         x_only_public_key: internal_key.to_string(),
//         funding_utxo_ids: "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0"
//             .to_string(),
//         script_data: base64.encode("Hello, Bitcoin!"),
//         sat_per_vbyte: 2,
//         change_output: None,
//         envelope: Some(546),
//         chained_script_data: None,
//     };

//     let server = TestServer::new(app)?;

//     let response: TestResponse = server
//     .get("/compose?address=bc1ptr86swg5ul8nn85fastuxv5kzsuytx5cyjckr2s5aqnp3wyw53lsz678x2&x_only_public_key=54e639c9617c3be8c5c8a5aeaecf7e383f78733421809903f01ac2841c8bc00f&funding_utxo_ids=dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8%3A0&script_data=SGVsbG8sIEJpdGNvaW4h&sat_per_vbyte=2&change_output=true&envelope=546")
//     .await;

//     println!("Response: {:#?}", response);
//     assert_eq!(response.status_code(), StatusCode::OK);
//     let result: ComposeResponse = serde_json::from_slice(response.as_bytes()).unwrap();

//     let compose_outputs = result.result;

//     let mut commit_transaction = compose_outputs.commit_transaction;

//     let tap_script = compose_outputs.tap_script;
//     let taproot_spend_info = TaprootBuilder::new()
//         .add_leaf(0, tap_script.clone())
//         .map_err(|e| anyhow!("Failed to add leaf: {}", e))?
//         .finalize(&secp, internal_key)
//         .map_err(|e| anyhow!("Failed to finalize Taproot tree: {:?}", e))?;
//     let script_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), KnownHrp::Mainnet);

//     assert_eq!(commit_transaction.input.len(), 1);
//     assert_eq!(commit_transaction.output.len(), 1);
//     assert_eq!(commit_transaction.output[0].value.to_sat(), 8778);
//     assert_eq!(
//         commit_transaction.output[0].script_pubkey,
//         script_address.script_pubkey()
//     );

//     let mut reveal_transaction = compose_outputs.reveal_transaction;

//     assert_eq!(reveal_transaction.input.len(), 1);
//     assert_eq!(
//         reveal_transaction.input[0].previous_output.txid,
//         commit_transaction.compute_txid()
//     );
//     assert_eq!(reveal_transaction.input[0].previous_output.vout, 0);

//     assert_eq!(reveal_transaction.output.len(), 1);
//     assert_eq!(reveal_transaction.output[0].value.to_sat(), 8508);
//     assert_eq!(
//         reveal_transaction.output[0].script_pubkey,
//         seller_address.script_pubkey()
//     );

//     let commit_previous_output = TxOut {
//         value: Amount::from_sat(9000),
//         script_pubkey: seller_address.script_pubkey(),
//     };

//     test_utils::sign_key_spend(
//         &secp,
//         &mut commit_transaction,
//         &[commit_previous_output],
//         &keypair,
//         0,
//     )?;

//     let reveal_previous_output = commit_transaction.output[0].clone();

//     test_utils::sign_script_spend(
//         &secp,
//         &taproot_spend_info,
//         &tap_script,
//         &mut reveal_transaction,
//         &[reveal_previous_output],
//         &keypair,
//         0,
//     )?;

//     let commit_tx_hex = hex::encode(serialize_tx(&commit_transaction));
//     let reveal_tx_hex = hex::encode(serialize_tx(&reveal_transaction));

//     let result = bitcoin_client
//         .test_mempool_accept(&[commit_tx_hex, reveal_tx_hex])
//         .await?;
//     println!("Result: {:#?}", result);
//     assert_eq!(result.len(), 2, "Expected exactly two transaction results");
//     assert!(result[0].allowed, "Commit transaction was rejected");
//     assert!(result[1].allowed, "Reveal transaction was rejected");
//     Ok(())
// }
