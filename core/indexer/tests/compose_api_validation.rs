use anyhow::Result;
use axum::{Router, http::StatusCode, routing::get};
use axum_test::TestServer;
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as base64_engine;
use bitcoin::key::Secp256k1;
use clap::Parser;
use indexer::api::compose::{ComposeAddressQuery, ComposeQuery};
use indexer::api::{
    Env,
    handlers::{get_compose, get_compose_commit},
};
use indexer::bitcoin_client::Client;
use indexer::config::{Config, TestConfig};
use indexer::reactor::events::EventSubscriber;
use indexer::test_utils;
use tokio_util::sync::CancellationToken;

async fn create_test_app(bitcoin_client: Client) -> Result<Router> {
    let config = Config::try_parse()?;
    let (reader, _, _temp_dir) = test_utils::new_test_db(&config).await?;
    let env = Env {
        bitcoin: bitcoin_client,
        reader,
        config,
        cancel_token: CancellationToken::new(),
        event_subscriber: EventSubscriber::new(),
    };
    Ok(Router::new()
        .route("/compose", get(get_compose))
        .route("/compose/commit", get(get_compose_commit))
        .with_state(env))
}

#[tokio::test]
async fn test_addresses_payload_cap_direct() -> Result<()> {
    // Call handler directly to avoid URI length limits
    let config = Config::try_parse()?;
    let bitcoin_client = Client::new_from_config(&config)?;
    let (reader, _, _temp_dir) = test_utils::new_test_db(&config).await?;
    let env = Env {
        bitcoin: bitcoin_client,
        reader,
        config,
        cancel_token: CancellationToken::new(),
        event_subscriber: EventSubscriber::new(),
    };
    let too_many = 64 * 1024 + 1;
    let addr = "bc1p5cyxnuxmeuwuvkwfem96lxxss9s4qegsy8q8kw3x3jg4l44jzs9q5g2m4x".to_string();
    let x = "0000000000000000000000000000000000000000000000000000000000000000".to_string();
    let addresses = vec![
        ComposeAddressQuery {
            address: addr,
            x_only_public_key: x,
            funding_utxo_ids: "txid:0".to_string()
        };
        too_many
    ];
    let query = ComposeQuery {
        addresses,
        script_data: b"a".to_vec(),
        sat_per_vbyte: 1,
        envelope: None,
        chained_script_data: None,
    };
    let result =
        indexer::api::handlers::get_compose(axum::extract::Query(query), axum::extract::State(env))
            .await;
    assert!(result.is_err());
    Ok(())
}

#[tokio::test]
async fn test_invalid_fee_rate() -> Result<()> {
    let bitcoin_client = Client::new_from_config(&Config::try_parse()?)?;
    let app = create_test_app(bitcoin_client.clone()).await?;
    let server = TestServer::new(app)?;
    // Build a valid address/xonly from test utils
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();
    let (addr, key, _) = test_utils::generate_taproot_address_from_mnemonic(&secp, &config, 0)?;
    let (xonly, _) =
        bitcoin::secp256k1::Keypair::from_secret_key(&secp, &key.private_key).x_only_public_key();
    let addresses = vec![ComposeAddressQuery {
        address: addr.to_string(),
        x_only_public_key: xonly.to_string(),
        funding_utxo_ids: "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0"
            .to_string(),
    }];
    let addresses_b64 = base64_engine.encode(serde_json::to_vec(&addresses)?);
    // sat_per_vbyte set to u64::MAX (invalid for FeeRate::from_sat_per_vb)
    let resp = server
        .get(&format!(
            "/compose?addresses={}&script_data={}&sat_per_vbyte=18446744073709551615",
            urlencoding::encode(&addresses_b64),
            urlencoding::encode(&base64_engine.encode("a"))
        ))
        .await;
    assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn test_out_of_bounds_vout_returns_error() -> Result<()> {
    let bitcoin_client = Client::new_from_config(&Config::try_parse()?)?;
    let app = create_test_app(bitcoin_client.clone()).await?;
    let server = TestServer::new(app)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();
    let (addr, key, _) = test_utils::generate_taproot_address_from_mnemonic(&secp, &config, 0)?;
    let (xonly, _) =
        bitcoin::secp256k1::Keypair::from_secret_key(&secp, &key.private_key).x_only_public_key();
    let addresses = vec![ComposeAddressQuery {
        address: addr.to_string(),
        x_only_public_key: xonly.to_string(),
        funding_utxo_ids: "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:99"
            .to_string(),
    }];
    let addresses_b64 = base64_engine.encode(serde_json::to_vec(&addresses)?);
    let resp = server
        .get(&format!(
            "/compose?addresses={}&script_data={}&sat_per_vbyte=2",
            urlencoding::encode(&addresses_b64),
            urlencoding::encode(&base64_engine.encode("a"))
        ))
        .await;
    assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
    let msg = resp.text();
    assert!(msg.contains("vout") || msg.contains("funding"));
    Ok(())
}

#[tokio::test]
async fn test_duplicate_address_rejected() -> Result<()> {
    let bitcoin_client = Client::new_from_config(&Config::try_parse()?)?;
    let app = create_test_app(bitcoin_client.clone()).await?;
    let server = TestServer::new(app)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();
    let (addr, key, _) = test_utils::generate_taproot_address_from_mnemonic(&secp, &config, 0)?;
    let (xonly, _) =
        bitcoin::secp256k1::Keypair::from_secret_key(&secp, &key.private_key).x_only_public_key();
    // Two entries with the same address string
    let addresses = vec![
        ComposeAddressQuery {
            address: addr.to_string(),
            x_only_public_key: xonly.to_string(),
            funding_utxo_ids: "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0"
                .to_string(),
        },
        ComposeAddressQuery {
            address: addr.to_string(),
            x_only_public_key: xonly.to_string(),
            funding_utxo_ids: "01587d31f4144ab80432d8a48641ff6a0db29dc397ced675823791368e6eac7b:0"
                .to_string(),
        },
    ];
    let addresses_b64 = base64_engine.encode(serde_json::to_vec(&addresses)?);
    let resp = server
        .get(&format!(
            "/compose?addresses={}&script_data={}&sat_per_vbyte=2",
            urlencoding::encode(&addresses_b64),
            urlencoding::encode(&base64_engine.encode("a"))
        ))
        .await;
    assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
    let body = resp.text();
    assert!(body.contains("duplicate address"));
    Ok(())
}

#[tokio::test]
async fn test_duplicate_outpoint_across_participants_rejected() -> Result<()> {
    let bitcoin_client = Client::new_from_config(&Config::try_parse()?)?;
    let app = create_test_app(bitcoin_client.clone()).await?;
    let server = TestServer::new(app)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();
    let (addr0, key0, _) = test_utils::generate_taproot_address_from_mnemonic(&secp, &config, 0)?;
    let (addr1, key1, _) = test_utils::generate_taproot_address_from_mnemonic(&secp, &config, 1)?;
    let (x0, _) =
        bitcoin::secp256k1::Keypair::from_secret_key(&secp, &key0.private_key).x_only_public_key();
    let (x1, _) =
        bitcoin::secp256k1::Keypair::from_secret_key(&secp, &key1.private_key).x_only_public_key();
    // Same outpoint for both participants
    let addresses = vec![
        ComposeAddressQuery {
            address: addr0.to_string(),
            x_only_public_key: x0.to_string(),
            funding_utxo_ids: "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0"
                .to_string(),
        },
        ComposeAddressQuery {
            address: addr1.to_string(),
            x_only_public_key: x1.to_string(),
            funding_utxo_ids: "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0"
                .to_string(),
        },
    ];
    let addresses_b64 = base64_engine.encode(serde_json::to_vec(&addresses)?);
    let resp = server
        .get(&format!(
            "/compose?addresses={}&script_data={}&sat_per_vbyte=2",
            urlencoding::encode(&addresses_b64),
            urlencoding::encode(&base64_engine.encode("a"))
        ))
        .await;
    assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
    let body = resp.text();
    assert!(body.contains("duplicate funding outpoint"));
    Ok(())
}

#[tokio::test]
async fn test_invalid_xonly_key_rejected() -> Result<()> {
    let bitcoin_client = Client::new_from_config(&Config::try_parse()?)?;
    let app = create_test_app(bitcoin_client.clone()).await?;
    let server = TestServer::new(app)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();
    let (addr, _key, _) = test_utils::generate_taproot_address_from_mnemonic(&secp, &config, 0)?;
    // Invalid hex for x-only key
    let addresses = vec![ComposeAddressQuery {
        address: addr.to_string(),
        x_only_public_key: "not-a-key".to_string(),
        funding_utxo_ids: "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8:0"
            .to_string(),
    }];
    let addresses_b64 = base64_engine.encode(serde_json::to_vec(&addresses)?);
    let resp = server
        .get(&format!(
            "/compose?addresses={}&script_data={}&sat_per_vbyte=2",
            urlencoding::encode(&addresses_b64),
            urlencoding::encode(&base64_engine.encode("a"))
        ))
        .await;
    assert_eq!(resp.status_code(), StatusCode::BAD_REQUEST);
    Ok(())
}
