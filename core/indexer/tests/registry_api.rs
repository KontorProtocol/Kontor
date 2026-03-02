use anyhow::Result;
use axum::{Router, http::StatusCode, routing::get};
use axum_test::{TestResponse, TestServer};
use bitcoin::key::rand::RngCore;
use bitcoin::key::{Keypair, Secp256k1, rand};
use indexer::{
    api::{
        Env,
        handlers::{get_registry_entry, get_registry_entry_by_id},
    },
    bls::RegistrationProof,
    database::queries::insert_processed_block,
    runtime::{ComponentCache, Runtime, Storage},
    test_utils::new_test_db,
};
use indexer_types::{BlockRow, RegistryEntryResponse, Signer};
use serde::{Deserialize, Serialize};
use tempfile::TempDir;

#[derive(Debug, Serialize, Deserialize)]
struct RegistryResponse {
    result: RegistryEntryResponse,
}

struct RegisteredUser {
    x_only_pubkey: String,
    bls_pubkey: Vec<u8>,
}

async fn register_user(runtime: &mut Runtime) -> Result<RegisteredUser> {
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut rand::thread_rng());
    let mut ikm = [0u8; 32];
    rand::thread_rng().fill_bytes(&mut ikm);
    let bls_sk = blst::min_sig::SecretKey::key_gen(&ikm, &[]).expect("BLS key_gen");

    let proof = RegistrationProof::new(&keypair, &bls_sk.to_bytes())?;
    let x_only = keypair.x_only_public_key().0;
    let signer = Signer::XOnlyPubKey(x_only.to_string());

    runtime
        .register_bls_key(&signer, &proof.bls_pubkey, &proof.schnorr_sig, &proof.bls_sig)
        .await?;

    Ok(RegisteredUser {
        x_only_pubkey: x_only.to_string(),
        bls_pubkey: proof.bls_pubkey.to_vec(),
    })
}

async fn create_test_app() -> Result<(Router, Vec<RegisteredUser>, TempDir)> {
    let (reader, writer, (db_dir, db_name)) = new_test_db().await?;
    let conn = writer.connection();

    insert_processed_block(
        &conn,
        BlockRow::builder()
            .height(0)
            .hash(
                "0000000000000000000000000000000000000000000000000000000000000000"
                    .parse()?,
            )
            .build(),
    )
    .await?;

    let storage = Storage::builder().height(0).conn(conn.clone()).build();
    let mut runtime = Runtime::new(ComponentCache::new(), storage).await?;
    runtime.publish_native_contracts().await?;

    insert_processed_block(
        &conn,
        BlockRow::builder()
            .height(1)
            .hash(
                "0000000000000000000000000000000000000000000000000000000000000001"
                    .parse()?,
            )
            .build(),
    )
    .await?;

    runtime.storage.height = 1;
    let user0 = register_user(&mut runtime).await?;
    let user1 = register_user(&mut runtime).await?;

    let env = Env::new_test(reader, db_dir.path(), db_name).await?;

    let app = Router::new()
        .route(
            "/api/registry/entry/{x_only_pubkey}",
            get(get_registry_entry),
        )
        .route(
            "/api/registry/entry-by-id/{signer_id}",
            get(get_registry_entry_by_id),
        )
        .with_state(env);

    Ok((app, vec![user0, user1], db_dir))
}

#[tokio::test]
async fn test_get_registry_entry_by_pubkey() -> Result<()> {
    let (app, users, _db) = create_test_app().await?;
    let server = TestServer::new(app)?;

    let response: TestResponse = server
        .get(&format!("/api/registry/entry/{}", users[0].x_only_pubkey))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: RegistryResponse = serde_json::from_slice(response.as_bytes())?;
    assert_eq!(result.result.signer_id, 0);
    assert_eq!(result.result.x_only_pubkey, users[0].x_only_pubkey);
    assert_eq!(result.result.bls_pubkey, users[0].bls_pubkey);

    Ok(())
}

#[tokio::test]
async fn test_get_registry_entry_by_signer_id() -> Result<()> {
    let (app, users, _db) = create_test_app().await?;
    let server = TestServer::new(app)?;

    let response: TestResponse = server.get("/api/registry/entry-by-id/0").await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: RegistryResponse = serde_json::from_slice(response.as_bytes())?;
    assert_eq!(result.result.signer_id, 0);
    assert_eq!(result.result.x_only_pubkey, users[0].x_only_pubkey);
    assert_eq!(result.result.bls_pubkey, users[0].bls_pubkey);

    Ok(())
}

#[tokio::test]
async fn test_get_registry_entry_not_found_by_pubkey() -> Result<()> {
    let (app, _, _db) = create_test_app().await?;
    let server = TestServer::new(app)?;

    let fake_xonly = "ab".repeat(32);
    let response: TestResponse = server
        .get(&format!("/api/registry/entry/{}", fake_xonly))
        .await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    let error_body = response.text();
    assert!(error_body.contains("registry entry not found"));

    Ok(())
}

#[tokio::test]
async fn test_get_registry_entry_not_found_by_id() -> Result<()> {
    let (app, _, _db) = create_test_app().await?;
    let server = TestServer::new(app)?;

    let response: TestResponse = server.get("/api/registry/entry-by-id/999999").await;
    assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

    let error_body = response.text();
    assert!(error_body.contains("registry entry not found"));

    Ok(())
}

#[tokio::test]
async fn test_lookup_by_pubkey_and_by_id_return_same_entry() -> Result<()> {
    let (app, users, _db) = create_test_app().await?;
    let server = TestServer::new(app)?;

    let by_pk: TestResponse = server
        .get(&format!("/api/registry/entry/{}", users[0].x_only_pubkey))
        .await;
    let by_id: TestResponse = server.get("/api/registry/entry-by-id/0").await;

    assert_eq!(by_pk.status_code(), StatusCode::OK);
    assert_eq!(by_id.status_code(), StatusCode::OK);

    let r_pk: RegistryResponse = serde_json::from_slice(by_pk.as_bytes())?;
    let r_id: RegistryResponse = serde_json::from_slice(by_id.as_bytes())?;

    assert_eq!(r_pk.result.signer_id, r_id.result.signer_id);
    assert_eq!(r_pk.result.x_only_pubkey, r_id.result.x_only_pubkey);
    assert_eq!(r_pk.result.bls_pubkey, r_id.result.bls_pubkey);

    Ok(())
}

#[tokio::test]
async fn test_second_registered_user_gets_sequential_id() -> Result<()> {
    let (app, users, _db) = create_test_app().await?;
    let server = TestServer::new(app)?;

    let response: TestResponse = server
        .get(&format!("/api/registry/entry/{}", users[1].x_only_pubkey))
        .await;
    assert_eq!(response.status_code(), StatusCode::OK);

    let result: RegistryResponse = serde_json::from_slice(response.as_bytes())?;
    assert_eq!(result.result.signer_id, 1);
    assert_eq!(result.result.x_only_pubkey, users[1].x_only_pubkey);
    assert_eq!(result.result.bls_pubkey, users[1].bls_pubkey);

    let by_id: TestResponse = server.get("/api/registry/entry-by-id/1").await;
    assert_eq!(by_id.status_code(), StatusCode::OK);

    let by_id_result: RegistryResponse = serde_json::from_slice(by_id.as_bytes())?;
    assert_eq!(by_id_result.result.signer_id, 1);
    assert_eq!(by_id_result.result.x_only_pubkey, users[1].x_only_pubkey);

    Ok(())
}

#[tokio::test]
async fn test_two_users_have_distinct_entries() -> Result<()> {
    let (app, _users, _db) = create_test_app().await?;
    let server = TestServer::new(app)?;

    let resp0: TestResponse = server.get("/api/registry/entry-by-id/0").await;
    let resp1: TestResponse = server.get("/api/registry/entry-by-id/1").await;

    assert_eq!(resp0.status_code(), StatusCode::OK);
    assert_eq!(resp1.status_code(), StatusCode::OK);

    let r0: RegistryResponse = serde_json::from_slice(resp0.as_bytes())?;
    let r1: RegistryResponse = serde_json::from_slice(resp1.as_bytes())?;

    assert_ne!(r0.result.x_only_pubkey, r1.result.x_only_pubkey);
    assert_ne!(r0.result.bls_pubkey, r1.result.bls_pubkey);
    assert_eq!(r0.result.signer_id, 0);
    assert_eq!(r1.result.signer_id, 1);

    Ok(())
}
