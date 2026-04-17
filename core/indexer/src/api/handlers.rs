use std::str::FromStr;

use axum::{
    Json,
    extract::{Path, Query, State},
};
use bitcoin::consensus::encode;
use indexer_types::{
    BlockRow, CommitOutputs, ComposeOutputs, ComposeQuery, ContractListRow, ContractResponse, Info,
    OpWithResult, PaginatedResponse, RegistryEntryResponse, ResultRow, RevealOutputs, RevealQuery,
    TransactionHex, TransactionRow, ViewExpr, ViewResult,
};

use crate::{
    api::compose::reveal_inputs_from_query,
    block::inspect,
    built_info,
    database::{
        queries::{
            self, get_blocks_paginated, get_checkpoint_latest, get_op_result,
            get_results_paginated, get_transaction_by_txid, get_transactions_paginated,
            select_block_by_height_or_hash, select_block_latest, select_latest_consensus_height,
        },
        types::{BlockQuery, OpResultId, ResultQuery, TransactionQuery},
    },
    database::queries::{get_signer_entry, get_signer_entry_by_id},
    runtime::ContractAddress,
};

use super::{
    Env,
    compose::{CommitInputs, ComposeInputs, compose, compose_commit, compose_reveal},
    error::HttpError,
    result::Result,
};

async fn get_info(env: &Env) -> anyhow::Result<Info> {
    let conn = env.reader.connection().await?;
    let height = select_block_latest(&conn)
        .await?
        .map(|b| b.height)
        .unwrap_or((env.config.starting_block_height - 1) as i64);
    let checkpoint = get_checkpoint_latest(&conn).await?.map(|c| c.hash);
    let consensus_height = select_latest_consensus_height(&conn).await?;
    Ok(Info {
        version: built_info::PKG_VERSION.to_string(),
        target: built_info::TARGET.to_string(),
        network: env.config.network.to_string(),
        available: *env.available.read().await,
        height,
        checkpoint,
        consensus_height,
    })
}

pub async fn get_index(State(env): State<Env>) -> Result<Info> {
    Ok(get_info(&env).await?.into())
}

pub async fn stop(State(env): State<Env>) -> Result<Info> {
    env.cancel_token.cancel();
    Ok(get_info(&env).await?.into())
}

pub async fn get_block(State(env): State<Env>, Path(identifier): Path<String>) -> Result<BlockRow> {
    match select_block_by_height_or_hash(&*env.reader.connection().await?, &identifier).await? {
        Some(block_row) => Ok(block_row.into()),
        None => Err(HttpError::NotFound(format!("block at height or hash: {}", identifier)).into()),
    }
}

pub async fn get_block_latest(State(env): State<Env>) -> Result<BlockRow> {
    match select_block_latest(&*env.reader.connection().await?).await? {
        Some(block_row) => Ok(block_row.into()),
        None => Err(HttpError::NotFound("No blocks written".to_owned()).into()),
    }
}

pub async fn post_compose(
    State(env): State<Env>,
    Json(query): Json<ComposeQuery>,
) -> Result<ComposeOutputs> {
    if query.instructions.len() > 400 * 1024 {
        return Err(HttpError::BadRequest("instructions too large".to_string()).into());
    }

    let inputs = ComposeInputs::from_query(query, env.config.network, &env.bitcoin)
        .await
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;

    let outputs = compose(inputs).map_err(|e| HttpError::BadRequest(e.to_string()))?;

    Ok(outputs.into())
}

pub async fn post_compose_commit(
    State(env): State<Env>,
    Json(query): Json<ComposeQuery>,
) -> Result<CommitOutputs> {
    if query.instructions.len() > 400 * 1024 {
        return Err(HttpError::BadRequest("instructions too large".to_string()).into());
    }

    let inputs = ComposeInputs::from_query(query, env.config.network, &env.bitcoin)
        .await
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;
    let commit_inputs = CommitInputs::from(inputs);

    let outputs =
        compose_commit(commit_inputs).map_err(|e| HttpError::BadRequest(e.to_string()))?;

    Ok(outputs.into())
}

pub async fn post_compose_reveal(
    State(env): State<Env>,
    Json(query): Json<RevealQuery>,
) -> Result<RevealOutputs> {
    let inputs = reveal_inputs_from_query(query, env.config.network)
        .await
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;
    let outputs = compose_reveal(inputs).map_err(|e| HttpError::BadRequest(e.to_string()))?;

    Ok(outputs.into())
}

pub fn validate_query(
    cursor: Option<i64>,
    offset: Option<i64>,
) -> std::result::Result<(), HttpError> {
    if cursor.is_some() && offset.is_some() {
        return Err(HttpError::BadRequest(
            "Cannot specify both cursor and offset parameters".to_string(),
        ));
    }
    Ok(())
}

pub async fn get_blocks(
    Query(query): Query<BlockQuery>,
    State(env): State<Env>,
) -> Result<PaginatedResponse<BlockRow>> {
    validate_query(query.cursor, query.offset)?;
    let (results, pagination) =
        get_blocks_paginated(&*env.reader.connection().await?, query).await?;
    Ok(PaginatedResponse {
        results,
        pagination,
    }
    .into())
}

pub async fn get_transactions(
    Query(query): Query<TransactionQuery>,
    State(env): State<Env>,
) -> Result<PaginatedResponse<TransactionRow>> {
    validate_query(query.cursor, query.offset)?;
    let (results, pagination) =
        get_transactions_paginated(&*env.reader.connection().await?, query).await?;
    Ok(PaginatedResponse {
        results,
        pagination,
    }
    .into())
}

pub async fn get_block_transactions(
    Path(identifier): Path<String>,
    Query(mut query): Query<TransactionQuery>,
    State(env): State<Env>,
) -> Result<PaginatedResponse<TransactionRow>> {
    validate_query(query.cursor, query.offset)?;
    let conn = env.reader.connection().await?;
    let block = select_block_by_height_or_hash(&conn, &identifier)
        .await?
        .ok_or_else(|| HttpError::NotFound(format!("block at height or hash: {}", identifier)))?;
    query.height = Some(block.height);
    let (results, pagination) = get_transactions_paginated(&conn, query).await?;
    Ok(PaginatedResponse {
        results,
        pagination,
    }
    .into())
}

pub async fn get_transaction(
    Path(txid): Path<String>,
    State(env): State<Env>,
) -> Result<TransactionRow> {
    match get_transaction_by_txid(&*env.reader.connection().await?, &txid).await? {
        Some(transaction) => Ok(transaction.into()),
        None => Err(HttpError::NotFound(format!("transaction: {}", txid)).into()),
    }
}

pub async fn post_transaction_hex_inspect(
    State(env): State<Env>,
    Json(TransactionHex { hex }): Json<TransactionHex>,
) -> Result<Vec<OpWithResult>> {
    let btx = encode::deserialize_hex::<bitcoin::Transaction>(&hex)
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;
    let tx = crate::block::filter_map((0, btx))
        .ok_or_else(|| HttpError::BadRequest("Not a valid Kontor transaction".to_string()))?;
    let conn = env.reader.connection().await?;
    Ok(inspect(&conn, &tx).await?.into())
}

pub async fn get_transaction_inspect(
    State(env): State<Env>,
    Path(txid): Path<String>,
) -> Result<Vec<OpWithResult>> {
    let txid = bitcoin::Txid::from_str(&txid)
        .map_err(|e| HttpError::BadRequest(format!("Invalid txid: {}", e)))?;
    let btx = env.bitcoin.get_raw_transaction(&txid).await?;
    let tx = crate::block::filter_map((0, btx))
        .ok_or_else(|| HttpError::BadRequest("Not a valid Kontor transaction".to_string()))?;
    let conn = env.reader.connection().await?;
    Ok(inspect(&conn, &tx).await?.into())
}

pub async fn post_simulate(
    State(env): State<Env>,
    Json(TransactionHex { hex }): Json<TransactionHex>,
) -> Result<Vec<OpWithResult>> {
    let btx = encode::deserialize_hex::<bitcoin::Transaction>(&hex)
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;
    let tx = crate::block::filter_map((0, btx))
        .ok_or_else(|| HttpError::BadRequest("Not a valid Kontor transaction".to_string()))?;
    let (ret_tx, ret_rx) = tokio::sync::oneshot::channel();
    env.simulate_tx.send((tx, ret_tx)).await?;
    Ok(ret_rx
        .await?
        .map_err(|e| HttpError::BadRequest(e.to_string()))?
        .into())
}

pub async fn post_contract(
    Path(address): Path<String>,
    State(env): State<Env>,
    Json(ViewExpr { expr }): Json<ViewExpr>,
) -> Result<ViewResult> {
    if !*env.available.read().await {
        return Err(HttpError::ServiceUnavailable("Indexer is not available".to_string()).into());
    }
    let contract_address = address
        .parse::<ContractAddress>()
        .map_err(|_| HttpError::BadRequest("Invalid contract address".to_string()))?;
    let result = env
        .runtime_pool
        .get()
        .await?
        .execute(None, &contract_address, &expr)
        .await;
    Ok(match result {
        Ok(value) => ViewResult::Ok { value },
        Err(e) => ViewResult::Err {
            message: format!("{:?}", e),
        },
    }
    .into())
}

pub async fn get_contracts(State(env): State<Env>) -> Result<Vec<ContractListRow>> {
    let conn = env.reader.connection().await?;
    Ok(queries::get_contracts(&conn).await?.into())
}

pub async fn get_contract(
    Path(address): Path<String>,
    State(env): State<Env>,
) -> Result<ContractResponse> {
    if !*env.available.read().await {
        return Err(HttpError::ServiceUnavailable("Indexer is not available".to_string()).into());
    }
    let contract_address = address
        .parse::<ContractAddress>()
        .map_err(|_| HttpError::BadRequest("Invalid contract address".to_string()))?;
    let runtime = env.runtime_pool.get().await?;
    let contract_id = runtime
        .storage
        .contract_id(&contract_address)
        .await?
        .ok_or(HttpError::NotFound("Contract not found".to_string()))?;

    let wit = runtime.storage.component_wit(contract_id).await?;
    Ok(ContractResponse { wit }.into())
}

pub async fn get_results(
    Query(query): Query<ResultQuery>,
    State(env): State<Env>,
) -> Result<PaginatedResponse<ResultRow>> {
    validate_query(query.cursor, query.offset)?;
    if query.start_height.is_some() && query.height.is_some() {
        return Err(HttpError::BadRequest(
            "start_height and height cannot be used together".to_string(),
        )
        .into());
    }

    if query.func.is_some() && query.contract.is_none() {
        return Err(HttpError::BadRequest("func requires contract".to_string()).into());
    }

    let (results, pagination) =
        get_results_paginated(&*env.reader.connection().await?, query).await?;
    Ok(PaginatedResponse {
        results: results.into_iter().map(Into::into).collect(),
        pagination,
    }
    .into())
}

pub async fn get_result(
    Path(id): Path<String>,
    State(env): State<Env>,
) -> Result<Option<ResultRow>> {
    let id = id
        .parse::<OpResultId>()
        .map_err(|_| HttpError::BadRequest("Invalid ID".to_string()))?;
    Ok(get_op_result(&*env.reader.connection().await?, &id)
        .await?
        .map(Into::into)
        .into())
}

pub async fn get_registry_entry(
    Path(identifier): Path<String>,
    State(env): State<Env>,
) -> Result<RegistryEntryResponse> {
    if !*env.available.read().await {
        return Err(HttpError::ServiceUnavailable("Indexer is not available".to_string()).into());
    }
    let mut runtime = env.runtime_pool.get().await?;

    let conn = runtime.get_storage_conn();
    let entry = if let Ok(signer_id) = identifier.parse::<u64>() {
        get_signer_entry_by_id(&conn, signer_id as i64)
            .await
            .map_err(|e| HttpError::BadRequest(e.to_string()))?
    } else {
        get_signer_entry(&conn, &identifier)
            .await
            .map_err(|e| HttpError::BadRequest(e.to_string()))?
    };

    match entry {
        Some(e) => Ok(RegistryEntryResponse {
            signer_id: e.signer_id as u64,
            x_only_pubkey: e.x_only_pubkey,
            bls_pubkey: e.bls_pubkey,
            next_nonce: e.next_nonce as u64,
        }
        .into()),
        None => {
            Err(HttpError::NotFound(format!("registry entry not found for: {}", identifier)).into())
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        api::{Env, handlers::get_registry_entry},
        bls::RegistrationProof,
        database::queries::{get_signer_entry, insert_block},
        runtime::{ComponentCache, Runtime, Storage},
        test_utils::new_test_db,
    };
    use anyhow::{Result, anyhow};
    use axum::{Router, http::StatusCode, routing::get};
    use axum_test::{TestResponse, TestServer};
    use bitcoin::key::rand::RngCore;
    use bitcoin::key::{Keypair, Secp256k1, rand};
    use crate::runtime::wit::Signer;
    use indexer_types::{BlockRow, RegistryEntryResponse};
    use serde::{Deserialize, Serialize};
    use tempfile::TempDir;

    #[derive(Debug, Serialize, Deserialize)]
    struct RegistryResponse {
        result: RegistryEntryResponse,
    }

    struct RegisteredUser {
        signer_id: u64,
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
        let identity = runtime.get_or_create_identity(&x_only.to_string()).await?;
        let signer = Signer::Id(identity);

        runtime
            .register_bls_key(
                &signer,
                &proof.bls_pubkey,
                &proof.schnorr_sig,
                &proof.bls_sig,
            )
            .await?;

        let conn = runtime.get_storage_conn();
        let entry = get_signer_entry(&conn, &x_only.to_string())
            .await
            .map_err(|e| anyhow!("{e}"))?
            .expect("signer entry must exist after registration");

        Ok(RegisteredUser {
            signer_id: entry.signer_id as u64,
            x_only_pubkey: x_only.to_string(),
            bls_pubkey: proof.bls_pubkey.to_vec(),
        })
    }

    async fn create_test_app() -> Result<(Router, Vec<RegisteredUser>, TempDir)> {
        let (reader, writer, (db_dir, db_name)) = new_test_db().await?;
        let conn = writer.connection();

        insert_block(
            &conn,
            BlockRow::builder()
                .height(0)
                .hash("0000000000000000000000000000000000000000000000000000000000000000".parse()?)
                .build(),
        )
        .await?;

        let storage = Storage::builder().height(0).conn(conn.clone()).build();
        let mut runtime = Runtime::new(ComponentCache::new(), storage).await?;
        runtime.publish_native_contracts(&[]).await?;

        insert_block(
            &conn,
            BlockRow::builder()
                .height(1)
                .hash("0000000000000000000000000000000000000000000000000000000000000001".parse()?)
                .build(),
        )
        .await?;

        runtime.storage.height = 1;
        let user0 = register_user(&mut runtime).await?;
        let user1 = register_user(&mut runtime).await?;

        let env = Env::new_test(reader, db_dir.path(), db_name).await?;

        let app = Router::new()
            .route(
                "/api/registry/entry/{pubkey_or_id}",
                get(get_registry_entry),
            )
            .with_state(env);

        Ok((app, vec![user0, user1], db_dir))
    }

    #[tokio::test]
    async fn test_get_registry_entry_by_pubkey() -> Result<()> {
        let (app, users, _db) = create_test_app().await?;
        let server = TestServer::new(app);

        let response: TestResponse = server
            .get(&format!("/api/registry/entry/{}", users[0].x_only_pubkey))
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let result: RegistryResponse = serde_json::from_slice(response.as_bytes())?;
        assert_eq!(result.result.signer_id, users[0].signer_id);
        assert_eq!(result.result.x_only_pubkey, users[0].x_only_pubkey);
        assert_eq!(result.result.bls_pubkey, Some(users[0].bls_pubkey.clone()));
        assert_eq!(result.result.next_nonce, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_registry_entry_by_signer_id() -> Result<()> {
        let (app, users, _db) = create_test_app().await?;
        let server = TestServer::new(app);

        let response: TestResponse = server
            .get(&format!("/api/registry/entry/{}", users[0].signer_id))
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let result: RegistryResponse = serde_json::from_slice(response.as_bytes())?;
        assert_eq!(result.result.signer_id, users[0].signer_id);
        assert_eq!(result.result.x_only_pubkey, users[0].x_only_pubkey);
        assert_eq!(result.result.bls_pubkey, Some(users[0].bls_pubkey.clone()));
        assert_eq!(result.result.next_nonce, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_get_registry_entry_not_found_by_pubkey() -> Result<()> {
        let (app, _, _db) = create_test_app().await?;
        let server = TestServer::new(app);

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
        let server = TestServer::new(app);

        let response: TestResponse = server.get("/api/registry/entry/999999").await;
        assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

        let error_body = response.text();
        assert!(error_body.contains("registry entry not found"));

        Ok(())
    }

    #[tokio::test]
    async fn test_lookup_by_pubkey_and_by_id_return_same_entry() -> Result<()> {
        let (app, users, _db) = create_test_app().await?;
        let server = TestServer::new(app);

        let by_pk: TestResponse = server
            .get(&format!("/api/registry/entry/{}", users[0].x_only_pubkey))
            .await;
        let by_id: TestResponse = server
            .get(&format!("/api/registry/entry/{}", users[0].signer_id))
            .await;

        assert_eq!(by_pk.status_code(), StatusCode::OK);
        assert_eq!(by_id.status_code(), StatusCode::OK);

        let r_pk: RegistryResponse = serde_json::from_slice(by_pk.as_bytes())?;
        let r_id: RegistryResponse = serde_json::from_slice(by_id.as_bytes())?;

        assert_eq!(r_pk.result.signer_id, r_id.result.signer_id);
        assert_eq!(r_pk.result.x_only_pubkey, r_id.result.x_only_pubkey);
        assert_eq!(r_pk.result.bls_pubkey, r_id.result.bls_pubkey);
        assert_eq!(r_pk.result.next_nonce, r_id.result.next_nonce);

        Ok(())
    }

    #[tokio::test]
    async fn test_second_registered_user_gets_sequential_id() -> Result<()> {
        let (app, users, _db) = create_test_app().await?;
        let server = TestServer::new(app);

        let response: TestResponse = server
            .get(&format!("/api/registry/entry/{}", users[1].x_only_pubkey))
            .await;
        assert_eq!(response.status_code(), StatusCode::OK);

        let result: RegistryResponse = serde_json::from_slice(response.as_bytes())?;
        assert_eq!(result.result.signer_id, users[1].signer_id);
        assert_eq!(result.result.x_only_pubkey, users[1].x_only_pubkey);
        assert_eq!(result.result.bls_pubkey, Some(users[1].bls_pubkey.clone()));
        assert_eq!(result.result.next_nonce, 0);
        assert_eq!(users[1].signer_id, users[0].signer_id + 1);

        let by_id: TestResponse = server
            .get(&format!("/api/registry/entry/{}", users[1].signer_id))
            .await;
        assert_eq!(by_id.status_code(), StatusCode::OK);

        let by_id_result: RegistryResponse = serde_json::from_slice(by_id.as_bytes())?;
        assert_eq!(by_id_result.result.signer_id, users[1].signer_id);
        assert_eq!(by_id_result.result.x_only_pubkey, users[1].x_only_pubkey);
        assert_eq!(by_id_result.result.next_nonce, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_two_users_have_distinct_entries() -> Result<()> {
        let (app, users, _db) = create_test_app().await?;
        let server = TestServer::new(app);

        let resp0: TestResponse = server
            .get(&format!("/api/registry/entry/{}", users[0].signer_id))
            .await;
        let resp1: TestResponse = server
            .get(&format!("/api/registry/entry/{}", users[1].signer_id))
            .await;

        assert_eq!(resp0.status_code(), StatusCode::OK);
        assert_eq!(resp1.status_code(), StatusCode::OK);

        let r0: RegistryResponse = serde_json::from_slice(resp0.as_bytes())?;
        let r1: RegistryResponse = serde_json::from_slice(resp1.as_bytes())?;

        assert_ne!(r0.result.x_only_pubkey, r1.result.x_only_pubkey);
        assert_ne!(r0.result.bls_pubkey, r1.result.bls_pubkey);
        assert_eq!(r0.result.signer_id, users[0].signer_id);
        assert_eq!(r1.result.signer_id, users[1].signer_id);
        assert_eq!(r0.result.next_nonce, 0);
        assert_eq!(r1.result.next_nonce, 0);

        Ok(())
    }

    #[tokio::test]
    async fn test_nonce_reverts_on_reorg_rollback() -> Result<()> {
        use crate::database::queries::{get_signer_entry_by_id, rollback_to_height};

        let (_, writer, (_db_dir, _db_name)) = new_test_db().await?;
        let conn = writer.connection();

        insert_block(
            &conn,
            BlockRow::builder()
                .height(0)
                .hash("0000000000000000000000000000000000000000000000000000000000000000".parse()?)
                .build(),
        )
        .await?;

        let storage = Storage::builder().height(0).conn(conn.clone()).build();
        let mut runtime = Runtime::new(ComponentCache::new(), storage).await?;
        runtime.publish_native_contracts(&[]).await?;

        insert_block(
            &conn,
            BlockRow::builder()
                .height(1)
                .hash("0000000000000000000000000000000000000000000000000000000000000001".parse()?)
                .build(),
        )
        .await?;
        runtime.storage.height = 1;

        let user = register_user(&mut runtime).await?;
        let entry = get_signer_entry_by_id(&conn, user.signer_id as i64)
            .await?
            .expect("entry must exist");
        assert_eq!(entry.next_nonce, 0);

        insert_block(
            &conn,
            BlockRow::builder()
                .height(2)
                .hash("0000000000000000000000000000000000000000000000000000000000000002".parse()?)
                .build(),
        )
        .await?;

        crate::database::types::Identity::new(user.signer_id as i64)
            .advance_nonce(&conn, 0, 2).await?;
        let entry = get_signer_entry_by_id(&conn, user.signer_id as i64)
            .await?
            .expect("entry must exist after advance");
        assert_eq!(entry.next_nonce, 1, "nonce must be 1 after advance");

        rollback_to_height(&conn, 1).await?;

        let entry = get_signer_entry_by_id(&conn, user.signer_id as i64)
            .await?
            .expect("entry must survive rollback (registered at height 1)");
        assert_eq!(
            entry.next_nonce, 0,
            "nonce must revert to 0 after rolling back height 2"
        );

        insert_block(
            &conn,
            BlockRow::builder()
                .height(2)
                .hash("0000000000000000000000000000000000000000000000000000000000000099".parse()?)
                .build(),
        )
        .await?;

        crate::database::types::Identity::new(user.signer_id as i64)
            .advance_nonce(&conn, 0, 2).await?;
        let entry = get_signer_entry_by_id(&conn, user.signer_id as i64)
            .await?
            .expect("entry must exist after re-advance");
        assert_eq!(
            entry.next_nonce, 1,
            "nonce must advance again from 0 after reorg"
        );

        Ok(())
    }

    mod transactions {
        use crate::{
            api::{
                Env,
                handlers::{
                    get_block, get_block_latest, get_block_transactions, get_transaction,
                    get_transactions,
                },
            },
            database::queries::{insert_block, insert_transaction},
            test_utils::new_test_db,
        };
        use anyhow::Result;
        use axum::{Router, http::StatusCode, routing::get};
        use axum_test::{TestResponse, TestServer};
        use indexer_types::{BlockRow, PaginatedResponse, TransactionRow};
        use libsql::params;
        use serde::{Deserialize, Serialize};
        use tempfile::TempDir;

        #[derive(Debug, Serialize, Deserialize)]
        struct BlockResponse {
            result: BlockRow,
        }

        #[derive(Debug, Serialize, Deserialize)]
        struct TransactionListResponseWrapper {
            result: PaginatedResponse<TransactionRow>,
        }

        #[derive(Debug, Serialize, Deserialize)]
        struct TransactionResponse {
            result: TransactionRow,
        }

        async fn create_test_app() -> Result<(Router, TempDir)> {
            let (reader, writer, (db_dir, db_name)) = new_test_db().await?;

            let conn = writer.connection();

            // Insert blocks
            let block1 = BlockRow::builder()
                .height(800000)
                .hash("000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?)
                .build();
            let block2 = BlockRow::builder()
                .height(800001)
                .hash("000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05".parse()?)
                .build();
            let block3 = BlockRow::builder()
                .height(800002)
                .hash("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".parse()?)
                .build();

            insert_block(&conn, block1).await?;
            insert_block(&conn, block2).await?;
            insert_block(&conn, block3).await?;

            let reader_conn = reader.connection().await?;
            let mut reader_verify_rows = reader_conn
                .query("SELECT COUNT(*) FROM blocks", params![])
                .await?;
            if let Some(row) = reader_verify_rows.next().await? {
                let count: i64 = row.get(0)?;
                assert_eq!(count, 3);
            }

            // Insert transactions
            let tx1 = TransactionRow::builder()
                .height(800000)
                .txid(
                    "tx1_800000_0_abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
                        .to_string(),
                )
                .tx_index(0)
                .build();
            let tx2 = TransactionRow::builder()
                .height(800000)
                .txid(
                    "tx2_800000_1_123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0"
                        .to_string(),
                )
                .tx_index(1)
                .build();
            let tx3 = TransactionRow::builder()
                .height(800001)
                .txid(
                    "tx3_800001_0_fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321"
                        .to_string(),
                )
                .tx_index(0)
                .build();

            insert_transaction(&conn, tx1).await?;
            insert_transaction(&conn, tx2).await?;
            insert_transaction(&conn, tx3).await?;

            let env = Env::new_test(reader, db_dir.path(), db_name).await?;

            let router = Router::new()
                .route("/api/blocks/{identifier}", get(get_block))
                .route(
                    "/api/blocks/{identifier}/transactions",
                    get(get_block_transactions),
                )
                .route("/api/blocks/latest", get(get_block_latest))
                .route("/api/transactions", get(get_transactions))
                .route("/api/transactions/{txid}", get(get_transaction))
                .with_state(env);
            Ok((router, db_dir))
        }

        // Block API Tests
        #[tokio::test]
        async fn test_get_block_by_height() -> Result<()> {
            let (app, _db) = create_test_app().await?;
            let server = TestServer::new(app);

            let response: TestResponse = server.get("/api/blocks/800000").await;
            assert_eq!(response.status_code(), StatusCode::OK);

            let result: BlockResponse = serde_json::from_slice(response.as_bytes())?;
            assert_eq!(result.result.height, 800000);
            assert_eq!(
                result.result.hash.to_string(),
                "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04"
            );

            Ok(())
        }

        #[tokio::test]
        async fn test_get_block_by_hash() -> Result<()> {
            let (app, _db) = create_test_app().await?;
            let server = TestServer::new(app);

            let response: TestResponse = server
                .get("/api/blocks/000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05")
                .await;
            assert_eq!(response.status_code(), StatusCode::OK);

            let result: BlockResponse = serde_json::from_slice(response.as_bytes())?;
            assert_eq!(result.result.height, 800001);
            assert_eq!(
                result.result.hash.to_string(),
                "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05"
            );

            Ok(())
        }

        #[tokio::test]
        async fn test_get_block_not_found() -> Result<()> {
            let (app, _db) = create_test_app().await?;
            let server = TestServer::new(app);

            let response: TestResponse = server.get("/api/blocks/999999").await;
            assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

            let error_body = response.text();
            assert!(error_body.contains("block at height or hash: 999999"));

            Ok(())
        }

        #[tokio::test]
        async fn test_get_block_invalid_hash() -> Result<()> {
            let (app, _db) = create_test_app().await?;
            let server = TestServer::new(app);

            let response: TestResponse = server.get("/api/blocks/invalidhash123").await;
            assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

            Ok(())
        }

        #[tokio::test]
        async fn test_get_block_latest() -> Result<()> {
            let (app, _db) = create_test_app().await?;
            let server = TestServer::new(app);

            let response: TestResponse = server.get("/api/blocks/latest").await;
            assert_eq!(response.status_code(), StatusCode::OK);

            let result: BlockResponse = serde_json::from_slice(response.as_bytes())?;
            assert_eq!(result.result.height, 800002); // Highest block
            assert_eq!(
                result.result.hash.to_string(),
                "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"
            );

            Ok(())
        }

        // Transaction API Tests
        #[tokio::test]
        async fn test_get_transactions_all() -> Result<()> {
            let (app, _db) = create_test_app().await?;
            let server = TestServer::new(app);

            let response: TestResponse = server.get("/api/transactions").await;
            assert_eq!(response.status_code(), StatusCode::OK);

            // This is correct - deserialize to the wrapper type first
            let result: TransactionListResponseWrapper =
                serde_json::from_slice(response.as_bytes())?;

            assert_eq!(result.result.results.len(), 3);
            assert_eq!(result.result.pagination.total_count, 3);
            assert!(!result.result.pagination.has_more);

            // Verify ordering (DESC by height, tx_index)
            assert_eq!(result.result.results[0].height, 800001);
            assert_eq!(result.result.results[1].height, 800000);
            assert_eq!(result.result.results[2].height, 800000);

            Ok(())
        }

        #[tokio::test]
        async fn test_get_transactions_with_limit() -> Result<()> {
            let (app, _db) = create_test_app().await?;
            let server = TestServer::new(app);

            let response: TestResponse = server.get("/api/transactions?limit=3").await;
            assert_eq!(response.status_code(), StatusCode::OK);

            let result: TransactionListResponseWrapper =
                serde_json::from_slice(response.as_bytes())?;
            assert_eq!(result.result.results.len(), 3);
            assert_eq!(result.result.pagination.total_count, 3);
            assert!(!result.result.pagination.has_more);
            assert_eq!(result.result.pagination.next_offset, Some(3));
            assert!(result.result.pagination.next_cursor.is_some());

            Ok(())
        }

        #[tokio::test]
        async fn test_get_transactions_with_offset() -> Result<()> {
            let (app, _db) = create_test_app().await?;
            let server = TestServer::new(app);

            let response: TestResponse = server.get("/api/transactions?limit=2&offset=1").await;
            assert_eq!(response.status_code(), StatusCode::OK);

            let result: TransactionListResponseWrapper =
                serde_json::from_slice(response.as_bytes())?;
            assert_eq!(result.result.results.len(), 2);
            assert_eq!(result.result.pagination.total_count, 3);
            assert!(!result.result.pagination.has_more);

            Ok(())
        }

        #[tokio::test]
        async fn test_get_transactions_with_cursor() -> Result<()> {
            let (app, _db) = create_test_app().await?;
            let server = TestServer::new(app);

            // First get transactions with limit to get cursor
            let response: TestResponse = server.get("/api/transactions?limit=1").await;
            let result: TransactionListResponseWrapper =
                serde_json::from_slice(response.as_bytes())?;

            assert_eq!(response.status_code(), StatusCode::OK);
            assert_eq!(result.result.results[0].height, 800001);
            assert_eq!(result.result.results[0].tx_index, Some(0));
            assert_eq!(result.result.results.len(), 1);
            assert_eq!(result.result.pagination.total_count, 3);
            assert!(result.result.pagination.has_more);
            assert!(result.result.pagination.next_offset.is_some());
            assert!(result.result.pagination.next_cursor.is_some());

            let cursor = result.result.pagination.next_cursor.unwrap();

            assert_eq!(cursor, 3);

            // Use cursor for next page
            let response: TestResponse = server
                .get(&format!("/api/transactions?cursor={}", cursor))
                .await;
            assert_eq!(response.status_code(), StatusCode::OK);
            let result: TransactionListResponseWrapper =
                serde_json::from_slice(response.as_bytes())?;

            assert_eq!(result.result.results.len(), 2);

            Ok(())
        }

        #[tokio::test]
        async fn test_get_transactions_cursor_and_offset_error() -> Result<()> {
            let (app, _db) = create_test_app().await?;
            let server = TestServer::new(app);

            let response: TestResponse = server.get("/api/transactions?cursor=1&offset=10").await;
            assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

            let error_body = response.text();
            assert!(error_body.contains("Cannot specify both cursor and offset parameters"));

            Ok(())
        }

        #[tokio::test]
        async fn test_get_transactions_at_height() -> Result<()> {
            let (app, _db) = create_test_app().await?;
            let server = TestServer::new(app);

            let response: TestResponse = server.get("/api/transactions?height=800000").await;
            assert_eq!(response.status_code(), StatusCode::OK);

            let result: TransactionListResponseWrapper =
                serde_json::from_slice(response.as_bytes())?;
            assert_eq!(result.result.results.len(), 2);
            assert_eq!(result.result.pagination.total_count, 2);

            // All transactions should be at height 800000
            for tx in &result.result.results {
                assert_eq!(tx.height, 800000);
            }

            Ok(())
        }

        #[tokio::test]
        async fn test_get_transactions_at_height_empty() -> Result<()> {
            let (app, _db) = create_test_app().await?;
            let server = TestServer::new(app);

            let response: TestResponse = server.get("/api/transactions?height=999999").await;
            assert_eq!(response.status_code(), StatusCode::OK);

            let result: TransactionListResponseWrapper =
                serde_json::from_slice(response.as_bytes())?;
            assert_eq!(result.result.results.len(), 0);
            assert_eq!(result.result.pagination.total_count, 0);

            Ok(())
        }

        #[tokio::test]
        async fn test_get_transaction_by_txid() -> Result<()> {
            let (app, _db) = create_test_app().await?;
            let server = TestServer::new(app);

            let response: TestResponse = server
            .get("/api/transactions/tx1_800000_0_abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890")
            .await;
            assert_eq!(response.status_code(), StatusCode::OK);

            let result: TransactionResponse = serde_json::from_slice(response.as_bytes())?;
            assert_eq!(
                result.result.txid,
                "tx1_800000_0_abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890"
            );
            assert_eq!(result.result.height, 800000);
            assert_eq!(result.result.tx_index, Some(0));

            Ok(())
        }

        #[tokio::test]
        async fn test_get_transaction_not_found() -> Result<()> {
            let (app, _db) = create_test_app().await?;
            let server = TestServer::new(app);

            let response: TestResponse = server.get("/api/transactions/nonexistent_txid").await;
            assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

            let error_body = response.text();
            assert!(error_body.contains("transaction: nonexistent_txid"));

            Ok(())
        }

        #[tokio::test]
        async fn test_get_transactions_limit_bounds() -> Result<()> {
            let (app, _db) = create_test_app().await?;
            let server = TestServer::new(app);

            // Test minimum limit
            let response: TestResponse = server.get("/api/transactions?limit=-1").await;
            assert_eq!(response.status_code(), StatusCode::OK);
            let result: TransactionListResponseWrapper =
                serde_json::from_slice(response.as_bytes())?;
            assert_eq!(result.result.results.len(), 0); // Clamped to 0

            // Test maximum limit
            let response: TestResponse = server.get("/api/transactions?limit=2000").await;
            assert_eq!(response.status_code(), StatusCode::OK);
            let result: TransactionListResponseWrapper =
                serde_json::from_slice(response.as_bytes())?;
            assert_eq!(result.result.results.len(), 3); // All available transactions

            Ok(())
        }

        #[tokio::test]
        async fn test_get_transactions_invalid_cursor() -> Result<()> {
            let (app, _db) = create_test_app().await?;
            let server = TestServer::new(app);

            let response: TestResponse =
                server.get("/api/transactions?cursor=invalid_cursor").await;
            assert_eq!(response.status_code(), StatusCode::BAD_REQUEST);

            Ok(())
        }

        #[tokio::test]
        async fn test_get_block_transactions_by_height() -> Result<()> {
            let (app, _db) = create_test_app().await?;
            let server = TestServer::new(app);

            let response: TestResponse = server.get("/api/blocks/800000/transactions").await;
            assert_eq!(response.status_code(), StatusCode::OK);

            let result: TransactionListResponseWrapper =
                serde_json::from_slice(response.as_bytes())?;
            assert_eq!(result.result.results.len(), 2);
            assert_eq!(result.result.pagination.total_count, 2);

            for tx in &result.result.results {
                assert_eq!(tx.height, 800000);
            }

            Ok(())
        }

        #[tokio::test]
        async fn test_get_block_transactions_by_hash() -> Result<()> {
            let (app, _db) = create_test_app().await?;
            let server = TestServer::new(app);

            // Use block hash for height 800000
            let response: TestResponse = server
            .get("/api/blocks/000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04/transactions")
            .await;
            assert_eq!(response.status_code(), StatusCode::OK);

            let result: TransactionListResponseWrapper =
                serde_json::from_slice(response.as_bytes())?;
            assert_eq!(result.result.results.len(), 2);
            assert_eq!(result.result.pagination.total_count, 2);

            for tx in &result.result.results {
                assert_eq!(tx.height, 800000);
            }

            Ok(())
        }

        #[tokio::test]
        async fn test_get_block_transactions_not_found() -> Result<()> {
            let (app, _db) = create_test_app().await?;
            let server = TestServer::new(app);

            let response: TestResponse = server.get("/api/blocks/999999/transactions").await;
            assert_eq!(response.status_code(), StatusCode::NOT_FOUND);

            let error_body = response.text();
            assert!(error_body.contains("block at height or hash: 999999"));

            Ok(())
        }
    }

    mod transactions_pagination {
        use crate::{
            api::{
                Env,
                handlers::{get_block, get_block_latest, get_transaction, get_transactions},
            },
            bitcoin_client::Client,
            config::Config,
            database::{
                Reader, Writer,
                queries::{
                    insert_block, insert_contract, insert_contract_state, insert_transaction,
                },
                types::{ContractRow, ContractStateRow},
            },
            event::EventSubscriber,
            runtime,
            test_utils::new_test_db,
        };
        use anyhow::Result;
        use axum::{Router, routing::get};
        use axum_test::{TestResponse, TestServer};
        use indexer_types::{BlockRow, PaginatedResponse, TransactionRow};
        use libsql::params;
        use reqwest::StatusCode;
        use serde::{Deserialize, Serialize};
        use std::{path::PathBuf, sync::Arc};
        use tokio::sync::{RwLock, mpsc};
        use tokio_util::sync::CancellationToken;

        #[derive(Debug, Serialize, Deserialize)]
        struct TransactionListResponseWrapper {
            result: PaginatedResponse<TransactionRow>,
        }

        async fn create_test_app(
            reader: Reader,
            writer: Writer,
            db_dir: PathBuf,
            db_name: String,
        ) -> Result<Router> {
            let conn = writer.connection();
            // Insert blocks for heights 800000-800005
            for height in 800000..=800005 {
                let block = BlockRow::builder()
                    .height(height)
                    .hash(format!("{:064x}", height).parse()?)
                    .build();
                insert_block(&conn, block).await?;
            }

            insert_contract(
                &conn,
                ContractRow::builder()
                    .name("token".to_string())
                    .height(800000)
                    .tx_index(1)
                    .bytes(vec![])
                    .build(),
            )
            .await?;

            let mut reader_verify_rows =
                conn.query("SELECT COUNT(*) FROM blocks", params![]).await?;
            if let Some(row) = reader_verify_rows.next().await? {
                let count: i64 = row.get(0)?;
                assert_eq!(count, 6);
            }

            // Height 800000: 5 transactions (indices 0-4)
            let mut tx_ids_800000 = Vec::new();
            for tx_index in 0..5 {
                let tx = TransactionRow::builder()
                    .height(800000)
                    .txid(format!("tx_800000_{}_hash{:056x}", tx_index, tx_index))
                    .tx_index(tx_index)
                    .build();
                tx_ids_800000.push(insert_transaction(&conn, tx).await?);
            }

            // tx_index=1 modifies the token contract
            insert_contract_state(
                &conn,
                ContractStateRow::builder()
                    .contract_id(1)
                    .tx_id(tx_ids_800000[1])
                    .height(800000)
                    .path("foo".to_string())
                    .build(),
            )
            .await?;

            // Height 800001: 3 transactions (indices 0-2)
            let mut tx_ids_800001 = Vec::new();
            for tx_index in 0..3 {
                let tx = TransactionRow::builder()
                    .height(800001)
                    .txid(format!("tx_800001_{}_hash{:056x}", tx_index, tx_index))
                    .tx_index(tx_index)
                    .build();
                tx_ids_800001.push(insert_transaction(&conn, tx).await?);
            }

            // tx_index=2 modifies the token contract
            insert_contract_state(
                &conn,
                ContractStateRow::builder()
                    .contract_id(1)
                    .tx_id(tx_ids_800001[2])
                    .height(800001)
                    .path("bar".to_string())
                    .build(),
            )
            .await?;

            // Height 800002: 7 transactions (indices 0-6)
            let mut tx_ids_800002 = Vec::new();
            for tx_index in 0..7 {
                let tx = TransactionRow::builder()
                    .height(800002)
                    .txid(format!("tx_800002_{}_hash{:056x}", tx_index, tx_index))
                    .tx_index(tx_index)
                    .build();
                tx_ids_800002.push(insert_transaction(&conn, tx).await?);
            }

            // tx_index=3 modifies the token contract
            insert_contract_state(
                &conn,
                ContractStateRow::builder()
                    .contract_id(1)
                    .tx_id(tx_ids_800002[3])
                    .height(800002)
                    .path("biz".to_string())
                    .build(),
            )
            .await?;

            // Height 800003: 1 transaction (index 0)
            let tx = TransactionRow::builder()
                .height(800003)
                .txid(
                    "tx_800003_0_hash0000000000000000000000000000000000000000000000000000000"
                        .to_string(),
                )
                .tx_index(0)
                .build();
            insert_transaction(&conn, tx).await?;

            // Height 800004: 4 transactions (indices 0-3)
            for tx_index in 0..4 {
                let tx = TransactionRow::builder()
                    .height(800004)
                    .txid(format!("tx_800004_{}_hash{:056x}", tx_index, tx_index))
                    .tx_index(tx_index)
                    .build();
                insert_transaction(&conn, tx).await?;
            }

            // Height 800005: 2 transactions (indices 0-1)
            for tx_index in 0..2 {
                let tx = TransactionRow::builder()
                    .height(800005)
                    .txid(format!("tx_800005_{}_hash{:056x}", tx_index, tx_index))
                    .tx_index(tx_index)
                    .build();
                insert_transaction(&conn, tx).await?;
            }

            let (simulate_tx, _) = mpsc::channel(10);
            let env = Env {
                bitcoin: Client::new("".to_string(), "".to_string(), "".to_string())?,
                config: Config::new_na(),
                cancel_token: CancellationToken::new(),
                available: Arc::new(RwLock::new(true)),
                event_subscriber: EventSubscriber::new(),
                runtime_pool: runtime::pool::new(db_dir, db_name).await?,
                reader,
                simulate_tx,
            };

            Ok(Router::new()
                .route("/api/blocks/{identifier}", get(get_block))
                .route("/api/blocks/latest", get(get_block_latest))
                .route("/api/transactions", get(get_transactions))
                .route("/api/transactions/{txid}", get(get_transaction))
                .with_state(env))
        }

        async fn collect_all_transactions_with_cursor(
            server: &TestServer,
            endpoint: &str,
            limit: u32,
            height: Option<u32>,
        ) -> Result<Vec<TransactionRow>> {
            let mut all_transactions = Vec::new();
            let mut cursor: Option<i64> = None;
            let mut iterations = 0;
            const MAX_ITERATIONS: usize = 50; // Safety limit

            loop {
                iterations += 1;
                if iterations > MAX_ITERATIONS {
                    panic!("Too many iterations, possible infinite loop");
                }

                let mut url = format!("{}?limit={}", endpoint, limit);
                if let Some(c) = cursor.as_ref() {
                    url += &format!("&cursor={}", c);
                }
                if let Some(h) = height {
                    url += &format!("&height={}", h);
                }

                let response: TestResponse = server.get(&url).await;
                assert_eq!(response.status_code(), StatusCode::OK);

                let result: TransactionListResponseWrapper =
                    serde_json::from_slice(response.as_bytes())?;

                all_transactions.extend(result.result.results);

                if !result.result.pagination.has_more {
                    break;
                }

                cursor = result.result.pagination.next_cursor;
                assert!(
                    cursor.is_some(),
                    "has_more=true but no next_cursor provided"
                );
            }

            Ok(all_transactions)
        }

        async fn collect_all_transactions_with_offset(
            server: &TestServer,
            endpoint: &str,
            limit: u32,
            height: Option<u32>,
        ) -> Result<Vec<TransactionRow>> {
            let mut all_transactions = Vec::new();
            let mut offset = 0;
            let mut iterations = 0;
            const MAX_ITERATIONS: usize = 50;

            loop {
                iterations += 1;
                if iterations > MAX_ITERATIONS {
                    panic!("Too many iterations, possible infinite loop");
                }

                let mut url = format!("{}?limit={}&offset={}", endpoint, limit, offset);
                if let Some(h) = height {
                    url += &format!("&height={}", h);
                }
                let response: TestResponse = server.get(&url).await;
                assert_eq!(response.status_code(), StatusCode::OK);

                let result: TransactionListResponseWrapper =
                    serde_json::from_slice(response.as_bytes())?;

                all_transactions.extend(result.result.results);

                if !result.result.pagination.has_more {
                    break;
                }

                offset = result.result.pagination.next_offset.unwrap_or(0);
            }

            Ok(all_transactions)
        }

        #[tokio::test]
        async fn test_cursor_pagination_no_gaps_all_transactions() -> Result<()> {
            let (reader, writer, (db_dir, db_name)) = new_test_db().await?;
            let app = create_test_app(reader, writer, db_dir.path().to_path_buf(), db_name).await?;
            let server = TestServer::new(app);

            // Test with different page sizes
            for limit in [1, 2, 3, 5, 7, 10] {
                let cursor_transactions =
                    collect_all_transactions_with_cursor(&server, "/api/transactions", limit, None)
                        .await?;
                let offset_transactions =
                    collect_all_transactions_with_offset(&server, "/api/transactions", limit, None)
                        .await?;

                // Both methods should return the same transactions in the same order
                assert_eq!(
                    cursor_transactions.len(),
                    offset_transactions.len(),
                    "Cursor and offset pagination returned different counts for limit={}",
                    limit
                );

                for (i, (cursor_tx, offset_tx)) in cursor_transactions
                    .iter()
                    .zip(offset_transactions.iter())
                    .enumerate()
                {
                    assert_eq!(
                        cursor_tx.txid, offset_tx.txid,
                        "Transaction mismatch at index {} for limit={}",
                        i, limit
                    );
                    assert_eq!(
                        cursor_tx.height, offset_tx.height,
                        "Height mismatch at index {} for limit={}",
                        i, limit
                    );
                    assert_eq!(
                        cursor_tx.tx_index, offset_tx.tx_index,
                        "tx_index mismatch at index {} for limit={}",
                        i, limit
                    );
                }

                // Verify total count (5+3+7+1+4+2 = 22 transactions)
                assert_eq!(
                    cursor_transactions.len(),
                    22,
                    "Expected 22 total transactions for limit={}",
                    limit
                );

                // Verify ordering (DESC by height, tx_index)
                for i in 1..cursor_transactions.len() {
                    let prev = &cursor_transactions[i - 1];
                    let curr = &cursor_transactions[i];

                    assert!(
                        prev.height > curr.height
                            || (prev.height == curr.height && prev.tx_index > curr.tx_index),
                        "Incorrect ordering at index {} for limit={}: ({}, {:?}) should come before ({}, {:?})",
                        i,
                        limit,
                        prev.height,
                        prev.tx_index,
                        curr.height,
                        curr.tx_index
                    );
                }
            }

            Ok(())
        }

        #[tokio::test]
        async fn test_cursor_pagination_no_gaps_single_height() -> Result<()> {
            let (reader, writer, (db_dir, db_name)) = new_test_db().await?;
            let app = create_test_app(reader, writer, db_dir.path().to_path_buf(), db_name).await?;
            let server = TestServer::new(app);

            // Test pagination for height 800000 (5 transactions)
            for limit in [1, 2, 3, 4, 5, 6] {
                let cursor_transactions = collect_all_transactions_with_cursor(
                    &server,
                    "/api/transactions",
                    limit,
                    Some(800000),
                )
                .await?;
                let offset_transactions = collect_all_transactions_with_offset(
                    &server,
                    "/api/transactions",
                    limit,
                    Some(800000),
                )
                .await?;

                // Both methods should return the same transactions
                assert_eq!(
                    cursor_transactions.len(),
                    offset_transactions.len(),
                    "Cursor and offset pagination returned different counts for height 800000, limit={}",
                    limit
                );

                for (i, (cursor_tx, offset_tx)) in cursor_transactions
                    .iter()
                    .zip(offset_transactions.iter())
                    .enumerate()
                {
                    assert_eq!(
                        cursor_tx.txid, offset_tx.txid,
                        "Transaction mismatch at index {} for height 800000, limit={}",
                        i, limit
                    );
                }

                // Verify all transactions are at height 800000
                for tx in &cursor_transactions {
                    assert_eq!(
                        tx.height, 800000,
                        "Transaction not at expected height 800000"
                    );
                }

                // Verify count (5 transactions at height 800000)
                assert_eq!(
                    cursor_transactions.len(),
                    5,
                    "Expected 5 transactions at height 800000 for limit={}",
                    limit
                );

                // Verify ordering (DESC by tx_index: 4, 3, 2, 1, 0)
                let expected_indices: [i64; 5] = [4, 3, 2, 1, 0];
                for (i, tx) in cursor_transactions.iter().enumerate() {
                    assert_eq!(
                        tx.tx_index,
                        Some(expected_indices[i]),
                        "Incorrect tx_index at position {} for limit={}: expected {}, got {:?}",
                        i,
                        limit,
                        expected_indices[i],
                        tx.tx_index
                    );
                }
            }

            Ok(())
        }

        #[tokio::test]
        async fn test_cursor_pagination_no_gaps_height_with_many_transactions() -> Result<()> {
            let (reader, writer, (db_dir, db_name)) = new_test_db().await?;
            let app = create_test_app(reader, writer, db_dir.path().to_path_buf(), db_name).await?;
            let server = TestServer::new(app);

            // Test pagination for height 800002 (7 transactions)
            for limit in [1, 2, 3, 4, 5, 6, 7, 8] {
                let cursor_transactions = collect_all_transactions_with_cursor(
                    &server,
                    "/api/transactions",
                    limit,
                    Some(800002),
                )
                .await?;
                let offset_transactions = collect_all_transactions_with_offset(
                    &server,
                    "/api/transactions",
                    limit,
                    Some(800002),
                )
                .await?;

                // Both methods should return the same transactions
                assert_eq!(
                    cursor_transactions.len(),
                    offset_transactions.len(),
                    "Cursor and offset pagination returned different counts for height 800002, limit={}",
                    limit
                );

                // Verify count (7 transactions at height 800002)
                assert_eq!(
                    cursor_transactions.len(),
                    7,
                    "Expected 7 transactions at height 800002 for limit={}",
                    limit
                );

                // Verify ordering (DESC by tx_index: 6, 5, 4, 3, 2, 1, 0)
                let expected_indices: [i64; 7] = [6, 5, 4, 3, 2, 1, 0];
                for (i, tx) in cursor_transactions.iter().enumerate() {
                    assert_eq!(
                        tx.tx_index,
                        Some(expected_indices[i]),
                        "Incorrect tx_index at position {} for limit={}: expected {}, got {:?}",
                        i,
                        limit,
                        expected_indices[i],
                        tx.tx_index
                    );
                }
            }

            Ok(())
        }

        #[tokio::test]
        async fn test_cursor_pagination_edge_cases() -> Result<()> {
            let (reader, writer, (db_dir, db_name)) = new_test_db().await?;
            let app = create_test_app(reader, writer, db_dir.path().to_path_buf(), db_name).await?;
            let server = TestServer::new(app);

            // Test with limit=1 to ensure every transaction is returned exactly once
            let transactions =
                collect_all_transactions_with_cursor(&server, "/api/transactions", 1, None).await?;

            // Create a set of unique transaction IDs to check for duplicates
            let mut seen_txids = std::collections::HashSet::new();
            for tx in &transactions {
                assert!(
                    seen_txids.insert(&tx.txid),
                    "Duplicate transaction found: {}",
                    tx.txid
                );
            }

            // Test height with single transaction (800003)
            let single_tx =
                collect_all_transactions_with_cursor(&server, "/api/transactions", 1, Some(800003))
                    .await?;
            assert_eq!(
                single_tx.len(),
                1,
                "Expected exactly 1 transaction at height 800003"
            );
            assert_eq!(single_tx[0].height, 800003);
            assert_eq!(single_tx[0].tx_index, Some(0));

            // Test empty height (800006 - no transactions)
            let empty_result = collect_all_transactions_with_cursor(
                &server,
                "/api/transactions",
                10,
                Some(800006),
            )
            .await?;
            assert_eq!(
                empty_result.len(),
                0,
                "Expected no transactions at height 800006"
            );

            Ok(())
        }

        #[tokio::test]
        async fn test_cursor_pagination_boundary_conditions() -> Result<()> {
            let (reader, writer, (db_dir, db_name)) = new_test_db().await?;
            let app = create_test_app(reader, writer, db_dir.path().to_path_buf(), db_name).await?;
            let server = TestServer::new(app);

            // Test that cursor pagination works correctly when page size equals total count
            let height_800001_all =
                collect_all_transactions_with_cursor(&server, "/api/transactions", 3, Some(800001))
                    .await?;
            assert_eq!(
                height_800001_all.len(),
                3,
                "Expected 3 transactions at height 800001"
            );

            // Test that cursor pagination works correctly when page size exceeds total count
            let height_800001_large = collect_all_transactions_with_cursor(
                &server,
                "/api/transactions",
                10,
                Some(800001),
            )
            .await?;
            assert_eq!(
                height_800001_large.len(),
                3,
                "Expected 3 transactions at height 800001 with large limit"
            );

            // Verify both results are identical
            for (i, (tx1, tx2)) in height_800001_all
                .iter()
                .zip(height_800001_large.iter())
                .enumerate()
            {
                assert_eq!(tx1.txid, tx2.txid, "Transaction mismatch at index {}", i);
            }

            Ok(())
        }

        #[tokio::test]
        async fn test_cursor_consistency_across_different_limits() -> Result<()> {
            let (reader, writer, (db_dir, db_name)) = new_test_db().await?;
            let app = create_test_app(reader, writer, db_dir.path().to_path_buf(), db_name).await?;
            let server = TestServer::new(app);

            // Collect all transactions with different page sizes
            let results_limit_1 =
                collect_all_transactions_with_cursor(&server, "/api/transactions", 1, None).await?;
            let results_limit_3 =
                collect_all_transactions_with_cursor(&server, "/api/transactions", 3, None).await?;
            let results_limit_7 =
                collect_all_transactions_with_cursor(&server, "/api/transactions", 7, None).await?;
            let results_limit_22 =
                collect_all_transactions_with_cursor(&server, "/api/transactions", 22, None)
                    .await?;

            // All should return the same transactions in the same order
            let all_results = [
                &results_limit_1,
                &results_limit_3,
                &results_limit_7,
                &results_limit_22,
            ];

            for (i, results) in all_results.iter().enumerate() {
                assert_eq!(results.len(), 22, "Result set {} has wrong length", i);

                for (j, (tx1, tx2)) in results_limit_1.iter().zip(results.iter()).enumerate() {
                    assert_eq!(
                        tx1.txid, tx2.txid,
                        "Transaction mismatch at index {} in result set {}",
                        j, i
                    );
                    assert_eq!(
                        tx1.height, tx2.height,
                        "Height mismatch at index {} in result set {}",
                        j, i
                    );
                    assert_eq!(
                        tx1.tx_index, tx2.tx_index,
                        "tx_index mismatch at index {} in result set {}",
                        j, i
                    );
                }
            }

            Ok(())
        }

        #[tokio::test]
        async fn test_cursor_pagination_maintains_total_count() -> Result<()> {
            let (reader, writer, (db_dir, db_name)) = new_test_db().await?;
            let app = create_test_app(reader, writer, db_dir.path().to_path_buf(), db_name).await?;
            let server = TestServer::new(app);

            // Test that total_count decreases as we paginate (showing remaining items)
            let mut cursor: Option<i64> = None;
            let mut page_count = 0;
            let limit = 3;
            let mut previous_total_count = None;

            loop {
                page_count += 1;
                let url = if let Some(ref c) = cursor {
                    format!("/api/transactions?limit={}&cursor={}", limit, c)
                } else {
                    format!("/api/transactions?limit={}", limit)
                };

                let response: TestResponse = server.get(&url).await;
                assert_eq!(response.status_code(), StatusCode::OK);

                let result: TransactionListResponseWrapper =
                    serde_json::from_slice(response.as_bytes())?;

                let current_total_count = result.result.pagination.total_count;

                // First page should have the full count
                if page_count == 1 {
                    assert_eq!(
                        current_total_count, 22,
                        "First page should show total count of 22"
                    );
                } else {
                    // Subsequent pages should have decreasing total_count (showing remaining items)
                    if let Some(prev_count) = previous_total_count {
                        assert!(
                            current_total_count < prev_count,
                            "total_count should decrease as we paginate: {} -> {}",
                            prev_count,
                            current_total_count
                        );
                    }
                }

                previous_total_count = Some(current_total_count);

                if !result.result.pagination.has_more {
                    break;
                }

                cursor = result.result.pagination.next_cursor;
            }

            assert!(page_count > 1, "Should have required multiple pages");

            Ok(())
        }

        #[tokio::test]
        async fn test_cursor_pagination_contract_address() -> Result<()> {
            let (reader, writer, (db_dir, db_name)) = new_test_db().await?;
            let app = create_test_app(reader, writer, db_dir.path().to_path_buf(), db_name).await?;
            let server = TestServer::new(app);

            let url = "/api/transactions?limit=1&contract=token_800000_1";
            let response: TestResponse = server.get(url).await;
            assert_eq!(response.status_code(), StatusCode::OK);
            let result: TransactionListResponseWrapper =
                serde_json::from_slice(response.as_bytes())?;
            let transactions = result.result.results;
            let meta = result.result.pagination;

            assert_eq!(transactions.len(), 1);
            assert_eq!(transactions[0].height, 800002);
            assert_eq!(transactions[0].tx_index, Some(3));
            assert!(meta.has_more);
            assert_eq!(meta.next_cursor, Some(transactions[0].id));
            assert_eq!(meta.total_count, 3);

            let url = format!(
                "/api/transactions?limit=1&contract=token_800000_1&cursor={}",
                meta.next_cursor.unwrap()
            );
            let response: TestResponse = server.get(&url).await;
            assert_eq!(response.status_code(), StatusCode::OK);
            let result: TransactionListResponseWrapper =
                serde_json::from_slice(response.as_bytes())?;
            let transactions = result.result.results;
            let meta = result.result.pagination;

            assert_eq!(transactions.len(), 1);
            assert_eq!(transactions[0].height, 800001);
            assert_eq!(transactions[0].tx_index, Some(2));
            assert!(meta.has_more);
            assert_eq!(meta.next_cursor, Some(transactions[0].id));

            let url = format!(
                "/api/transactions?limit=1&contract=token_800000_1&cursor={}",
                meta.next_cursor.unwrap()
            );
            let response: TestResponse = server.get(&url).await;
            assert_eq!(response.status_code(), StatusCode::OK);
            let result: TransactionListResponseWrapper =
                serde_json::from_slice(response.as_bytes())?;
            let transactions = result.result.results;
            let meta = result.result.pagination;

            assert_eq!(transactions.len(), 1);
            assert_eq!(transactions[0].height, 800000);
            assert_eq!(transactions[0].tx_index, Some(1));
            assert!(!meta.has_more);
            assert_eq!(meta.next_cursor, Some(transactions[0].id));

            Ok(())
        }

        #[tokio::test]
        async fn test_cursor_pagination_contract_address_asc() -> Result<()> {
            let (reader, writer, (db_dir, db_name)) = new_test_db().await?;
            let app = create_test_app(reader, writer, db_dir.path().to_path_buf(), db_name).await?;
            let server = TestServer::new(app);

            let url = "/api/transactions?limit=1&contract=token_800000_1&order=asc";
            let response: TestResponse = server.get(url).await;
            assert_eq!(response.status_code(), StatusCode::OK);
            let result: TransactionListResponseWrapper =
                serde_json::from_slice(response.as_bytes())?;
            let transactions = result.result.results;
            let meta = result.result.pagination;

            assert_eq!(transactions.len(), 1);
            assert_eq!(transactions[0].height, 800000);
            assert_eq!(transactions[0].tx_index, Some(1));
            assert!(meta.has_more);
            assert_eq!(meta.next_cursor, Some(transactions[0].id));
            assert_eq!(meta.total_count, 3);

            let url = format!(
                "/api/transactions?limit=1&contract=token_800000_1&cursor={}&order=asc",
                meta.next_cursor.unwrap()
            );
            let response: TestResponse = server.get(&url).await;
            assert_eq!(response.status_code(), StatusCode::OK);
            let result: TransactionListResponseWrapper =
                serde_json::from_slice(response.as_bytes())?;
            let transactions = result.result.results;
            let meta = result.result.pagination;

            assert_eq!(transactions.len(), 1);
            assert_eq!(transactions[0].height, 800001);
            assert_eq!(transactions[0].tx_index, Some(2));
            assert!(meta.has_more);
            assert_eq!(meta.next_cursor, Some(transactions[0].id));

            let url = format!(
                "/api/transactions?limit=1&contract=token_800000_1&cursor={}&order=asc",
                meta.next_cursor.unwrap()
            );
            let response: TestResponse = server.get(&url).await;
            assert_eq!(response.status_code(), StatusCode::OK);
            let result: TransactionListResponseWrapper =
                serde_json::from_slice(response.as_bytes())?;
            let transactions = result.result.results;
            let meta = result.result.pagination;

            assert_eq!(transactions.len(), 1);
            assert_eq!(transactions[0].height, 800002);
            assert_eq!(transactions[0].tx_index, Some(3));
            assert!(!meta.has_more);
            assert_eq!(meta.next_cursor, Some(transactions[0].id));

            Ok(())
        }
    }
}
