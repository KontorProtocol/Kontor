use std::io::Read;

use anyhow::{Context, Result, ensure};
use bitcoin::Network;
use brotli::CompressorReader;
use deadpool::managed::{Manager as _, Metrics};
use indexer_types::BlockRow;
use wasmtime::Engine;
use wit_component::{StringEncoding, embed_component_metadata};
use wit_validator::Validator;

use super::Manager;
use crate::config::DEFAULT_VIEW_GAS_LIMIT;
use crate::database::queries::{insert_block, rollback_to_height};
use crate::protocol::coordinator::selection::{ApplicationPosition, select_legacy_p1};
use crate::protocol::coordinator::view::execute_selected_view;
use crate::runtime::{ContractAddress, TransactionContext};
use crate::test_utils::{new_mock_block_hash, test_runtime};

fn fixture(value: u32) -> Result<Vec<u8>> {
    let wit = r#"package root:component;
        world root {
            import kontor:built-in/context;
            use kontor:built-in/context.{proc-context, view-context, contract};
            export init: func(ctx: borrow<proc-context>) -> contract;
            export read: func(ctx: borrow<view-context>) -> u32;
        }"#;
    let (validation, resolve) = Validator::validate_str(wit)?;
    ensure!(validation.is_valid(), "{validation}");
    let package = resolve
        .packages
        .iter()
        .find_map(|(id, package)| {
            (package.name.namespace == "root" && package.name.name == "component").then_some(id)
        })
        .context("fixture package missing")?;
    let world = resolve.select_world(&[package], Some("root"))?;
    let mut module = wat::parse_str(format!(
        r#"(module
        (import "kontor:built-in/context" "[method]proc-context.contract"
            (func $contract (param i32) (result i32)))
        (import "kontor:built-in/context" "[resource-drop]proc-context"
            (func $drop-proc (param i32)))
        (import "kontor:built-in/context" "[resource-drop]view-context"
            (func $drop-view (param i32)))
        (func (export "init") (param i32) (result i32)
            local.get 0 call $contract local.get 0 call $drop-proc)
        (func (export "read") (param i32) (result i32)
            local.get 0 call $drop-view i32.const {value}))"#
    ))?;
    embed_component_metadata(&mut module, &resolve, world, StringEncoding::UTF8, false)?;
    let mut compressed = Vec::new();
    CompressorReader::new(module.as_slice(), 4096, 5, 22).read_to_end(&mut compressed)?;
    Ok(compressed)
}

#[tokio::test]
async fn held_view_and_fresh_view_execute_their_own_code_after_id_reuse() -> Result<()> {
    let (mut writer, dir, name) = test_runtime().await?;
    let conn = writer.get_storage_conn();
    insert_block(
        &conn,
        BlockRow::builder()
            .height(2)
            .hash(new_mock_block_hash(2))
            .build(),
    )
    .await?;
    writer
        .set_context(2, Some(TransactionContext::builder().build()), None, None)
        .await;
    let id = writer
        .storage
        .insert_contract("snapshot-code", &fixture(7)?)
        .await?;
    let address = ContractAddress {
        name: "snapshot-code".into(),
        height: 2,
        tx_index: 0,
    };
    let manager = Manager::new(
        dir.path().to_path_buf(),
        name,
        Network::Regtest,
        DEFAULT_VIEW_GAS_LIMIT,
    )?;
    let mut old = manager.create().await?;
    let mut fresh = manager.create().await?;
    ensure!(Engine::same(&old.engine, &fresh.engine));
    old.storage.savepoint().await?;
    let old_selection = select_legacy_p1(
        &old.get_storage_conn(),
        Network::Regtest,
        ApplicationPosition::View,
    )
    .await?;
    ensure!(execute_selected_view(&mut old, &old_selection, &address, "read()").await? == "7");

    rollback_to_height(&conn, 1).await?;
    insert_block(
        &conn,
        BlockRow::builder()
            .height(2)
            .hash(new_mock_block_hash(2))
            .build(),
    )
    .await?;
    let replacement = writer
        .storage
        .insert_contract("snapshot-code", &fixture(9)?)
        .await?;
    ensure!(
        id == replacement,
        "fixture must reuse the old contract row ID"
    );

    // Warm the shared cache with the new publication, then run the old snapshot
    // again. Clearing on reorg cannot fix this interleaving for an ID-only cache.
    fresh.storage.savepoint().await?;
    let fresh_selection = select_legacy_p1(
        &fresh.get_storage_conn(),
        Network::Regtest,
        ApplicationPosition::View,
    )
    .await?;
    ensure!(execute_selected_view(&mut fresh, &fresh_selection, &address, "read()").await? == "9");
    ensure!(execute_selected_view(&mut old, &old_selection, &address, "read()").await? == "7");
    ensure!(execute_selected_view(&mut fresh, &fresh_selection, &address, "read()").await? == "9");
    let (entries, _) = manager.component_cache.workload_metrics().await;
    ensure!(
        entries == 2,
        "both immutable code identities should coexist"
    );
    old.storage.rollback().await?;
    manager
        .recycle(&mut old, &Metrics::default())
        .await
        .map_err(|e| anyhow::anyhow!("recycle failed: {e:?}"))?;
    old.storage.savepoint().await?;
    ensure!(
        execute_selected_view(&mut old, &old_selection, &address, "read()")
            .await
            .is_err()
    );
    let recycled_selection = select_legacy_p1(
        &old.get_storage_conn(),
        Network::Regtest,
        ApplicationPosition::View,
    )
    .await?;
    ensure!(execute_selected_view(&mut old, &recycled_selection, &address, "read()").await? == "9");
    old.storage.rollback().await?;
    fresh.storage.rollback().await?;
    Ok(())
}
