use std::hint::black_box;
use std::sync::Arc;
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use futures_util::TryStreamExt;
use indexer_types::serialize;
use libsql::{AuthAction, Authorization, Connection, params};
use serde_json::json;
use stdlib::{KeyPath, subtree_end};
use wasmtime::Store;
use wasmtime::component::Resource;

use super::{BUDGET, KeysHost, StorageHost, host};
use crate::runtime::Runtime;
use crate::runtime::wit::ProcStorage;
use crate::test_utils::test_runtime;

// These layouts share production host calls but do not change contract codegen.
#[derive(Clone, Copy, Debug)]
enum Layout {
    Root,
    Path,
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Enum,
    Option,
}

#[derive(Clone, Copy, Debug)]
enum Payload {
    Unit,
    Scalar,
    Compound(u64),
}

fn tag(kind: Kind, payload: Payload) -> u8 {
    match (kind, payload) {
        (_, Payload::Unit) => 0,
        (Kind::Enum, Payload::Compound(_)) => 2,
        _ => 1,
    }
}

fn root(layout: Layout) -> KeyPath {
    KeyPath::new().push(match layout {
        Layout::Root => "root",
        Layout::Path => "path",
    })
}

fn variant(base: &KeyPath, kind: Kind, tag: u8) -> KeyPath {
    match kind {
        Kind::Enum => base.push_interned(tag),
        Kind::Option => base.push(if tag == 0 { "none" } else { "some" }),
    }
}

async fn resource(store: &mut Store<Runtime>) -> Result<u32> {
    Ok(store
        .data()
        .table
        .lock()
        .await
        .push(ProcStorage { contract_id: 1 })?
        .rep())
}

async fn read_tag(
    store: &mut Store<Runtime>,
    rep: u32,
    layout: Layout,
    kind: Kind,
) -> Result<Option<u64>> {
    let base = root(layout);
    match layout {
        Layout::Root => {
            host(store, async |accessor| {
                <Runtime as StorageHost<Runtime>>::get_u64(
                    accessor,
                    Resource::new_borrow(rep),
                    base.to_vec(),
                )
                .await
            })
            .await
        }
        Layout::Path => {
            let cursor = host(store, async |accessor| {
                <Runtime as StorageHost<Runtime>>::get_keys(
                    accessor,
                    Resource::new_borrow(rep),
                    base.to_vec(),
                    None,
                    None,
                    false,
                )
                .await
            })
            .await?;
            let result = host(store, async |accessor| {
                <Runtime as KeysHost<Runtime>>::next(accessor, Resource::new_borrow(cursor.rep()))
                    .await
            })
            .await;
            store.data().table.lock().await.delete(cursor)?;
            let Some(element) = result? else {
                return Ok(None);
            };
            let count = if matches!(kind, Kind::Enum) { 3 } else { 2 };
            for tag in 0..count {
                if element == variant(&KeyPath::new(), kind, tag).as_ref() {
                    return Ok(Some(u64::from(tag)));
                }
            }
            anyhow::bail!("unexpected variant element {element:?}")
        }
    }
}

async fn replace(
    store: &mut Store<Runtime>,
    rep: u32,
    layout: Layout,
    kind: Kind,
    payload: Payload,
) -> Result<()> {
    let base = root(layout);
    let tag = tag(kind, payload);
    let child = variant(&base, kind, tag);
    host(store, async |accessor| {
        <Runtime as StorageHost<Runtime>>::delete(
            accessor,
            Resource::new_borrow(rep),
            base.to_vec(),
        )
        .await?;
        match layout {
            Layout::Root => {
                <Runtime as StorageHost<Runtime>>::set_u64(
                    accessor,
                    Resource::new_borrow(rep),
                    base.to_vec(),
                    u64::from(tag),
                )
                .await?
            }
            Layout::Path if !matches!(payload, Payload::Scalar) => {
                // Keep compound presence even after its last descendant is removed.
                <Runtime as StorageHost<Runtime>>::set_void(
                    accessor,
                    Resource::new_borrow(rep),
                    child.to_vec(),
                )
                .await?;
            }
            Layout::Path => {}
        }
        match payload {
            Payload::Unit => {}
            Payload::Scalar => {
                <Runtime as StorageHost<Runtime>>::set_u64(
                    accessor,
                    Resource::new_borrow(rep),
                    child.to_vec(),
                    42,
                )
                .await?
            }
            Payload::Compound(count) => {
                for key in 0..count {
                    let path = child.push_interned(0).push_element(&key);
                    <Runtime as StorageHost<Runtime>>::set_u64(
                        accessor,
                        Resource::new_borrow(rep),
                        path.to_vec(),
                        key,
                    )
                    .await?;
                }
            }
        }
        Ok(())
    })
    .await
}

async fn block(runtime: &mut Runtime, height: u64) -> Result<()> {
    runtime
        .storage
        .conn
        .execute(
            "INSERT INTO blocks VALUES (?, ?, 1)",
            params![height, format!("variant-{height}")],
        )
        .await?;
    runtime.storage.height = height;
    Ok(())
}

async fn footprint(conn: &Connection, layout: Layout) -> Result<(u64, u64)> {
    let base = root(layout);
    let row = conn.query(
        "SELECT count(*), coalesce(sum(length(path) + size), 0) FROM current_contract_state WHERE contract_id = 1 AND path >= ? AND path < ?",
        params![base.to_vec(), subtree_end(&base)],
    ).await?.next().await?.context("footprint")?;
    Ok((row.get(0)?, row.get(1)?))
}

// Lower-level comparison: one bounded index seek can return only the tag bytes.
// No new host API or fuel price is implied by this SQL-only timing.
async fn direct_path_tag(conn: &Connection, kind: Kind) -> Result<Option<Vec<u8>>> {
    let base = root(Layout::Path);
    let width = variant(&KeyPath::new(), kind, 0).len();
    let mut rows = conn.query(
        "SELECT substr(path, ?1, ?2), length(path) FROM current_contract_state WHERE contract_id = 1 AND path > ?3 AND path < ?4 ORDER BY path LIMIT 1",
        params![(base.len() + 1) as u64, width as u64, base.to_vec(), subtree_end(&base)],
    ).await?;
    let Some(row) = rows.next().await? else {
        return Ok(None);
    };
    // Every variant has a scalar or presence marker at the child root. Reject
    // longer elements instead of accepting a truncated string tag with an escaped NUL.
    ensure!(
        row.get::<u64>(1)? == (base.len() + width) as u64,
        "missing variant-root value"
    );
    Ok(Some(row.get(0)?))
}

async fn measure_read(
    store: &mut Store<Runtime>,
    rep: u32,
    layout: Layout,
    kind: Kind,
) -> Result<(f64, u64)> {
    let mut samples = Vec::new();
    let mut expected = None;
    let mut fuel = 0;
    for trial in 0..11 {
        let start = Instant::now();
        for _ in 0..20 {
            store.set_fuel(BUDGET)?;
            let value = black_box(read_tag(store, rep, layout, kind).await?);
            if let Some(previous) = expected {
                ensure!(value == previous);
            }
            expected = Some(value);
            let spent = BUDGET - store.get_fuel()?;
            if fuel != 0 {
                ensure!(spent == fuel);
            }
            fuel = spent;
        }
        if trial >= 2 {
            samples.push(start.elapsed().as_secs_f64() * 1e6 / 20.0);
        }
    }
    samples.sort_by(f64::total_cmp);
    Ok((samples[samples.len() / 2], fuel))
}

async fn measure_sql(runtime: &Runtime, layout: Layout, kind: Kind) -> Result<f64> {
    let mut samples = Vec::new();
    for trial in 0..11 {
        let start = Instant::now();
        for _ in 0..20 {
            let _ = black_box(match layout {
                Layout::Root => runtime.storage.get(8, 1, &root(layout)).await?,
                Layout::Path => direct_path_tag(&runtime.storage.conn, kind).await?,
            });
        }
        if trial >= 2 {
            samples.push(start.elapsed().as_secs_f64() * 1e6 / 20.0);
        }
    }
    samples.sort_by(f64::total_cmp);
    Ok(samples[samples.len() / 2])
}

#[tokio::test]
async fn path_variant_prototype_preserves_presence_replacement_and_rollback() -> Result<()> {
    for kind in [Kind::Enum, Kind::Option] {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        let conn = runtime.storage.conn.clone();
        let mut store = runtime.make_store(BUDGET)?;
        let rep = resource(&mut store).await?;
        for layout in [Layout::Root, Layout::Path] {
            ensure!(read_tag(&mut store, rep, layout, kind).await?.is_none());
            replace(&mut store, rep, layout, kind, Payload::Compound(4)).await?;
            let children =
                variant(&root(layout), kind, tag(kind, Payload::Compound(4))).push_interned(0);
            host(&mut store, async |accessor| {
                <Runtime as StorageHost<Runtime>>::delete(
                    accessor,
                    Resource::new_borrow(rep),
                    children.to_vec(),
                )
                .await
            })
            .await?;
            ensure!(footprint(&conn, layout).await?.0 == 1);
            ensure!(
                read_tag(&mut store, rep, layout, kind).await?
                    == Some(u64::from(tag(kind, Payload::Compound(0))))
            );
            runtime.storage.savepoint().await?;
            replace(&mut store, rep, layout, kind, Payload::Unit).await?;
            ensure!(read_tag(&mut store, rep, layout, kind).await? == Some(0));
            runtime.storage.rollback().await?;
            ensure!(read_tag(&mut store, rep, layout, kind).await? != Some(0));
        }
        // Key-only selection must not read history or copy a payload.
        conn.authorizer(Some(Arc::new(|context| match context.action {
            AuthAction::Read {
                table_name: "contract_state",
                ..
            } => Authorization::Deny,
            _ => Authorization::Allow,
        })))?;
        let via_host = read_tag(&mut store, rep, Layout::Path, kind).await;
        let via_sql = direct_path_tag(&conn, kind).await;
        conn.authorizer(None)?;
        ensure!(via_host? == Some(u64::from(tag(kind, Payload::Compound(0)))));
        ensure!(
            via_sql?
                == Some(variant(&KeyPath::new(), kind, tag(kind, Payload::Compound(0))).to_vec())
        );
        block(&mut runtime, 2).await?;
        let mut store = runtime.make_store(BUDGET)?;
        let rep = resource(&mut store).await?;
        for layout in [Layout::Root, Layout::Path] {
            replace(&mut store, rep, layout, kind, Payload::Scalar).await?;
            ensure!(read_tag(&mut store, rep, layout, kind).await? == Some(1));
            ensure!(
                footprint(&conn, layout).await?.0
                    == if matches!(layout, Layout::Root) { 2 } else { 1 }
            );
            let value = host(&mut store, async |accessor| {
                <Runtime as StorageHost<Runtime>>::get_u64(
                    accessor,
                    Resource::new_borrow(rep),
                    variant(&root(layout), kind, 1).to_vec(),
                )
                .await
            })
            .await?;
            ensure!(value == Some(42));
        }
        runtime.storage.rollback_with_footprint(1).await?;
        for layout in [Layout::Root, Layout::Path] {
            ensure!(
                read_tag(&mut store, rep, layout, kind).await?
                    == Some(u64::from(tag(kind, Payload::Compound(0))))
            );
            ensure!(footprint(&conn, layout).await?.0 == 1);
        }
        runtime.storage.prune(0, 1).await?;
        for layout in [Layout::Root, Layout::Path] {
            ensure!(
                read_tag(&mut store, rep, layout, kind).await?
                    == Some(u64::from(tag(kind, Payload::Compound(0))))
            );
        }
    }
    Ok(())
}

#[tokio::test]
#[ignore = "compare variant layouts through real host calls; run in release mode"]
async fn benchmark_variant_layouts() -> Result<()> {
    for kind in [Kind::Enum, Kind::Option] {
        let (mut runtime, _dir, _name) = test_runtime().await?;
        let mut store = runtime.make_store(BUDGET)?;
        let rep = resource(&mut store).await?;
        for payload in [
            Payload::Unit,
            Payload::Scalar,
            Payload::Compound(0),
            Payload::Compound(4),
            Payload::Compound(128),
        ] {
            for layout in [Layout::Root, Layout::Path] {
                store.set_fuel(BUDGET)?;
                replace(&mut store, rep, layout, kind, payload).await?;
                let (rows, bytes) = footprint(&runtime.storage.conn, layout).await?;
                let (read_us, read_fuel) = measure_read(&mut store, rep, layout, kind).await?;
                let sql_us = measure_sql(&runtime, layout, kind).await?;
                let mut samples = Vec::new();
                let mut write_fuel = None;
                for trial in 0..11 {
                    runtime.storage.savepoint().await?;
                    store.set_fuel(BUDGET)?;
                    let start = Instant::now();
                    replace(&mut store, rep, layout, kind, payload).await?;
                    let elapsed = start.elapsed().as_secs_f64() * 1e6;
                    let spent = BUDGET - store.get_fuel()?;
                    if let Some(expected) = write_fuel {
                        ensure!(spent == expected);
                    }
                    write_fuel = Some(spent);
                    if trial >= 2 {
                        samples.push(elapsed);
                    }
                    runtime.storage.rollback().await?;
                }
                samples.sort_by(f64::total_cmp);
                println!(
                    "VARIANT_LAYOUT {}",
                    json!({"kind":format!("{kind:?}"),"layout":format!("{layout:?}"),"payload":format!("{payload:?}"),"rows":rows,"logical_bytes":bytes,"read_us":read_us,"read_fuel":read_fuel,"sql_us":sql_us,"replace_us":samples[samples.len()/2],"replace_fuel":write_fuel})
                );
            }
        }
        // Grow retained payload history without changing the live shape or tags.
        let conn = runtime.storage.conn.clone();
        let payload_roots = [Layout::Root, Layout::Path].map(|layout| {
            variant(&root(layout), kind, tag(kind, Payload::Compound(128))).push_interned(0)
        });
        let leaves = runtime
            .storage
            .find_live_subtree(1, &[])
            .await?
            .try_collect::<Vec<_>>()
            .await?;
        let leaves: Vec<_> = leaves
            .into_iter()
            .filter(|row| {
                payload_roots
                    .iter()
                    .any(|prefix| row.path.starts_with(prefix))
            })
            .collect();
        ensure!(
            leaves.len() == 256,
            "history fixture must version every payload leaf"
        );
        let insert = conn.prepare("INSERT INTO contract_state (contract_id,height,path,size,value,deleted) VALUES (1, ?, ?, ?, ?, 0)").await?;
        let value = serialize(&42u64)?;
        let mut previous = 1;
        let mut expected_fuel = [None, None];
        for depth in [1, 10, 100, 1000] {
            conn.execute_batch("BEGIN").await?;
            for height in previous + 1..=depth {
                block(&mut runtime, height).await?;
                for row in &leaves {
                    insert
                        .execute(params![
                            height,
                            row.path.clone(),
                            value.len() as u64,
                            value.clone()
                        ])
                        .await?;
                    insert.reset();
                }
            }
            conn.execute_batch("COMMIT").await?;
            previous = depth;
            for (index, layout) in [Layout::Root, Layout::Path].into_iter().enumerate() {
                ensure!(
                    read_tag(&mut store, rep, layout, kind).await?
                        == Some(u64::from(tag(kind, Payload::Compound(128))))
                );
                let (us, fuel) = measure_read(&mut store, rep, layout, kind).await?;
                if let Some(expected) = expected_fuel[index] {
                    ensure!(fuel == expected, "history changed tag fuel");
                }
                expected_fuel[index] = Some(fuel);
                let sql_us = measure_sql(&runtime, layout, kind).await?;
                println!(
                    "VARIANT_HISTORY {}",
                    json!({"kind":format!("{kind:?}"),"layout":format!("{layout:?}"),"versions":depth,"read_us":us,"fuel":fuel,"sql_us":sql_us})
                );
            }
        }
        runtime.storage.prune(0, 1000).await?;
        conn.execute_batch("VACUUM").await?;
        for (index, layout) in [Layout::Root, Layout::Path].into_iter().enumerate() {
            ensure!(
                read_tag(&mut store, rep, layout, kind).await?
                    == Some(u64::from(tag(kind, Payload::Compound(128))))
            );
            let (us, fuel) = measure_read(&mut store, rep, layout, kind).await?;
            ensure!(
                Some(fuel) == expected_fuel[index],
                "pruning changed tag fuel"
            );
            println!(
                "VARIANT_PRUNED {}",
                json!({"kind":format!("{kind:?}"),"layout":format!("{layout:?}"),"read_us":us,"fuel":fuel})
            );
        }
    }
    Ok(())
}
