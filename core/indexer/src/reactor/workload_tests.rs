use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use bitcoin::Network;
use libsql::{Builder, Connection, params};
use sha2::{Digest, Sha256};
use tempfile::{NamedTempFile, TempDir};

use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{ComponentCache, Decimal, Runtime, Storage};
use crate::test_utils::{open_test_db, test_runtime};

mod smoke;
mod storage;
mod validators;

struct Snapshot {
    path: PathBuf,
    sha256: String,
}

fn hash_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0; 64 * 1024];
    loop {
        let length = file.read(&mut buffer)?;
        if length == 0 {
            break;
        }
        digest.update(&buffer[..length]);
    }
    Ok(hex::encode(digest.finalize()))
}

impl Snapshot {
    async fn export(conn: &Connection, destination: &Path) -> Result<Self> {
        ensure!(!destination.exists(), "snapshot destination already exists");
        let parent = destination.parent().context("snapshot has no parent")?;
        let staged = NamedTempFile::new_in(parent)?;
        let name = staged.path().to_str().context("non-UTF-8 snapshot path")?;
        // VACUUM INTO includes committed WAL pages and all schema/state tables.
        // Staging keeps a failed export from reserving the frozen fixture path.
        conn.execute("VACUUM INTO ?", params![name]).await?;
        staged.as_file().sync_all()?;
        let sha256 = hash_file(staged.path())?;
        staged.persist_noclobber(destination)?;
        Ok(Self {
            path: destination.to_path_buf(),
            sha256,
        })
    }

    fn copy_to(&self, destination: &Path) -> Result<()> {
        let mut source = File::open(&self.path)?;
        let mut output = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(destination)?;
        let result = (|| -> Result<()> {
            let mut digest = Sha256::new();
            let mut buffer = [0; 64 * 1024];
            loop {
                let length = source.read(&mut buffer)?;
                if length == 0 {
                    break;
                }
                digest.update(&buffer[..length]);
                output.write_all(&buffer[..length])?;
            }
            ensure!(
                hex::encode(digest.finalize()) == self.sha256,
                "snapshot digest changed"
            );
            output.sync_all()?;
            Ok(())
        })();
        drop(output);
        if result.is_err() {
            fs::remove_file(destination).context("remove failed snapshot copy")?;
        }
        result
    }
}

async fn read_marker(conn: &Connection) -> Result<String> {
    let mut rows = conn
        .query("SELECT value FROM marker WHERE id = 1", ())
        .await?;
    Ok(rows.next().await?.context("missing marker")?.get(0)?)
}

#[tokio::test]
async fn workload_snapshot_copies_include_wal_and_restore_independently() -> Result<()> {
    let dir = TempDir::new()?;
    let db = Builder::new_local(dir.path().join("source.db"))
        .build()
        .await?;
    let conn = db.connect()?;
    conn.execute_batch(
        "PRAGMA journal_mode=WAL;
         PRAGMA wal_autocheckpoint=0;
         CREATE TABLE marker (id INTEGER PRIMARY KEY, value TEXT NOT NULL);
         INSERT INTO marker VALUES (1, 'committed WAL value');",
    )
    .await?;
    ensure!(fs::metadata(dir.path().join("source.db-wal"))?.len() > 0);
    let snapshot = Snapshot::export(&conn, &dir.path().join("snapshot.db")).await?;

    conn.execute("UPDATE marker SET value = 'later source value'", ())
        .await?;
    let first_path = dir.path().join("first.db");
    let second_path = dir.path().join("second.db");
    snapshot.copy_to(&first_path)?;
    snapshot.copy_to(&second_path)?;
    ensure!(hash_file(&first_path)? == snapshot.sha256);
    ensure!(hash_file(&second_path)? == snapshot.sha256);
    let first_db = Builder::new_local(&first_path).build().await?;
    let second_db = Builder::new_local(&second_path).build().await?;
    let first = first_db.connect()?;
    let second = second_db.connect()?;
    ensure!(read_marker(&first).await? == "committed WAL value");
    ensure!(read_marker(&second).await? == "committed WAL value");
    first
        .execute("UPDATE marker SET value = 'first trial only'", ())
        .await?;
    ensure!(read_marker(&second).await? == "committed WAL value");
    ensure!(read_marker(&conn).await? == "later source value");
    ensure!(hash_file(&snapshot.path)? == snapshot.sha256);
    ensure!(Snapshot::export(&conn, &snapshot.path).await.is_err());
    ensure!(hash_file(&snapshot.path)? == snapshot.sha256);
    ensure!(snapshot.copy_to(&first_path).is_err());
    ensure!(read_marker(&first).await? == "first trial only");
    Ok(())
}

#[tokio::test]
async fn workload_snapshot_rejects_active_transaction_and_changed_input() -> Result<()> {
    let dir = TempDir::new()?;
    let db = Builder::new_local(dir.path().join("source.db"))
        .build()
        .await?;
    let conn = db.connect()?;
    conn.execute_batch("CREATE TABLE marker (id INTEGER PRIMARY KEY, value TEXT NOT NULL);")
        .await?;
    conn.execute("BEGIN IMMEDIATE", ()).await?;
    conn.execute("INSERT INTO marker VALUES (1, 'uncommitted')", ())
        .await?;
    let rejected_path = dir.path().join("uncommitted.db");
    ensure!(Snapshot::export(&conn, &rejected_path).await.is_err());
    ensure!(!rejected_path.exists());
    ensure!(fs::read_dir(dir.path())?.all(|entry| {
        entry.is_ok_and(|entry| entry.file_name().to_string_lossy().starts_with("source.db"))
    }));
    conn.execute("ROLLBACK", ()).await?;

    let snapshot = Snapshot::export(&conn, &dir.path().join("snapshot.db")).await?;
    OpenOptions::new()
        .append(true)
        .open(&snapshot.path)?
        .write_all(b"changed")?;
    let copy_path = dir.path().join("rejected-copy.db");
    ensure!(snapshot.copy_to(&copy_path).is_err());
    ensure!(!copy_path.exists());
    Ok(())
}

#[tokio::test]
async fn workload_snapshot_reopens_native_state_without_reseeding() -> Result<()> {
    let (mut source, _source_dir, _source_name) = test_runtime().await?;
    let core = Signer::Core(Box::new(Signer::Nobody));
    token::issue_to(&mut source, &core, HolderRef::Core, Decimal::from("123")).await??;
    let supply = token::total_supply(&mut source).await?;
    let balance = token::balance(&mut source, HolderRef::Core).await?;
    let dir = TempDir::new()?;
    let snapshot =
        Snapshot::export(&source.get_storage_conn(), &dir.path().join("frozen.db")).await?;
    let mut trials = Vec::new();
    for name in ["first.db", "second.db"] {
        snapshot.copy_to(&dir.path().join(name))?;
        let (_reader, writer) = open_test_db(dir.path(), name).await?;
        let storage = Storage::builder()
            .height(1)
            .conn(writer.connection())
            .build();
        // Reopening must load the exported native artifacts and state. Calling
        // publish_native_contracts here would hide an incomplete snapshot.
        let mut runtime = Runtime::new(ComponentCache::new(), storage).await?;
        runtime.network = Network::Regtest;
        ensure!(token::total_supply(&mut runtime).await? == supply);
        ensure!(token::balance(&mut runtime, HolderRef::Core).await? == balance);
        trials.push(runtime);
    }
    token::issue_to(&mut trials[0], &core, HolderRef::Core, Decimal::from("7")).await??;
    ensure!(token::total_supply(&mut trials[0]).await? != supply);
    ensure!(token::total_supply(&mut trials[1]).await? == supply);
    ensure!(token::total_supply(&mut source).await? == supply);
    ensure!(hash_file(&snapshot.path)? == snapshot.sha256);
    Ok(())
}
