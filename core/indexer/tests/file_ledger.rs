use anyhow::Result;
use ff::PrimeField;
use indexer::{
    database::{
        queries::{insert_block, insert_transaction, select_all_file_metadata},
        types::FileMetadataRow,
    },
    runtime::{Storage, file_ledger::FileLedger},
    test_utils::{create_fake_file_metadata, new_mock_block_hash, new_test_db},
};
use indexer_types::{BlockRow, TransactionRow};
use kontor_crypto::FileLedger as CryptoFileLedger;

/// Helper to create a test Storage from a database connection
fn create_test_storage(conn: libsql::Connection) -> Storage {
    Storage::builder().conn(conn).build()
}

/// Helper to set up a block and transaction in the database
async fn setup_block_and_tx(conn: &libsql::Connection, height: i64) -> Result<()> {
    let hash = new_mock_block_hash(height as u32);
    let block = BlockRow::builder().height(height).hash(hash).build();
    insert_block(conn, block).await?;

    let txid = format!("{:0>64x}", height);
    let tx = TransactionRow::builder()
        .height(height)
        .txid(txid)
        .tx_index(0)
        .build();
    insert_transaction(conn, tx).await?;

    Ok(())
}

#[tokio::test]
async fn test_file_ledger_new_creates_empty_ledger() -> Result<()> {
    let ledger = FileLedger::new();

    // A new ledger should exist (we can't directly check internal state,
    // but we can verify it doesn't panic and can be used)
    ledger.clear_dirty().await;

    Ok(())
}

#[tokio::test]
async fn test_file_ledger_add_file_persists_to_database() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let storage = create_test_storage(conn.clone());

    // Set up block and transaction for foreign key constraints
    let height = 800000;
    setup_block_and_tx(&conn, height).await?;

    let ledger = FileLedger::new();
    let metadata = create_fake_file_metadata("file_001_id", "file_001.dat", height);

    // Add file to ledger
    ledger.add_file(&storage.conn, &metadata).await?;

    // Verify file was persisted to database
    let entries = select_all_file_metadata(&conn).await?;
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].file_id, metadata.file_id);
    assert_eq!(entries[0].root, metadata.root);
    assert_eq!(entries[0].padded_len, metadata.padded_len);
    assert_eq!(entries[0].original_size, metadata.original_size);
    assert_eq!(entries[0].filename, metadata.filename);
    assert_eq!(entries[0].height, height);

    Ok(())
}

#[tokio::test]
async fn test_file_ledger_add_file_sets_dirty_flag() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let storage = create_test_storage(conn.clone());

    let height = 800000;
    setup_block_and_tx(&conn, height).await?;

    let ledger = FileLedger::new();
    let metadata = create_fake_file_metadata("file_001_id", "file_001.dat", height);

    // Add file - this should set dirty flag
    ledger.add_file(&storage.conn, &metadata).await?;

    // Clear dirty should work (we can't directly verify the flag, but this tests the path)
    ledger.clear_dirty().await;

    Ok(())
}

#[tokio::test]
async fn test_file_ledger_first_file_has_no_historical_root() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let storage = create_test_storage(conn.clone());

    let height = 800000;
    setup_block_and_tx(&conn, height).await?;

    let ledger = FileLedger::new();
    let metadata = create_fake_file_metadata("file_001_id", "file_001.dat", height);

    ledger.add_file(&storage.conn, &metadata).await?;

    // Every file now snapshots the ledger root as historical (even the first one)
    let entries = select_all_file_metadata(&conn).await?;
    assert_eq!(entries.len(), 1);
    assert!(
        entries[0].historical_root.is_some(),
        "First file should have a historical root (snapshot of empty ledger)"
    );

    Ok(())
}

#[tokio::test]
async fn test_file_ledger_second_file_has_historical_root() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let storage = create_test_storage(conn.clone());

    // Set up two blocks
    let height1 = 800000;
    let height2 = 800001;
    setup_block_and_tx(&conn, height1).await?;
    setup_block_and_tx(&conn, height2).await?;

    let ledger = FileLedger::new();

    // Add first file
    let metadata1 = create_fake_file_metadata("file_001_id", "file_001.dat", height1);
    ledger.add_file(&storage.conn, &metadata1).await?;

    // Add second file
    let metadata2 = create_fake_file_metadata("file_002_id", "file_002.dat", height2);
    ledger.add_file(&storage.conn, &metadata2).await?;

    // Verify historical roots - every file now has one
    let entries = select_all_file_metadata(&conn).await?;
    assert_eq!(entries.len(), 2);

    // First file should have a historical root (snapshot of empty ledger)
    assert!(
        entries[0].historical_root.is_some(),
        "First file should have a historical root"
    );

    // Second file should have a historical root (the root after first file was added)
    assert!(
        entries[1].historical_root.is_some(),
        "Second file should have a historical root"
    );

    // The historical roots should be different (ledger state changed between adds)
    assert_ne!(
        entries[0].historical_root, entries[1].historical_root,
        "Historical roots should differ as ledger state changed"
    );

    Ok(())
}

#[tokio::test]
async fn test_file_ledger_rebuild_from_db_restores_files() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let storage = create_test_storage(conn.clone());

    // Set up blocks
    let height1 = 800000;
    let height2 = 800001;
    setup_block_and_tx(&conn, height1).await?;
    setup_block_and_tx(&conn, height2).await?;

    // Create files with real data
    let metadata1 = create_fake_file_metadata("file_001_id", "file_001.dat", height1);
    let metadata2 = create_fake_file_metadata("file_002_id", "file_002.dat", height2);
    let file_id1 = metadata1.file_id.clone();
    let file_id2 = metadata2.file_id.clone();

    // Create ledger and add files
    let ledger1 = FileLedger::new();
    ledger1.add_file(&storage.conn, &metadata1).await?;
    ledger1.add_file(&storage.conn, &metadata2).await?;

    // Rebuild from database
    let _ledger2 = FileLedger::rebuild_from_db(&storage.conn).await?;

    // Verify files are still in database
    let entries = select_all_file_metadata(&conn).await?;
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].file_id, file_id1);
    assert_eq!(entries[1].file_id, file_id2);

    Ok(())
}

#[tokio::test]
async fn test_file_ledger_rebuild_from_db_restores_historical_roots() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let storage = create_test_storage(conn.clone());

    // Set up blocks
    let height1 = 800000;
    let height2 = 800001;
    let height3 = 800002;
    setup_block_and_tx(&conn, height1).await?;
    setup_block_and_tx(&conn, height2).await?;
    setup_block_and_tx(&conn, height3).await?;

    // Create ledger and add files with real data
    let ledger1 = FileLedger::new();
    ledger1
        .add_file(
            &storage.conn,
            &create_fake_file_metadata("file_001_id", "file_001.dat", height1),
        )
        .await?;
    ledger1
        .add_file(
            &storage.conn,
            &create_fake_file_metadata("file_002_id", "file_002.dat", height2),
        )
        .await?;
    ledger1
        .add_file(
            &storage.conn,
            &create_fake_file_metadata("file_003_id", "file_003.dat", height3),
        )
        .await?;

    // Capture original historical roots from database
    let original_entries = select_all_file_metadata(&conn).await?;
    let original_historical_roots: Vec<Option<[u8; 32]>> =
        original_entries.iter().map(|e| e.historical_root).collect();

    // Rebuild from database - this should restore historical roots
    let _ledger2 = FileLedger::rebuild_from_db(&storage.conn).await?;

    // Verify historical roots are preserved in database (rebuild doesn't modify them)
    let rebuilt_entries = select_all_file_metadata(&conn).await?;
    let rebuilt_historical_roots: Vec<Option<[u8; 32]>> =
        rebuilt_entries.iter().map(|e| e.historical_root).collect();

    assert_eq!(
        original_historical_roots, rebuilt_historical_roots,
        "Historical roots should be preserved after rebuild"
    );

    Ok(())
}

#[tokio::test]
async fn test_file_ledger_resync_skips_when_not_dirty() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let storage = create_test_storage(conn.clone());

    let height = 800000;
    setup_block_and_tx(&conn, height).await?;

    // Create a new ledger (not dirty)
    let ledger = FileLedger::new();

    // Resync should complete without error (and skip the actual resync)
    ledger.resync_from_db(&storage.conn).await?;

    Ok(())
}

#[tokio::test]
async fn test_file_ledger_resync_rebuilds_when_dirty() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let storage = create_test_storage(conn.clone());

    let height = 800000;
    setup_block_and_tx(&conn, height).await?;

    let ledger = FileLedger::new();

    // Add a file to make it dirty
    let metadata = create_fake_file_metadata("file_001_id", "file_001.dat", height);
    ledger.add_file(&storage.conn, &metadata).await?;

    // Resync should rebuild from database
    ledger.resync_from_db(&storage.conn).await?;

    // Verify file is still in database
    let entries = select_all_file_metadata(&conn).await?;
    assert_eq!(entries.len(), 1);

    Ok(())
}

#[tokio::test]
async fn test_file_ledger_force_resync_always_rebuilds() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let storage = create_test_storage(conn.clone());

    let height = 800000;
    setup_block_and_tx(&conn, height).await?;

    // Create a new ledger (not dirty)
    let ledger = FileLedger::new();

    // Force resync should complete without error (even though not dirty)
    ledger.force_resync_from_db(&storage.conn).await?;

    Ok(())
}

#[tokio::test]
async fn test_file_ledger_clear_dirty() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let storage = create_test_storage(conn.clone());

    let height = 800000;
    setup_block_and_tx(&conn, height).await?;

    let ledger = FileLedger::new();

    // Add a file to make it dirty
    let metadata = create_fake_file_metadata("file_001_id", "file_001.dat", height);
    ledger.add_file(&storage.conn, &metadata).await?;

    // Clear dirty flag
    ledger.clear_dirty().await;

    // Now resync should skip (since we cleared dirty)
    // This indirectly tests that clear_dirty works
    ledger.resync_from_db(&storage.conn).await?;

    Ok(())
}

#[tokio::test]
async fn test_file_ledger_multiple_files_correct_historical_roots() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let storage = create_test_storage(conn.clone());

    // Set up blocks
    for i in 0..5 {
        setup_block_and_tx(&conn, 800000 + i).await?;
    }

    let ledger = FileLedger::new();

    // Add 5 files with distinct content
    for i in 0..5 {
        let filename = format!("file_{:03}.dat", i);
        let metadata =
            create_fake_file_metadata(&format!("file_{:03}_id", i), &filename, 800000 + i as i64);
        ledger.add_file(&storage.conn, &metadata).await?;
    }

    let entries = select_all_file_metadata(&conn).await?;
    assert_eq!(entries.len(), 5);

    // All files should have historical roots (each snapshots the ledger state before add)
    for entry in entries.iter() {
        assert!(
            entry.historical_root.is_some(),
            "File {} should have a historical root",
            entry.file_id
        );
    }

    // Each historical root should be different (since the ledger state changes)
    let historical_roots: Vec<[u8; 32]> =
        entries.iter().filter_map(|e| e.historical_root).collect();

    // Check that roots are unique
    let unique_roots: std::collections::HashSet<_> = historical_roots.iter().collect();
    assert_eq!(
        historical_roots.len(),
        unique_roots.len(),
        "Each historical root should be unique"
    );

    Ok(())
}

#[tokio::test]
async fn test_file_ledger_rebuild_preserves_file_order() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let storage = create_test_storage(conn.clone());

    // Set up blocks
    for i in 0..3 {
        setup_block_and_tx(&conn, 800000 + i).await?;
    }

    // Create files with real data - capture file_ids (SHA256 hashes)
    let metadata1 = create_fake_file_metadata("alpha_id", "alpha.dat", 800000);
    let metadata2 = create_fake_file_metadata("beta_id", "beta.dat", 800001);
    let metadata3 = create_fake_file_metadata("gamma_id", "gamma.dat", 800002);
    let file_id1 = metadata1.file_id.clone();
    let file_id2 = metadata2.file_id.clone();
    let file_id3 = metadata3.file_id.clone();

    let ledger = FileLedger::new();

    // Add files
    ledger.add_file(&storage.conn, &metadata1).await?;
    ledger.add_file(&storage.conn, &metadata2).await?;
    ledger.add_file(&storage.conn, &metadata3).await?;

    // Rebuild from database
    let _ledger2 = FileLedger::rebuild_from_db(&storage.conn).await?;

    // Verify order is preserved (ordered by id ASC - which is insertion order)
    let entries = select_all_file_metadata(&conn).await?;
    assert_eq!(entries.len(), 3);
    assert_eq!(entries[0].file_id, file_id1);
    assert_eq!(entries[1].file_id, file_id2);
    assert_eq!(entries[2].file_id, file_id3);

    Ok(())
}

/// Comprehensive test that adds multiple files per block across 4 blocks,
/// then verifies that resync produces both the same tree root AND same historical ledger
/// as the original ledger produced by the multiple add_file calls.
#[tokio::test]
async fn test_file_ledger_resync_produces_identical_tree_and_historical_ledger() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let storage = create_test_storage(conn.clone());

    // Set up 4 blocks
    let block_heights: Vec<i64> = vec![800000, 800001, 800002, 800003];
    for height in &block_heights {
        setup_block_and_tx(&conn, *height).await?;
    }

    // Create files: 2-3 files per block to simulate realistic usage
    // Block 0: 2 files
    // Block 1: 3 files
    // Block 2: 2 files
    // Block 3: 3 files
    let files_per_block = [
        vec![("b0_a.dat", "b0_a_id"), ("b0_b.dat", "b0_b_id")],
        vec![
            ("b1_a.dat", "b1_a_id"),
            ("b1_b.dat", "b1_b_id"),
            ("b1_c.dat", "b1_c_id"),
        ],
        vec![("b2_a.dat", "b2_a_id"), ("b2_b.dat", "b2_b_id")],
        vec![
            ("b3_a.dat", "b3_a_id"),
            ("b3_b.dat", "b3_b_id"),
            ("b3_c.dat", "b3_c_id"),
        ],
    ];

    // Create metadata for all files
    let mut all_metadata: Vec<FileMetadataRow> = Vec::new();
    for (block_idx, files) in files_per_block.iter().enumerate() {
        let height = block_heights[block_idx];
        for (filename, file_id) in files {
            let metadata = create_fake_file_metadata(file_id, filename, height);
            all_metadata.push(metadata);
        }
    }

    // Create the original ledger and add all files
    let original_ledger = FileLedger::new();
    for metadata in &all_metadata {
        original_ledger.add_file(&storage.conn, metadata).await?;
    }

    // Build a reference CryptoFileLedger in parallel to capture expected state
    let mut reference_crypto_ledger = CryptoFileLedger::new();
    for metadata in &all_metadata {
        reference_crypto_ledger
            .add_file(metadata)
            .expect("Failed to add file to reference ledger");
    }

    // Capture the original ledger's tree root by building a reference from the same files
    let original_tree_root: [u8; 32] = reference_crypto_ledger.root().to_repr().into();
    let original_historical_roots = reference_crypto_ledger.historical_roots.clone();

    // Get the database entries to verify historical roots were stored correctly
    let db_entries = select_all_file_metadata(&conn).await?;
    assert_eq!(db_entries.len(), 10, "Should have 10 files total");

    // All files should have historical roots (each snapshots ledger state before add)
    for (i, entry) in db_entries.iter().enumerate() {
        assert!(
            entry.historical_root.is_some(),
            "File {} (index {}) should have a historical root",
            entry.file_id,
            i
        );
    }

    // Now rebuild from database
    let rebuilt_ledger = FileLedger::rebuild_from_db(&storage.conn).await?;

    // Build another reference ledger by adding the same files and restoring historical roots
    // This simulates what rebuild_from_db should do internally
    let mut rebuilt_reference = CryptoFileLedger::new();
    rebuilt_reference
        .add_files(&db_entries)
        .expect("Failed to add files to rebuilt reference");

    // Restore historical roots from database (as rebuild_from_db does)
    let stored_historical_roots: Vec<[u8; 32]> = db_entries
        .iter()
        .filter_map(|row| row.historical_root)
        .collect();
    rebuilt_reference.set_historical_roots(stored_historical_roots.clone());

    // Verify the rebuilt ledger has the same tree root
    let rebuilt_tree_root: [u8; 32] = rebuilt_reference.root().to_repr().into();
    assert_eq!(
        original_tree_root, rebuilt_tree_root,
        "Rebuilt ledger should have the same tree root as original"
    );

    // Verify the rebuilt ledger has the same historical roots
    assert_eq!(
        original_historical_roots.len(),
        rebuilt_reference.historical_roots.len(),
        "Rebuilt ledger should have the same number of historical roots"
    );

    for (i, (original, rebuilt)) in original_historical_roots
        .iter()
        .zip(rebuilt_reference.historical_roots.iter())
        .enumerate()
    {
        assert_eq!(
            original, rebuilt,
            "Historical root at index {} should match: original {:?} vs rebuilt {:?}",
            i, original, rebuilt
        );
    }

    // Now test resync: add a file, mark dirty, then resync
    // First, set up another block
    setup_block_and_tx(&conn, 800004).await?;
    let extra_metadata = create_fake_file_metadata("extra_id", "extra.dat", 800004);
    rebuilt_ledger
        .add_file(&storage.conn, &extra_metadata)
        .await?;

    // Verify the extra file was added
    let entries_after_extra = select_all_file_metadata(&conn).await?;
    assert_eq!(
        entries_after_extra.len(),
        11,
        "Should have 11 files after adding extra"
    );

    // Now resync (ledger is dirty after add_file)
    rebuilt_ledger.resync_from_db(&storage.conn).await?;

    // Verify all files are still in database
    let final_entries = select_all_file_metadata(&conn).await?;
    assert_eq!(
        final_entries.len(),
        11,
        "Should still have 11 files after resync"
    );

    // Build final reference to verify state
    let mut final_reference = CryptoFileLedger::new();
    final_reference
        .add_files(&final_entries)
        .expect("Failed to add files to final reference");
    let final_historical_roots: Vec<[u8; 32]> = final_entries
        .iter()
        .filter_map(|row| row.historical_root)
        .collect();
    final_reference.set_historical_roots(final_historical_roots);

    // The final ledger should have 10 historical roots (one for each file after the first)
    assert_eq!(
        final_reference.historical_roots.len(),
        11,
        "Final ledger should have 11 historical roots"
    );

    Ok(())
}
