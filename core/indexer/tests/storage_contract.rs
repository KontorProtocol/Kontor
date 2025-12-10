use ff::PrimeField;
use kontor_crypto::api::prepare_file;
use testlib::*;
use tracing::info;

interface!(name = "storage", path = "../native-contracts/storage/wit");

/// Get the native storage contract address (published at height 0)
fn native_storage_address() -> ContractAddress {
    ContractAddress {
        name: "storage".to_string(),
        height: 0,
        tx_index: 0,
    }
}

/// Prepare a fake file using kontor-crypto and return metadata for the storage contract.
/// This generates a real Merkle tree root from the given data.
fn prepare_test_file(file_id: &str, data: &[u8]) -> storage::FileMetadata {
    let (_prepared, crypto_meta) = prepare_file(data, file_id).expect("prepare_file failed");
    let root_bytes = crypto_meta.root.to_repr();
    let root_hex = hex::encode(root_bytes);
    let depth = crypto_meta.depth() as i64;
    storage::FileMetadata {
        file_id: crypto_meta.file_id,
        root: root_hex,
        tree_depth: depth,
    }
}

async fn run_test_create_agreement_happy_path(runtime: &mut Runtime) -> Result<()> {
    info!("test_create_agreement_happy_path");
    let owner = runtime.identity().await?;
    let storage_addr = native_storage_address();

    // Prepare a real file using kontor-crypto
    // Note: file_id is derived by kontor-crypto from the content, not from the filename
    let test_data = b"Hello, this is test file content for the storage protocol!";
    let metadata = prepare_test_file("test-file-001", test_data);
    let expected_file_id = metadata.file_id.clone();
    let expected_root = metadata.root.clone();
    let expected_depth = metadata.tree_depth;

    let result = storage::create_agreement(runtime, &storage_addr, &owner, metadata).await?;
    assert!(
        result.is_ok(),
        "create_agreement should succeed: {:?}",
        result
    );
    let create_result = result.unwrap();
    assert_eq!(create_result.agreement_id, expected_file_id);

    // Verify agreement can be retrieved using the generated file_id
    let agreement = storage::get_agreement(runtime, &storage_addr, &expected_file_id).await?;
    assert!(agreement.is_some(), "agreement should exist");
    let agreement = agreement.unwrap();
    assert_eq!(agreement.file_id, expected_file_id);
    assert_eq!(agreement.root, expected_root);
    assert_eq!(agreement.tree_depth, expected_depth);
    assert!(!agreement.active); // starts inactive until nodes join

    // Verify agreement count
    let count = storage::agreement_count(runtime, &storage_addr).await?;
    assert_eq!(count, 1);

    Ok(())
}

async fn run_test_duplicate_rejection(runtime: &mut Runtime) -> Result<()> {
    info!("test_duplicate_rejection");
    let owner = runtime.identity().await?;
    let storage_addr = native_storage_address();

    // Prepare a real file
    let test_data = b"Duplicate test file content";
    let metadata = prepare_test_file("duplicate-file", test_data);

    // First creation should succeed
    let result =
        storage::create_agreement(runtime, &storage_addr, &owner, metadata.clone()).await?;
    assert!(result.is_ok(), "first create_agreement should succeed");

    // Second creation with same file_id should fail
    let result = storage::create_agreement(runtime, &storage_addr, &owner, metadata).await?;
    assert!(result.is_err(), "duplicate create_agreement should fail");
    let err = result.unwrap_err();
    assert!(
        err.to_string().contains("already exists"),
        "error should mention duplicate: {:?}",
        err
    );

    Ok(())
}

async fn run_test_invalid_inputs(runtime: &mut Runtime) -> Result<()> {
    info!("test_invalid_inputs");
    let owner = runtime.identity().await?;
    let storage_addr = native_storage_address();

    // Get a valid root from a real file preparation for tests that need it
    let valid_metadata = prepare_test_file("valid-file", b"some data");
    let valid_root = valid_metadata.root.clone();

    // Empty file_id
    let metadata = storage::FileMetadata {
        file_id: "".to_string(),
        root: valid_root.clone(),
        tree_depth: 10,
    };
    let result = storage::create_agreement(runtime, &storage_addr, &owner, metadata).await?;
    assert!(result.is_err(), "empty file_id should fail");

    // Invalid root (not hex)
    let metadata = storage::FileMetadata {
        file_id: "file-invalid-root".to_string(),
        root: "not-hex-data".to_string(),
        tree_depth: 10,
    };
    let result = storage::create_agreement(runtime, &storage_addr, &owner, metadata).await?;
    assert!(result.is_err(), "invalid hex root should fail");

    // Invalid root (wrong length - too short)
    let metadata = storage::FileMetadata {
        file_id: "file-short-root".to_string(),
        root: "0123456789abcdef".to_string(), // only 16 chars = 8 bytes
        tree_depth: 10,
    };
    let result = storage::create_agreement(runtime, &storage_addr, &owner, metadata).await?;
    assert!(result.is_err(), "short root should fail");

    // Invalid tree_depth (zero or negative)
    let metadata = storage::FileMetadata {
        file_id: "file-zero-depth".to_string(),
        root: valid_root,
        tree_depth: 0,
    };
    let result = storage::create_agreement(runtime, &storage_addr, &owner, metadata).await?;
    assert!(result.is_err(), "zero tree_depth should fail");

    Ok(())
}

async fn run_test_multiple_agreements(runtime: &mut Runtime) -> Result<()> {
    info!("test_multiple_agreements");
    let owner = runtime.identity().await?;
    let storage_addr = native_storage_address();

    // Store file_ids and expected depths for verification
    let mut file_ids = Vec::new();
    let mut expected_depths = Vec::new();

    // Create multiple agreements with different file content
    for i in 0..5 {
        let data = format!("File content for multi-file test {}", i);
        let metadata = prepare_test_file(&format!("multi-file-{}", i), data.as_bytes());
        file_ids.push(metadata.file_id.clone());
        expected_depths.push(metadata.tree_depth);

        let result = storage::create_agreement(runtime, &storage_addr, &owner, metadata).await?;
        assert!(result.is_ok(), "create_agreement {} should succeed", i);
    }

    // Verify all agreements exist using their actual file_ids
    for i in 0..5 {
        let agreement = storage::get_agreement(runtime, &storage_addr, &file_ids[i]).await?;
        assert!(agreement.is_some(), "agreement {} should exist", i);
        let agreement = agreement.unwrap();
        assert_eq!(agreement.tree_depth, expected_depths[i]);
    }

    // Verify count
    let count = storage::agreement_count(runtime, &storage_addr).await?;
    assert_eq!(count, 5);

    Ok(())
}

async fn run_test_get_nonexistent_agreement(runtime: &mut Runtime) -> Result<()> {
    info!("test_get_nonexistent_agreement");
    let storage_addr = native_storage_address();

    let agreement = storage::get_agreement(runtime, &storage_addr, "does-not-exist").await?;
    assert!(
        agreement.is_none(),
        "nonexistent agreement should return None"
    );

    Ok(())
}

#[testlib::test(contracts_dir = "native-contracts")]
async fn test_create_agreement_happy_path() -> Result<()> {
    run_test_create_agreement_happy_path(runtime).await
}

#[testlib::test(contracts_dir = "native-contracts")]
async fn test_duplicate_rejection() -> Result<()> {
    run_test_duplicate_rejection(runtime).await
}

#[testlib::test(contracts_dir = "native-contracts")]
async fn test_invalid_inputs() -> Result<()> {
    run_test_invalid_inputs(runtime).await
}

#[testlib::test(contracts_dir = "native-contracts")]
async fn test_multiple_agreements() -> Result<()> {
    run_test_multiple_agreements(runtime).await
}

#[testlib::test(contracts_dir = "native-contracts")]
async fn test_get_nonexistent_agreement() -> Result<()> {
    run_test_get_nonexistent_agreement(runtime).await
}
