use testlib::*;

import!(
    name = "storage_agreement",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/storage-agreement/wit",
);

fn make_metadata(file_id: String, root: Vec<u8>, depth: i64) -> storage_agreement::FileMetadata {
    storage_agreement::FileMetadata {
        file_id,
        root,
        depth,
    }
}

async fn prepare_real_metadata() -> Result<storage_agreement::FileMetadata> {
    let root: Vec<u8> = [0u8; 32].to_vec();
    let depth: i64 = 4;
    Ok(make_metadata("test_file".to_string(), root, depth))
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_storage_agreement_create_and_get() -> Result<()> {
    let signer = runtime.identity().await?;
    let metadata = prepare_real_metadata().await?;

    let created = storage_agreement::create_agreement(runtime, &signer, metadata.clone()).await??;
    assert_eq!(created.agreement_id, metadata.file_id);

    let got = storage_agreement::get_agreement(runtime, created.agreement_id.as_str()).await?;
    let got = got.expect("agreement should exist");

    assert_eq!(got.agreement_id, created.agreement_id);
    assert_eq!(got.file_id, metadata.file_id);
    assert_eq!(got.root, metadata.root);
    assert_eq!(got.depth, metadata.depth);
    assert!(!got.active);
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_storage_agreement_count_increments() -> Result<()> {
    let signer = runtime.identity().await?;

    let c0 = storage_agreement::agreement_count(runtime).await?;
    let m1 = prepare_real_metadata().await?;
    storage_agreement::create_agreement(runtime, &signer, m1).await??;
    let c1 = storage_agreement::agreement_count(runtime).await?;
    assert_eq!(c1, c0 + 1);

    let m2 = make_metadata("another_file".to_string(), vec![7u8; 32], 8);
    storage_agreement::create_agreement(runtime, &signer, m2).await??;
    let c2 = storage_agreement::agreement_count(runtime).await?;
    assert_eq!(c2, c1 + 1);

    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_storage_agreement_duplicate_fails() -> Result<()> {
    let signer = runtime.identity().await?;
    let metadata = make_metadata("dup_file".to_string(), vec![1u8; 32], 8);

    storage_agreement::create_agreement(runtime, &signer, metadata.clone()).await??;
    let err = storage_agreement::create_agreement(runtime, &signer, metadata).await?;
    assert!(matches!(err, Err(Error::Message(_))));
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_storage_agreement_invalid_root_fails() -> Result<()> {
    let signer = runtime.identity().await?;
    let metadata = make_metadata("bad_root".to_string(), vec![1u8; 31], 8);

    let err = storage_agreement::create_agreement(runtime, &signer, metadata).await?;
    assert!(matches!(err, Err(Error::Validation(_))));
    Ok(())
}
