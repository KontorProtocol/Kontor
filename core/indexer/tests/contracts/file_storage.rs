use testlib::*;

#[path = "file_storage_tests/mod.rs"]
mod file_storage_tests;

// The aggregated-proof e2e is local: it seeds the host ledger directly (no
// cluster storage_conn) and verifies a live proof — no precomputed fixtures.
#[testlib::test(contracts_dir = "../../test-contracts", local_only)]
async fn test_file_storage_e2e_aggregated_proof() -> Result<()> {
    file_storage_tests::proof_verification_e2e::run(runtime).await?;
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_file_storage_regtest() -> Result<()> {
    file_storage_tests::native_filestorage_contract::run_regtest(runtime).await?;
    file_storage_tests::proof_verification::run_regtest(runtime).await?;
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only)]
async fn test_file_storage_core_signer_proof_verification() -> Result<()> {
    file_storage_tests::proof_verification::run_core_signer(runtime).await?;
    Ok(())
}
