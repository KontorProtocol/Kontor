use testlib::*;

#[path = "file_storage_tests/mod.rs"]
mod file_storage_tests;

// TODO(challenge-ledger migration): e2e + native_filestorage_contract tests are
// temporarily disabled — they call contract challenge functions removed in the
// shrink. Re-enable after rewriting them (e2e needs the get-challenges view).
// #[testlib::test(contracts_dir = "../../test-contracts")]
// async fn test_file_storage_regtest_e2e() -> Result<()> {
//     file_storage_tests::proof_verification_e2e::run(runtime).await?;
//     Ok(())
// }

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
