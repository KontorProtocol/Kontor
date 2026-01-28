use testlib::*;

mod file_storage_tests;

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_file_storage_regtest() -> Result<()> {
    file_storage_tests::native_filestorage_contract::run_regtest(runtime).await?;
    file_storage_tests::proof_verification::run_regtest(runtime).await?;
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_file_storage_regtest_e2e() -> Result<()> {
    file_storage_tests::proof_verification_e2e::run(runtime).await?;
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_file_storage_core_signer_lucky_hash() -> Result<()> {
    file_storage_tests::native_filestorage_contract::run_core_signer_lucky(runtime).await?;
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_file_storage_core_signer_smoke() -> Result<()> {
    file_storage_tests::native_filestorage_contract::run_core_signer_smoke(runtime).await?;
    Ok(())
}

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_file_storage_core_signer_proof_verification() -> Result<()> {
    file_storage_tests::proof_verification::run_core_signer(runtime).await?;
    Ok(())
}
