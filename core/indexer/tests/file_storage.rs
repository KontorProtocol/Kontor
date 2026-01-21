use testlib::*;

mod file_storage_tests;

#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_file_storage_regtest() -> Result<()> {
    file_storage_tests::native_filestorage_contract::run(runtime).await?;
    file_storage_tests::proof_verification::run(runtime).await?;
    Ok(())
}

#[ignore]
#[testlib::test(contracts_dir = "../../test-contracts", mode = "regtest")]
async fn test_file_storage_e2e_regtest() -> Result<()> {
    file_storage_tests::proof_verification_e2e::run(runtime).await
}
