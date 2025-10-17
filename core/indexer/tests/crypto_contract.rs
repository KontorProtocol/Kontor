use testlib::*;

interface!(name = "crypto", path = "../contracts/crypto/wit",);

async fn run_test_crypto_contract(runtime: &mut Runtime) -> Result<()> {
    let alice = runtime.identity().await?;
    let crypto = runtime.publish(&alice, "crypto").await?;

    let result = crypto::hash(runtime, &crypto, "foo").await?;
    assert_eq!(
        result,
        "2c26b46b68ffc68ff99b453c1d30413413422d706483bfa0f98a5e886266e7ae"
    );

    let result = crypto::hash_with_salt(runtime, &crypto, "foo", "bar").await?;
    assert_eq!(
        result,
        "c3ab8ff13720e8ad9047dd39466b3c8974e592c2fa383d4a3960714caef0c4f2"
    );

    let result = crypto::generate_id(runtime, &crypto).await?;
    assert_eq!(
        result,
        "26eab58ebc163556b05d60d774a7cf9d726e6ebf3e8e945d9088424a3c255271"
    );

    let result = crypto::generate_id(runtime, &crypto).await?;
    assert_eq!(
        result,
        "d793e0c6d5bf864ccb0e64b1aaa6b9bc0fb02b2c64faa5b8aabb97f9f54a5b90"
    );

    Ok(())
}

#[runtime(contracts_dir = "../../contracts")]
async fn test_crypto_contract() -> Result<()> {
    run_test_crypto_contract(runtime).await
}

#[runtime(contracts_dir = "../../contracts", mode = "regtest")]
async fn test_crypto_contract_regtest() -> Result<()> {
    run_test_crypto_contract(runtime).await
}
