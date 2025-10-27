use testlib::*;

interface!(name = "crypto", path = "../contracts/crypto/wit");

async fn run_test_crypto_contract(runtime: &mut Runtime) -> Result<(Signer, ContractAddress)> {
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

    Ok((alice, crypto))
}

#[runtime(contracts_dir = "../../contracts")]
async fn test_crypto_contract() -> Result<()> {
    let (alice, crypto) = run_test_crypto_contract(runtime).await?;

    let result = crypto::generate_id(runtime, &crypto, &alice).await?;
    assert_eq!(result, "2c34ce1df23b838c");

    let result = crypto::generate_id(runtime, &crypto, &alice).await?;
    assert_eq!(result, "19ea44be89eece0f");

    Ok(())
}

#[runtime(contracts_dir = "../../contracts", mode = "regtest")]
async fn test_crypto_contract_regtest() -> Result<()> {
    let (alice, crypto) = run_test_crypto_contract(runtime).await?;

    let id = crypto::generate_id(runtime, &crypto, &alice).await?;
    assert_eq!(id.len(), 16);

    let next_id = crypto::generate_id(runtime, &crypto, &alice).await?;
    assert_eq!(next_id.len(), 16);
    assert_ne!(id, next_id);

    Ok(())
}
