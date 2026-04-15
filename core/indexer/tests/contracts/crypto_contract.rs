use testlib::*;

interface!(name = "crypto", path = "../../test-contracts/crypto/wit");

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_crypto_contract() -> Result<()> {
    let alice = runtime.identity().await?;
    let crypto = runtime.publish(&alice, "crypto").await?;

    // Views — no consensus needed
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

    // set_hash is a mutation
    let expected_hash = vec![
        44, 38, 180, 107, 104, 255, 198, 143, 249, 155, 69, 60, 29, 48, 65, 52, 19, 66, 45, 112,
        100, 131, 191, 160, 249, 138, 94, 136, 98, 102, 231, 174,
    ];
    let result = crypto::set_hash(runtime, &crypto, &alice, "foo").await?;
    assert_eq!(result, expected_hash);
    let result = crypto::get_hash(runtime, &crypto).await?;
    assert_eq!(result, Some(expected_hash));

    // generate_id: sequential (second depends on first's state change)
    let id = crypto::generate_id(runtime, &crypto, &alice).await?;
    assert_eq!(id.len(), 16);

    let next_id = crypto::generate_id(runtime, &crypto, &alice).await?;
    assert_eq!(next_id.len(), 16);
    assert_ne!(id, next_id);

    Ok(())
}
