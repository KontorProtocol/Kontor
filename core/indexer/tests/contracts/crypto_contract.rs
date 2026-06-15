use testlib::*;

interface!(name = "crypto", path = "../../test-contracts/crypto/wit");

#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_crypto_contract() -> Result<()> {
    let alice = runtime.identity().await?;
    let crypto = runtime.publish(&alice, "crypto").await?;

    // sha256(bytes) — SHA-256("foo"), as raw digest bytes.
    let expected_hash = vec![
        44, 38, 180, 107, 104, 255, 198, 143, 249, 155, 69, 60, 29, 48, 65, 52, 19, 66, 45, 112,
        100, 131, 191, 160, 249, 138, 94, 136, 98, 102, 231, 174,
    ];
    let result = crypto::sha256(runtime, &crypto, b"foo".to_vec()).await?;
    assert_eq!(result, expected_hash);

    // set_hash is a mutation; stores + returns the same digest.
    let result = crypto::set_hash(runtime, &crypto, &alice, b"foo".to_vec()).await?;
    assert_eq!(result, expected_hash);
    let result = crypto::get_hash(runtime, &crypto).await?;
    assert_eq!(result, Some(expected_hash));

    // block_entropy: a height beyond the current block has no entropy yet → none.
    let result = crypto::block_entropy(runtime, &crypto, 99_999_999).await?;
    assert_eq!(result, None);

    // generate_id: sequential (second depends on first's state change)
    let id = crypto::generate_id(runtime, &crypto, &alice).await?;
    assert_eq!(id.len(), 16);

    let next_id = crypto::generate_id(runtime, &crypto, &alice).await?;
    assert_eq!(next_id.len(), 16);
    assert_ne!(id, next_id);

    Ok(())
}
