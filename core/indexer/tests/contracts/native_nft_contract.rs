use indexer::test_utils::make_descriptor;
use testlib::*;

import!(
    name = "nft",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/nft/wit",
);

fn file_descriptor(file_id: &str, root_seed: u8) -> RawFileDescriptor {
    make_descriptor(
        file_id.to_string(),
        vec![root_seed; 32],
        16,
        10,
        format!("{file_id}.txt"),
    )
}

#[testlib::test(contracts_dir = "../../test-contracts", local_only)]
async fn test_native_nft_contract() -> Result<()> {
    let alice = runtime.identity().await?;
    let bob = runtime.identity().await?;
    let carol = runtime.identity().await?;
    let alice_ref: HolderRef = (&alice).into();
    let bob_ref: HolderRef = (&bob).into();
    let carol_ref: HolderRef = (&carol).into();

    // nft_id is intentionally different from file_id to demonstrate that the
    // two namespaces are decoupled: the contract picks `nft_id`, filestorage
    // picks `agreement_id` (= file_descriptor.file_id), and the NFT links to it.
    let nft_id_1 = "genesis-nft-1";
    let nft_id_2 = "second-nft";
    let description = "First NFT";
    let file_id = "nft_file_1";

    // mint OK: nft_id is independent of file_id, agreement_id is what
    // filestorage returned (= file_id).
    let minted = nft::mint(
        runtime,
        &alice,
        nft_id_1,
        description,
        file_descriptor(file_id, 1),
    )
    .await??;
    assert_eq!(minted.nft_id, nft_id_1);
    assert_eq!(minted.owner, alice_ref);
    assert_eq!(minted.agreement_id, file_id);
    assert_eq!(minted.description, description.to_string());

    // get_info on existing nft returns the full record.
    let info_before = nft::get_info(runtime, &minted.nft_id)
        .await?
        .expect("info should exist");
    assert_eq!(info_before.nft_id, nft_id_1);
    assert_eq!(info_before.owner, alice_ref);
    assert_eq!(info_before.agreement_id, file_id);
    assert_eq!(info_before.description, description.to_string());

    // get_info on missing nft returns None.
    assert_eq!(nft::get_info(runtime, "does_not_exist").await?, None);

    assert_eq!(nft::total_nfts(runtime).await?, 1);

    // Reusing the same nft_id with a fresh file_id must fail with the local
    // uniqueness error (raised before the filestorage call).
    let duplicate_nft_id = nft::mint(
        runtime,
        &alice,
        nft_id_1,
        "different file",
        file_descriptor("nft_file_other", 2),
    )
    .await?;
    assert_eq!(
        duplicate_nft_id,
        Err(Error::Message("nft_id already exists".to_string()))
    );

    // Reusing the same file_id with a fresh nft_id must fail with an error
    // delegated by filestorage (agreement already exists).
    let duplicate_file_id = nft::mint(
        runtime,
        &alice,
        nft_id_2,
        "same file",
        file_descriptor(file_id, 3),
    )
    .await?;
    assert!(matches!(duplicate_file_id, Err(Error::Message(_))));

    // nft_id validation: non-empty and bounded length.
    let empty_nft_id = nft::mint(
        runtime,
        &alice,
        "",
        "valid description",
        file_descriptor("nft_file_empty_nft_id", 4),
    )
    .await?;
    assert_eq!(
        empty_nft_id,
        Err(Error::Message("nft_id cannot be empty".to_string()))
    );

    let long_nft_id = "t".repeat(65);
    let too_long_nft_id = nft::mint(
        runtime,
        &alice,
        &long_nft_id,
        "valid description",
        file_descriptor("nft_file_long_nft_id", 5),
    )
    .await?;
    assert_eq!(
        too_long_nft_id,
        Err(Error::Message("nft_id is too long".to_string()))
    );

    // description validation: non-empty and bounded length.
    let empty_description = nft::mint(
        runtime,
        &alice,
        "unique-empty-desc",
        "",
        file_descriptor("nft_file_empty_description", 6),
    )
    .await?;
    assert_eq!(
        empty_description,
        Err(Error::Message("description cannot be empty".to_string()))
    );

    let long_description = "d".repeat(2049);
    let too_long_description = nft::mint(
        runtime,
        &alice,
        "unique-long-desc",
        &long_description,
        file_descriptor("nft_file_long_description", 7),
    )
    .await?;
    assert_eq!(
        too_long_description,
        Err(Error::Message("description is too long".to_string()))
    );

    // Empty file_id is rejected by filestorage (delegated check), even with a
    // valid, never-used nft_id.
    let empty_file_id = nft::mint(
        runtime,
        &alice,
        "unique-empty-file-id",
        "valid description",
        file_descriptor("", 8),
    )
    .await?;
    assert_eq!(
        empty_file_id,
        Err(Error::Message("file_id cannot be empty".to_string()))
    );

    // A second successful mint, owned by bob, exercises the `total_nfts`
    // counter increment on a non-empty store and gives us an nft whose owner
    // is not the default signer for later checks.
    let second_mint = nft::mint(
        runtime,
        &bob,
        nft_id_2,
        "Second NFT",
        file_descriptor("nft_file_2", 9),
    )
    .await??;
    assert_eq!(second_mint.nft_id, nft_id_2);
    assert_eq!(second_mint.owner, bob_ref);
    assert_eq!(nft::total_nfts(runtime).await?, 2);

    // transfer on a non-existent nft_id must fail before any owner check.
    let missing_nft = nft::transfer(runtime, &alice, "does_not_exist", &alice).await?;
    assert_eq!(
        missing_nft,
        Err(Error::Message("nft not found".to_string()))
    );

    // transfer to an invalid HolderRef is rejected by the host's
    // `Holder::from_ref` (delegated, not a contract-level message).
    let invalid_new_owner = nft::transfer(
        runtime,
        &alice,
        &minted.nft_id,
        HolderRef::XOnlyPubkey("not-a-valid-x-only-pubkey".to_string()),
    )
    .await?;
    assert!(matches!(invalid_new_owner, Err(Error::Validation(_))));

    // transfer must fail for non-owner.
    let unauthorized_transfer = nft::transfer(runtime, &bob, &minted.nft_id, &bob).await?;
    assert_eq!(
        unauthorized_transfer,
        Err(Error::Message("only owner can transfer".to_string()))
    );

    // owner transfer succeeds; agreement_id and description are invariant
    // across transfers.
    let transfer_ab = nft::transfer(runtime, &alice, &minted.nft_id, &bob).await??;
    assert_eq!(transfer_ab.nft_id, minted.nft_id);
    assert_eq!(transfer_ab.src, alice_ref);
    assert_eq!(transfer_ab.dst, bob_ref);
    let info_ab = nft::get_info(runtime, &minted.nft_id)
        .await?
        .expect("info should still exist");
    assert_eq!(info_ab.owner, bob_ref);
    assert_ne!(info_ab.owner, info_before.owner);
    assert_eq!(info_ab.agreement_id, file_id);
    assert_eq!(info_ab.description, description.to_string());
    // total_nfts counts mints, not transfers: still 2 after the alice→bob move.
    assert_eq!(nft::total_nfts(runtime).await?, 2);

    // chained transfer: bob -> carol.
    let transfer_bc = nft::transfer(runtime, &bob, &minted.nft_id, &carol).await??;
    assert_eq!(transfer_bc.src, bob_ref);
    assert_eq!(transfer_bc.dst, carol_ref);
    let info_bc = nft::get_info(runtime, &minted.nft_id)
        .await?
        .expect("info should still exist");
    assert_eq!(info_bc.owner, carol_ref);
    assert_eq!(info_bc.agreement_id, file_id);
    assert_eq!(info_bc.description, description.to_string());

    // alice can no longer transfer it.
    let alice_after_chain = nft::transfer(runtime, &alice, &minted.nft_id, &alice).await?;
    assert_eq!(
        alice_after_chain,
        Err(Error::Message("only owner can transfer".to_string()))
    );

    // transfer to Burner: get_info still returns the same agreement_id and
    // description, only the owner becomes Burner.
    let transfer_to_burn =
        nft::transfer(runtime, &carol, &minted.nft_id, HolderRef::Burner).await??;
    assert_eq!(transfer_to_burn.src, carol_ref);
    assert_eq!(transfer_to_burn.dst, HolderRef::Burner);
    let info_burn = nft::get_info(runtime, &minted.nft_id)
        .await?
        .expect("info should still exist");
    assert_eq!(info_burn.owner, HolderRef::Burner);
    assert_eq!(info_burn.agreement_id, file_id);
    assert_eq!(info_burn.description, description.to_string());

    Ok(())
}
