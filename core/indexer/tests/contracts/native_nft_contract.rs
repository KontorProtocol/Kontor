use indexer::test_utils::make_descriptor;
use testlib::*;

import!(
    name = "nft",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/nft/wit",
);

fn descriptor(file_id: &str, root_seed: u8) -> RawFileDescriptor {
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

    let token_name = "Genesis NFT";
    let token_description = "First NFT";
    let file_id = "nft_file_1";

    // mint OK: owner + metadata + name mapping; token_id == file_id directly
    let minted = nft::mint(
        runtime,
        &alice,
        token_name,
        token_description,
        descriptor(file_id, 1),
    )
    .await??;
    assert_eq!(minted.token_id, file_id);
    assert_eq!(minted.owner, alice_ref);
    assert_eq!(minted.metadata.name, token_name.to_string());
    assert_eq!(minted.metadata.description, token_description.to_string());

    let owner_before = nft::owner_of(runtime, &minted.token_id)
        .await?
        .expect("owner should exist");
    assert_eq!(owner_before, alice_ref);
    let metadata = nft::metadata_of(runtime, &minted.token_id)
        .await?
        .expect("metadata should exist");
    assert_eq!(metadata.name, token_name.to_string());
    assert_eq!(metadata.description, token_description.to_string());
    assert_eq!(
        nft::token_id_by_name(runtime, &metadata.name).await?,
        Some(minted.token_id.clone())
    );
    assert_eq!(nft::total_tokens(runtime).await?, 1);

    // owner_of/metadata_of on missing token returns None
    assert_eq!(nft::owner_of(runtime, "does_not_exist").await?, None);
    assert_eq!(nft::metadata_of(runtime, "does_not_exist").await?, None);

    // duplicate file_id must fail (filestorage agreement already exists)
    let duplicate_file_id = nft::mint(
        runtime,
        &alice,
        "Second NFT",
        "same file",
        descriptor(file_id, 2),
    )
    .await?;
    assert!(matches!(duplicate_file_id, Err(Error::Message(_))));

    // duplicate name must fail (global case-sensitive uniqueness)
    let duplicate_name = nft::mint(
        runtime,
        &alice,
        &metadata.name,
        "different file",
        descriptor("nft_file_2", 3),
    )
    .await?;
    assert_eq!(
        duplicate_name,
        Err(Error::Message("name already exists".to_string()))
    );

    // metadata validation: non-empty and bounded lengths
    let empty_name = nft::mint(
        runtime,
        &alice,
        "",
        "valid description",
        descriptor("nft_file_empty_name", 4),
    )
    .await?;
    assert_eq!(
        empty_name,
        Err(Error::Message("name cannot be empty".to_string()))
    );

    let empty_description = nft::mint(
        runtime,
        &alice,
        "Unique Name",
        "",
        descriptor("nft_file_empty_description", 5),
    )
    .await?;
    assert_eq!(
        empty_description,
        Err(Error::Message("description cannot be empty".to_string()))
    );

    let long_name = "n".repeat(65);
    let too_long_name = nft::mint(
        runtime,
        &alice,
        &long_name,
        "valid description",
        descriptor("nft_file_long_name", 6),
    )
    .await?;
    assert_eq!(
        too_long_name,
        Err(Error::Message("name is too long".to_string()))
    );

    let long_description = "d".repeat(2049);
    let too_long_description = nft::mint(
        runtime,
        &alice,
        "Another Unique Name",
        &long_description,
        descriptor("nft_file_long_description", 7),
    )
    .await?;
    assert_eq!(
        too_long_description,
        Err(Error::Message("description is too long".to_string()))
    );

    // empty file_id is rejected by filestorage (delegated check)
    let empty_file_id = nft::mint(
        runtime,
        &alice,
        "Empty File Id",
        "valid description",
        descriptor("", 8),
    )
    .await?;
    assert_eq!(
        empty_file_id,
        Err(Error::Message("file_id cannot be empty".to_string()))
    );

    // transfer must fail for non-owner
    let unauthorized_transfer = nft::transfer(runtime, &bob, &minted.token_id, &bob).await?;
    assert_eq!(
        unauthorized_transfer,
        Err(Error::Message("only owner can transfer".to_string()))
    );

    // owner transfer succeeds; queries stay coherent
    let transfer_ab = nft::transfer(runtime, &alice, &minted.token_id, &bob).await??;
    assert_eq!(transfer_ab.token_id, minted.token_id);
    assert_eq!(transfer_ab.src, alice_ref);
    assert_eq!(transfer_ab.dst, bob_ref);
    let owner_after = nft::owner_of(runtime, &minted.token_id)
        .await?
        .expect("owner should still exist");
    assert_ne!(owner_before, owner_after);
    assert_eq!(owner_after, bob_ref);
    assert_eq!(
        nft::metadata_of(runtime, &minted.token_id)
            .await?
            .expect("metadata should still exist")
            .name,
        token_name.to_string()
    );
    assert_eq!(
        nft::token_id_by_name(runtime, &metadata.name).await?,
        Some(minted.token_id.clone())
    );
    assert_eq!(nft::total_tokens(runtime).await?, 1);

    // chained transfer: bob -> carol
    let transfer_bc = nft::transfer(runtime, &bob, &minted.token_id, &carol).await??;
    assert_eq!(transfer_bc.src, bob_ref);
    assert_eq!(transfer_bc.dst, carol_ref);
    assert_eq!(
        nft::owner_of(runtime, &minted.token_id).await?,
        Some(carol_ref.clone())
    );

    // alice can no longer transfer it
    let alice_after_chain = nft::transfer(runtime, &alice, &minted.token_id, &alice).await?;
    assert_eq!(
        alice_after_chain,
        Err(Error::Message("only owner can transfer".to_string()))
    );

    // transfer to Burner: owner_of must return HolderRef::Burner
    let transfer_to_burn =
        nft::transfer(runtime, &carol, &minted.token_id, HolderRef::Burner).await??;
    assert_eq!(transfer_to_burn.src, carol_ref);
    assert_eq!(transfer_to_burn.dst, HolderRef::Burner);
    assert_eq!(
        nft::owner_of(runtime, &minted.token_id).await?,
        Some(HolderRef::Burner)
    );

    Ok(())
}
