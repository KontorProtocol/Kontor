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

fn attr(key: &str, value: &str) -> nft::Attribute {
    nft::Attribute {
        key: key.to_string(),
        value: value.to_string(),
    }
}

#[testlib::test(contracts_dir = "../../test-contracts")]
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
    let nft_id_3 = "third-nft";
    let file_id = "nft_file_1";
    let initial_attributes = vec![
        attr("name", "First NFT"),
        attr("rarity", "legendary"),
        attr("series", "genesis"),
    ];

    // mint OK: nft_id is independent of file_id, agreement_id is what
    // filestorage returned (= file_id). NftInfo no longer carries attributes;
    // they are queried via dedicated view functions.
    let minted = nft::mint(
        runtime,
        &alice,
        nft_id_1,
        initial_attributes.clone(),
        file_descriptor(file_id, 1),
    )
    .await??;
    assert_eq!(minted.nft_id, nft_id_1);
    assert_eq!(minted.owner, alice_ref);
    // At mint time `creator == owner == signer`.
    assert_eq!(minted.creator, alice_ref);
    assert_eq!(minted.agreement_id, file_id);

    // get_info on existing nft returns the full record.
    let info_before = nft::get_info(runtime, &minted.nft_id)
        .await?
        .expect("info should exist");
    assert_eq!(info_before.nft_id, nft_id_1);
    assert_eq!(info_before.owner, alice_ref);
    assert_eq!(info_before.creator, alice_ref);
    assert_eq!(info_before.agreement_id, file_id);

    // get_info on missing nft returns None.
    assert_eq!(nft::get_info(runtime, "does_not_exist").await?, None);

    assert_eq!(nft::total_minted(runtime).await?, 1);

    // Attributes set at mint are queryable and immutable.
    let mut attrs_listed = nft::get_attributes(runtime, &minted.nft_id).await?;
    attrs_listed.sort_by(|a, b| a.key.cmp(&b.key));
    let mut expected = initial_attributes.clone();
    expected.sort_by(|a, b| a.key.cmp(&b.key));
    assert_eq!(attrs_listed, expected);
    assert_eq!(
        nft::get_attribute(runtime, &minted.nft_id, "name").await?,
        Some("First NFT".to_string())
    );
    assert_eq!(
        nft::get_attribute(runtime, &minted.nft_id, "missing").await?,
        None
    );

    // Reads on a missing nft return empty list / None instead of failing.
    assert_eq!(
        nft::get_attributes(runtime, "does_not_exist").await?,
        Vec::<nft::Attribute>::new()
    );
    assert_eq!(
        nft::get_attribute(runtime, "does_not_exist", "name").await?,
        None
    );

    // Reusing the same nft_id with a fresh file_id must fail with the local
    // uniqueness error (raised before the filestorage call).
    let duplicate_nft_id = nft::mint(
        runtime,
        &alice,
        nft_id_1,
        vec![],
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
        vec![],
        file_descriptor(file_id, 3),
    )
    .await?;
    assert!(matches!(duplicate_file_id, Err(Error::Message(_))));

    // nft_id validation: non-empty and bounded length.
    let empty_nft_id = nft::mint(
        runtime,
        &alice,
        "",
        vec![],
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
        vec![],
        file_descriptor("nft_file_long_nft_id", 5),
    )
    .await?;
    assert_eq!(
        too_long_nft_id,
        Err(Error::Message("nft_id is too long".to_string()))
    );

    // attributes validation: too many entries.
    let too_many: Vec<nft::Attribute> = (0..33).map(|i| attr(&format!("k{i}"), "v")).collect();
    let too_many_attrs = nft::mint(
        runtime,
        &alice,
        "unique-too-many-attrs",
        too_many,
        file_descriptor("nft_file_too_many_attrs", 6),
    )
    .await?;
    assert_eq!(
        too_many_attrs,
        Err(Error::Message("too many attributes".to_string()))
    );

    // attributes validation: empty key.
    let empty_key = nft::mint(
        runtime,
        &alice,
        "unique-empty-attr-key",
        vec![attr("", "v")],
        file_descriptor("nft_file_empty_attr_key", 7),
    )
    .await?;
    assert_eq!(
        empty_key,
        Err(Error::Message("attribute key cannot be empty".to_string()))
    );

    // attributes validation: key too long.
    let long_key = "k".repeat(65);
    let long_key_err = nft::mint(
        runtime,
        &alice,
        "unique-long-attr-key",
        vec![attr(&long_key, "v")],
        file_descriptor("nft_file_long_attr_key", 8),
    )
    .await?;
    assert_eq!(
        long_key_err,
        Err(Error::Message("attribute key is too long".to_string()))
    );

    // attributes validation: value too long.
    let long_value = "v".repeat(2049);
    let long_value_err = nft::mint(
        runtime,
        &alice,
        "unique-long-attr-value",
        vec![attr("k", &long_value)],
        file_descriptor("nft_file_long_attr_value", 9),
    )
    .await?;
    assert_eq!(
        long_value_err,
        Err(Error::Message("attribute value is too long".to_string()))
    );

    // attributes validation: duplicate keys.
    let duplicate_keys = nft::mint(
        runtime,
        &alice,
        "unique-dup-attr-key",
        vec![attr("name", "A"), attr("name", "B")],
        file_descriptor("nft_file_dup_attr_key", 10),
    )
    .await?;
    assert_eq!(
        duplicate_keys,
        Err(Error::Message("duplicate attribute key".to_string()))
    );

    // Empty file_id is rejected by filestorage (delegated check), even with a
    // valid, never-used nft_id.
    let empty_file_id = nft::mint(
        runtime,
        &alice,
        "unique-empty-file-id",
        vec![],
        file_descriptor("", 11),
    )
    .await?;
    assert_eq!(
        empty_file_id,
        Err(Error::Message("file_id cannot be empty".to_string()))
    );

    // A second successful mint, signed by alice, gives alice two
    // entries in the creator index so we can exercise pagination on
    // `list_nfts_by_creator` later. Lexicographic on `nft_id` this
    // lands between `genesis-nft-1` and any other id starting with
    // `s`, so alice's bucket reads [genesis-nft-1, third-nft] in
    // iteration order.
    let alice_second = nft::mint(
        runtime,
        &alice,
        nft_id_3,
        vec![],
        file_descriptor("nft_file_3", 12),
    )
    .await??;
    assert_eq!(alice_second.nft_id, nft_id_3);
    assert_eq!(alice_second.owner, alice_ref);
    assert_eq!(alice_second.creator, alice_ref);
    assert_eq!(nft::total_minted(runtime).await?, 2);

    // A third successful mint, signed by bob, exercises the
    // `total_minted` counter increment on a non-empty store and gives
    // us an NFT whose creator is not the default signer for later
    // checks. We pass an empty attribute list to exercise the
    // zero-attribute mint path.
    let second_mint = nft::mint(
        runtime,
        &bob,
        nft_id_2,
        vec![],
        file_descriptor("nft_file_2", 13),
    )
    .await??;
    assert_eq!(second_mint.nft_id, nft_id_2);
    assert_eq!(second_mint.owner, bob_ref);
    assert_eq!(second_mint.creator, bob_ref);
    assert_eq!(nft::total_minted(runtime).await?, 3);
    assert_eq!(
        nft::get_attributes(runtime, nft_id_2).await?,
        Vec::<nft::Attribute>::new()
    );
    assert_eq!(nft::get_attribute(runtime, nft_id_2, "name").await?, None);

    // The creator index reflects every successful mint, ignores the
    // failed ones (validation errors abort before the index is touched)
    // and stays empty for accounts that never minted anything. The
    // query is lenient on unknown holders (returns 0 / empty, not an
    // error). Pagination on alice's two-entry bucket exercises both
    // the offset/limit slicing and the lexicographic ordering of the
    // underlying map.
    assert_eq!(
        nft::count_nfts_by_creator(runtime, alice_ref.clone()).await?,
        2
    );
    assert_eq!(
        nft::count_nfts_by_creator(runtime, bob_ref.clone()).await?,
        1
    );
    assert_eq!(
        nft::count_nfts_by_creator(runtime, carol_ref.clone()).await?,
        0
    );
    let alice_minted = nft::list_nfts_by_creator(runtime, alice_ref.clone(), 0, 100).await?;
    assert_eq!(
        alice_minted
            .iter()
            .map(|n| n.nft_id.as_str())
            .collect::<Vec<_>>(),
        vec![nft_id_1, nft_id_3]
    );
    assert!(alice_minted.iter().all(|n| n.creator == alice_ref));
    assert!(alice_minted.iter().all(|n| n.owner == alice_ref));
    // Pagination: first page of size 1 is the lex-first nft, the
    // second page is the lex-next one, and a page past the end is
    // empty.
    let alice_first_page = nft::list_nfts_by_creator(runtime, alice_ref.clone(), 0, 1).await?;
    assert_eq!(
        alice_first_page
            .iter()
            .map(|n| n.nft_id.as_str())
            .collect::<Vec<_>>(),
        vec![nft_id_1]
    );
    let alice_second_page = nft::list_nfts_by_creator(runtime, alice_ref.clone(), 1, 1).await?;
    assert_eq!(
        alice_second_page
            .iter()
            .map(|n| n.nft_id.as_str())
            .collect::<Vec<_>>(),
        vec![nft_id_3]
    );
    assert_eq!(
        nft::list_nfts_by_creator(runtime, alice_ref.clone(), 2, 100).await?,
        Vec::<nft::NftInfo>::new()
    );
    // limit == 0 is a documented no-op even when results exist.
    assert_eq!(
        nft::list_nfts_by_creator(runtime, alice_ref.clone(), 0, 0).await?,
        Vec::<nft::NftInfo>::new()
    );
    let bob_minted = nft::list_nfts_by_creator(runtime, bob_ref.clone(), 0, 100).await?;
    assert_eq!(
        bob_minted
            .iter()
            .map(|n| n.nft_id.as_str())
            .collect::<Vec<_>>(),
        vec![nft_id_2]
    );
    assert_eq!(bob_minted[0].creator, bob_ref);
    assert_eq!(
        nft::list_nfts_by_creator(runtime, carol_ref.clone(), 0, 100).await?,
        Vec::<nft::NftInfo>::new()
    );

    // Covering read: `agreement_ids_by_creator` pulls each NFT's agreement id straight
    // from the creator index's COVERING projection (no per-NFT record fetch). It must
    // agree, in the same order, with the agreement ids the record-fetching
    // `list_nfts_by_creator` returns — proving the covering scan (host `get-index-rows`
    // → guest decode) reconstructs the covered field correctly.
    assert_eq!(
        nft::agreement_ids_by_creator(runtime, alice_ref.clone(), 0, 100).await?,
        alice_minted
            .iter()
            .map(|n| n.agreement_id.clone())
            .collect::<Vec<_>>()
    );
    // Pagination + leniency mirror `list_nfts_by_creator`.
    assert_eq!(
        nft::agreement_ids_by_creator(runtime, alice_ref.clone(), 1, 1).await?,
        vec![alice_minted[1].agreement_id.clone()]
    );
    assert_eq!(
        nft::agreement_ids_by_creator(runtime, alice_ref.clone(), 0, 0).await?,
        Vec::<String>::new()
    );
    assert_eq!(
        nft::agreement_ids_by_creator(runtime, carol_ref.clone(), 0, 100).await?,
        Vec::<String>::new()
    );

    // The global `list_nfts` view returns every successful mint in the
    // underlying map's lexicographic order on `nft_id`, regardless of
    // creator. With three mints in flight the page is
    // [genesis-nft-1, second-nft, third-nft] and each entry exposes the
    // current owner/creator at call time (still equal pre-transfer).
    let all_nfts = nft::list_nfts(runtime, 0, 100).await?;
    assert_eq!(
        all_nfts
            .iter()
            .map(|n| n.nft_id.as_str())
            .collect::<Vec<_>>(),
        vec![nft_id_1, nft_id_2, nft_id_3]
    );
    let nft1_global = all_nfts
        .iter()
        .find(|n| n.nft_id == nft_id_1)
        .expect("global list contains nft_id_1");
    assert_eq!(nft1_global.creator, alice_ref);
    assert_eq!(nft1_global.owner, alice_ref);
    assert_eq!(nft1_global.agreement_id, file_id);
    let nft2_global = all_nfts
        .iter()
        .find(|n| n.nft_id == nft_id_2)
        .expect("global list contains nft_id_2");
    assert_eq!(nft2_global.creator, bob_ref);
    assert_eq!(nft2_global.owner, bob_ref);
    let nft3_global = all_nfts
        .iter()
        .find(|n| n.nft_id == nft_id_3)
        .expect("global list contains nft_id_3");
    assert_eq!(nft3_global.creator, alice_ref);
    assert_eq!(nft3_global.owner, alice_ref);
    // Pagination on the global list: first page of size 1 is the
    // lex-first id, subsequent pages walk the collection, and a page
    // starting past the end is empty.
    let global_first = nft::list_nfts(runtime, 0, 1).await?;
    assert_eq!(
        global_first
            .iter()
            .map(|n| n.nft_id.as_str())
            .collect::<Vec<_>>(),
        vec![nft_id_1]
    );
    let global_second = nft::list_nfts(runtime, 1, 1).await?;
    assert_eq!(
        global_second
            .iter()
            .map(|n| n.nft_id.as_str())
            .collect::<Vec<_>>(),
        vec![nft_id_2]
    );
    let global_third = nft::list_nfts(runtime, 2, 1).await?;
    assert_eq!(
        global_third
            .iter()
            .map(|n| n.nft_id.as_str())
            .collect::<Vec<_>>(),
        vec![nft_id_3]
    );
    assert_eq!(
        nft::list_nfts(runtime, 3, 100).await?,
        Vec::<nft::NftInfo>::new()
    );
    // limit == 0 is a documented no-op even when results exist.
    assert_eq!(
        nft::list_nfts(runtime, 0, 0).await?,
        Vec::<nft::NftInfo>::new()
    );
    // `limit` is silently clamped to MAX_LIST_LIMIT (100): asking for
    // 10_000 yields the same three entries, not an error.
    let clamped = nft::list_nfts(runtime, 0, 10_000).await?;
    assert_eq!(
        clamped
            .iter()
            .map(|n| n.nft_id.as_str())
            .collect::<Vec<_>>(),
        vec![nft_id_1, nft_id_2, nft_id_3]
    );

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

    // owner transfer succeeds; agreement_id, attributes and creator are
    // invariant across transfers — only `owner` changes.
    let transfer_ab = nft::transfer(runtime, &alice, &minted.nft_id, &bob).await??;
    assert_eq!(transfer_ab.nft_id, minted.nft_id);
    assert_eq!(transfer_ab.src, alice_ref);
    assert_eq!(transfer_ab.dst, bob_ref);
    let info_ab = nft::get_info(runtime, &minted.nft_id)
        .await?
        .expect("info should still exist");
    assert_eq!(info_ab.owner, bob_ref);
    assert_ne!(info_ab.owner, info_before.owner);
    // Creator does NOT move with the NFT: alice minted it, alice stays
    // its creator forever regardless of who owns it.
    assert_eq!(info_ab.creator, alice_ref);
    assert_eq!(info_ab.agreement_id, file_id);
    let mut attrs_after_ab = nft::get_attributes(runtime, &minted.nft_id).await?;
    attrs_after_ab.sort_by(|a, b| a.key.cmp(&b.key));
    assert_eq!(attrs_after_ab, expected);
    // total_minted counts mints, not transfers: still 3 after the alice→bob move.
    assert_eq!(nft::total_minted(runtime).await?, 3);

    // The OWNER index tracks CURRENT holders — the mirror image of the creator index.
    // After the alice→bob transfer of nft_id_1: bob holds {nft_id_1 (transferred),
    // nft_id_2 (minted by bob)}, alice holds {nft_id_3}. Note this is the OPPOSITE of
    // the creator counts (alice 2, bob 1) — precisely the query the owner index exists
    // for, and impossible without it.
    assert_eq!(nft::count_nfts_by_owner(runtime, bob_ref.clone()).await?, 2);
    assert_eq!(
        nft::count_nfts_by_owner(runtime, alice_ref.clone()).await?,
        1
    );
    assert_eq!(
        nft::count_nfts_by_owner(runtime, carol_ref.clone()).await?,
        0
    );
    let bob_holds = nft::list_nfts_by_owner(runtime, bob_ref.clone(), 0, 100).await?;
    let mut bob_ids: Vec<&str> = bob_holds.iter().map(|n| n.nft_id.as_str()).collect();
    bob_ids.sort();
    let mut expected_bob = vec![nft_id_1, nft_id_2];
    expected_bob.sort();
    assert_eq!(bob_ids, expected_bob);
    assert!(bob_holds.iter().all(|n| n.owner == bob_ref));
    assert_eq!(
        nft::list_nfts_by_owner(runtime, alice_ref.clone(), 0, 100)
            .await?
            .iter()
            .map(|n| n.nft_id.as_str())
            .collect::<Vec<_>>(),
        vec![nft_id_3]
    );

    // The creator index is invariant under transfers: alice keeps her
    // two entries, bob keeps his single entry, and the listed NFTs now
    // expose the *current* owner (bob for nft_id_1, alice for nft_id_3,
    // bob for nft_id_2) while the creator field stays anchored to the
    // original minter.
    assert_eq!(
        nft::count_nfts_by_creator(runtime, alice_ref.clone()).await?,
        2
    );
    assert_eq!(
        nft::count_nfts_by_creator(runtime, bob_ref.clone()).await?,
        1
    );
    let alice_after_ab = nft::list_nfts_by_creator(runtime, alice_ref.clone(), 0, 100).await?;
    assert_eq!(
        alice_after_ab
            .iter()
            .map(|n| n.nft_id.as_str())
            .collect::<Vec<_>>(),
        vec![nft_id_1, nft_id_3]
    );
    assert!(alice_after_ab.iter().all(|n| n.creator == alice_ref));
    // After the transfer, nft_id_1's owner is bob but its creator
    // remains alice. nft_id_3 was not transferred so its owner is
    // still alice.
    let nft1_after_ab = alice_after_ab
        .iter()
        .find(|n| n.nft_id == nft_id_1)
        .expect("alice still lists nft_id_1 as creator");
    assert_eq!(nft1_after_ab.owner, bob_ref);
    let nft3_after_ab = alice_after_ab
        .iter()
        .find(|n| n.nft_id == nft_id_3)
        .expect("alice still lists nft_id_3 as creator");
    assert_eq!(nft3_after_ab.owner, alice_ref);

    // chained transfer: bob -> carol.
    let transfer_bc = nft::transfer(runtime, &bob, &minted.nft_id, &carol).await??;
    assert_eq!(transfer_bc.src, bob_ref);
    assert_eq!(transfer_bc.dst, carol_ref);
    let info_bc = nft::get_info(runtime, &minted.nft_id)
        .await?
        .expect("info should still exist");
    assert_eq!(info_bc.owner, carol_ref);
    assert_eq!(info_bc.creator, alice_ref);
    assert_eq!(info_bc.agreement_id, file_id);
    assert_eq!(
        nft::get_attribute(runtime, &minted.nft_id, "rarity").await?,
        Some("legendary".to_string())
    );

    // alice can no longer transfer it.
    let alice_after_chain = nft::transfer(runtime, &alice, &minted.nft_id, &alice).await?;
    assert_eq!(
        alice_after_chain,
        Err(Error::Message("only owner can transfer".to_string()))
    );

    // transfer to Burner: get_info still returns the same agreement_id and
    // attributes are still readable; only the owner becomes Burner.
    let transfer_to_burn =
        nft::transfer(runtime, &carol, &minted.nft_id, HolderRef::Burner).await??;
    assert_eq!(transfer_to_burn.src, carol_ref);
    assert_eq!(transfer_to_burn.dst, HolderRef::Burner);
    let info_burn = nft::get_info(runtime, &minted.nft_id)
        .await?
        .expect("info should still exist");
    assert_eq!(info_burn.owner, HolderRef::Burner);
    assert_eq!(info_burn.creator, alice_ref);
    assert_eq!(info_burn.agreement_id, file_id);
    let mut attrs_after_burn = nft::get_attributes(runtime, &minted.nft_id).await?;
    attrs_after_burn.sort_by(|a, b| a.key.cmp(&b.key));
    assert_eq!(attrs_after_burn, expected);

    // After the full transfer chain (alice → bob → carol → Burner) the
    // creator index is *unchanged*: alice still owns two entries
    // ({nft_id_1, nft_id_3}) and bob still owns one ({nft_id_2}). Even
    // burning the NFT only flips its `owner` to Burner; its `creator`
    // stays anchored on the original minter. carol and Burner never
    // minted anything, so they appear as 0/empty. An invalid
    // `HolderRef` is reported as 0/empty rather than as a validation
    // error — view functions stay lenient on query inputs.
    assert_eq!(
        nft::count_nfts_by_creator(runtime, alice_ref.clone()).await?,
        2
    );
    assert_eq!(
        nft::count_nfts_by_creator(runtime, bob_ref.clone()).await?,
        1
    );
    assert_eq!(
        nft::count_nfts_by_creator(runtime, carol_ref.clone()).await?,
        0
    );
    assert_eq!(
        nft::count_nfts_by_creator(runtime, HolderRef::Burner).await?,
        0
    );
    let alice_final = nft::list_nfts_by_creator(runtime, alice_ref.clone(), 0, 100).await?;
    assert_eq!(
        alice_final
            .iter()
            .map(|n| n.nft_id.as_str())
            .collect::<Vec<_>>(),
        vec![nft_id_1, nft_id_3]
    );
    assert!(alice_final.iter().all(|n| n.creator == alice_ref));
    // After all transfers, nft_id_1 is owned by Burner; nft_id_3 was
    // never moved and is still owned by alice.
    let nft1_final = alice_final
        .iter()
        .find(|n| n.nft_id == nft_id_1)
        .expect("alice keeps her creator entry for nft_id_1");
    assert_eq!(nft1_final.owner, HolderRef::Burner);
    let nft3_final = alice_final
        .iter()
        .find(|n| n.nft_id == nft_id_3)
        .expect("alice keeps her creator entry for nft_id_3");
    assert_eq!(nft3_final.owner, alice_ref);
    let bob_final = nft::list_nfts_by_creator(runtime, bob_ref.clone(), 0, 100).await?;
    assert_eq!(
        bob_final
            .iter()
            .map(|n| n.nft_id.as_str())
            .collect::<Vec<_>>(),
        vec![nft_id_2]
    );
    assert_eq!(bob_final[0].creator, bob_ref);
    assert_eq!(bob_final[0].owner, bob_ref);
    assert_eq!(
        nft::list_nfts_by_creator(runtime, carol_ref.clone(), 0, 100).await?,
        Vec::<nft::NftInfo>::new()
    );
    assert_eq!(
        nft::list_nfts_by_creator(runtime, HolderRef::Burner, 0, 100).await?,
        Vec::<nft::NftInfo>::new()
    );

    // After the alice → bob → carol → Burner chain on nft_id_1, the
    // global `list_nfts` membership and ordering are unchanged (no
    // mint, no burn-as-delete), but each entry now exposes the
    // *current* owner. Creator is invariant: alice still creates
    // nft_id_1 and nft_id_3, bob still creates nft_id_2.
    let all_after_chain = nft::list_nfts(runtime, 0, 100).await?;
    assert_eq!(
        all_after_chain
            .iter()
            .map(|n| n.nft_id.as_str())
            .collect::<Vec<_>>(),
        vec![nft_id_1, nft_id_2, nft_id_3]
    );
    let nft1_after_chain = all_after_chain
        .iter()
        .find(|n| n.nft_id == nft_id_1)
        .expect("global list still contains nft_id_1");
    assert_eq!(nft1_after_chain.creator, alice_ref);
    assert_eq!(nft1_after_chain.owner, HolderRef::Burner);
    let nft2_after_chain = all_after_chain
        .iter()
        .find(|n| n.nft_id == nft_id_2)
        .expect("global list still contains nft_id_2");
    assert_eq!(nft2_after_chain.creator, bob_ref);
    assert_eq!(nft2_after_chain.owner, bob_ref);
    let nft3_after_chain = all_after_chain
        .iter()
        .find(|n| n.nft_id == nft_id_3)
        .expect("global list still contains nft_id_3");
    assert_eq!(nft3_after_chain.creator, alice_ref);
    assert_eq!(nft3_after_chain.owner, alice_ref);

    // Lenient handling of malformed / never-seen holders.
    assert_eq!(
        nft::count_nfts_by_creator(
            runtime,
            HolderRef::XOnlyPubkey("not-a-valid-x-only-pubkey".to_string())
        )
        .await?,
        0
    );
    assert_eq!(
        nft::list_nfts_by_creator(
            runtime,
            HolderRef::XOnlyPubkey("not-a-valid-x-only-pubkey".to_string()),
            0,
            100
        )
        .await?,
        Vec::<nft::NftInfo>::new()
    );

    Ok(())
}
