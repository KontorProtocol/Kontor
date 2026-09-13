use anyhow::Result;

use super::api;
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::Decimal;
use crate::runtime::fuel::{FuelDiscriminants, FuelGauge};
use crate::runtime::token::api as token;
use crate::runtime::wit::{Signer, kontor::built_in::context::HolderRef};
use crate::test_utils::{make_descriptor, test_runtime};

#[tokio::test]
async fn nft_cursor_pages_seek_and_survive_membership_changes() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let signer = Signer::Id(
        runtime
            .get_or_create_identity(&random_x_only_pubkey())
            .await?,
    );
    let holder = HolderRef::from(&signer);
    let core = Signer::Core(Box::new(Signer::Nobody));
    token::issue_to(
        &mut runtime,
        &core,
        holder.clone(),
        Decimal::from("1000000"),
    )
    .await??;
    let keys: Vec<String> = ["a".into(), "a\0".into(), "a\0x".into()]
        .into_iter()
        .chain((0..107).map(|i| format!("nft-{i:03}")))
        .collect();
    for (i, key) in keys.iter().enumerate() {
        api::mint(
            &mut runtime,
            &signer,
            key,
            vec![],
            make_descriptor(
                format!("file-{i:03}"),
                vec![1; 32],
                16,
                10,
                "file.txt".into(),
            ),
        )
        .await??;
    }
    let mut all = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let page = api::list_nfts(&mut runtime, after.as_deref(), 7).await?;
        all.extend(page.items.into_iter().map(|n| n.nft_id));
        after = page.next;
        if after.is_none() {
            break;
        }
    }
    assert_eq!(all, keys);
    let mut work = Vec::new();
    for after in [None, Some("nft-099")] {
        let gauge = FuelGauge::new();
        runtime.gauge = Some(gauge.clone());
        let page = api::list_nfts(&mut runtime, after, 5).await?;
        assert_eq!(page.items.len(), 5);
        let stats = gauge.per_type_stats().await;
        work.push(stats[&FuelDiscriminants::KeysNext].count);
        let gauge = FuelGauge::new();
        runtime.gauge = Some(gauge.clone());
        let covered = api::agreement_ids_by_creator(&mut runtime, holder.clone(), after, 5).await?;
        assert_eq!(covered.next, page.next);
        assert_eq!(
            covered.items,
            page.items
                .iter()
                .map(|n| n.agreement_id.clone())
                .collect::<Vec<_>>()
        );
        let covered_stats = gauge.per_type_stats().await;
        assert_eq!(covered_stats[&FuelDiscriminants::KeysNext].count, 6);
        assert!(
            covered_stats
                .get(&FuelDiscriminants::Get)
                .map_or(0, |s| s.count)
                < stats[&FuelDiscriminants::Get].count
        );
    }
    assert_eq!(work[0], work[1], "earlier pages must not add scanned rows");
    runtime.gauge = None;
    let capped = api::list_nfts(&mut runtime, None, u64::MAX).await?;
    assert_eq!(capped.items.len(), 100);
    assert_eq!(capped.next.as_deref(), Some(keys[99].as_str()));
    let empty = api::list_nfts(&mut runtime, None, 0).await?;
    assert!(empty.items.is_empty() && empty.next.is_none());
    let missing = api::list_nfts(&mut runtime, Some("nft-099a"), 1).await?;
    assert_eq!(missing.items[0].nft_id, "nft-100");

    let first = api::list_nfts_by_holder(&mut runtime, holder.clone(), None, 1).await?;
    assert_eq!(first.next.as_deref(), Some("a"));
    runtime.storage.savepoint().await?;
    api::transfer(&mut runtime, &signer, "a", HolderRef::Burner).await??;
    let resumed =
        api::list_nfts_by_holder(&mut runtime, holder.clone(), first.next.as_deref(), 1).await?;
    assert_eq!(resumed.items[0].nft_id, "a\0");
    let changed = api::list_nfts_by_holder(&mut runtime, holder.clone(), None, 1).await?;
    assert_eq!(changed.items[0].nft_id, "a\0");
    runtime.storage.rollback().await?;
    let restored = api::list_nfts_by_holder(&mut runtime, holder, None, 1).await?;
    assert_eq!(restored.items[0].nft_id, "a");
    Ok(())
}
