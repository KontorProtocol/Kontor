use anyhow::Result;
use futures_util::TryStreamExt;
use stdlib::KeyPath;

use super::{address, api};
use crate::runtime::Decimal;
use crate::runtime::fuel::{FuelDiscriminants, FuelGauge};
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::{HolderRef, OutPoint};
use crate::test_utils::test_runtime;

#[tokio::test]
async fn balance_pages_cover_the_ledger_and_bound_scan_work() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let core = Signer::Core(Box::new(Signer::Nobody));
    let mut expected = Vec::new();
    for holder in (10..117).map(HolderRef::SignerId).chain([
        HolderRef::Core,
        HolderRef::Burner,
        HolderRef::OrderingPool,
        HolderRef::StoragePool,
        HolderRef::Utxo(OutPoint {
            txid: "ab".repeat(32),
            vout: 7,
        }),
    ]) {
        api::issue_to(&mut runtime, &core, holder.clone(), Decimal::from("1")).await??;
        if !matches!(holder, HolderRef::Core | HolderRef::Burner) {
            expected.push(holder.to_string());
        }
    }
    // Holder keys use their canonical string order, including numeric signer IDs.
    expected.sort();
    let mut all = Vec::new();
    let mut after: Option<String> = None;
    loop {
        let page = api::balances(&mut runtime, after.as_deref(), 7).await??;
        assert!(page.items.len() <= 7);
        if page.next.is_some() {
            assert_eq!(
                page.next,
                page.items.last().map(|balance| balance.acc.to_string())
            );
        }
        for balance in page.items {
            assert_eq!(balance.amt, Decimal::from("1"));
            all.push(balance.acc.to_string());
        }
        after = page.next;
        if after.is_none() {
            break;
        }
    }
    assert_eq!(all, expected);
    let capped = api::balances(&mut runtime, None, u64::MAX).await??;
    assert_eq!(capped.items.len(), 100);
    assert_eq!(capped.next.as_ref(), Some(&expected[99]));
    let final_page = api::balances(&mut runtime, capped.next.as_deref(), 10).await??;
    assert_eq!(final_page.items.len(), 10);
    assert!(
        final_page.next.is_none(),
        "a full final page has no continuation"
    );
    let past_end = api::balances(&mut runtime, expected.last().map(String::as_str), 1).await??;
    assert!(past_end.items.is_empty() && past_end.next.is_none());

    for cursor in [None, Some("80")] {
        let gauge = FuelGauge::with_profiling();
        runtime.gauge = Some(gauge.clone());
        let page = api::balances(&mut runtime, cursor, 5).await??;
        assert_eq!(page.items.len(), 5);
        let stats = gauge.report()?.profile.unwrap().per_type;
        assert_eq!(stats[&FuelDiscriminants::KeysNext].consumed_count, 6);
        assert!(!stats.contains_key(&FuelDiscriminants::Get));
    }
    let gauge = FuelGauge::with_profiling();
    runtime.gauge = Some(gauge.clone());
    let page = api::balances(&mut runtime, Some("99"), 100).await??;
    assert_eq!(page.items.len(), 3);
    let stats = gauge.report()?.profile.unwrap().per_type;
    assert_eq!(stats[&FuelDiscriminants::KeysNext].consumed_count, 5);
    assert!(!stats.contains_key(&FuelDiscriminants::Get));
    Ok(())
}

#[tokio::test]
async fn balance_cursors_survive_removal_and_rollback() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let core = Signer::Core(Box::new(Signer::Nobody));
    for id in [10, 20, 30] {
        api::issue_to(
            &mut runtime,
            &core,
            HolderRef::SignerId(id),
            Decimal::from("1"),
        )
        .await??;
    }
    let first = api::balances(&mut runtime, None, 1).await??;
    assert_eq!(first.next.as_deref(), Some("10"));
    let missing = api::balances(&mut runtime, Some("15"), 1).await??;
    assert_eq!(missing.items[0].acc, HolderRef::SignerId(20));

    runtime.storage.savepoint().await?;
    // Tokens retain zero rows today. Exercise deletion through versioned storage
    // to ensure the cursor is a seek boundary, not a lookup of its former row.
    let contract_id = runtime.storage.contract_id(&address()).await?.unwrap();
    let path = KeyPath::new().push_interned(0).push("10");
    let rows: Vec<_> = runtime
        .storage
        .find_live_subtree(contract_id, &path)
        .await?
        .try_collect()
        .await?;
    assert_eq!(rows.len(), 1);
    runtime.storage.tombstone_rows(contract_id, &rows).await?;
    let resumed = api::balances(&mut runtime, first.next.as_deref(), 1).await??;
    assert_eq!(resumed.items[0].acc, HolderRef::SignerId(20));
    let changed = api::balances(&mut runtime, None, 1).await??;
    assert_eq!(changed.items[0].acc, HolderRef::SignerId(20));
    runtime.storage.rollback().await?;
    let restored = api::balances(&mut runtime, None, 1).await??;
    assert_eq!(restored.items[0].acc, HolderRef::SignerId(10));
    assert_eq!(restored.next, first.next);
    Ok(())
}

#[tokio::test]
async fn balance_pages_handle_empty_zero_limit_and_invalid_cursors() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    let empty = api::balances(&mut runtime, None, 100).await??;
    assert!(empty.items.is_empty() && empty.next.is_none());
    let core = Signer::Core(Box::new(Signer::Nobody));
    for holder in [HolderRef::Core, HolderRef::Burner] {
        api::issue_to(&mut runtime, &core, holder, Decimal::from("1")).await??;
    }
    let filtered = api::balances(&mut runtime, None, 1).await??;
    assert!(filtered.items.is_empty() && filtered.next.is_none());
    let gauge = FuelGauge::with_profiling();
    runtime.gauge = Some(gauge.clone());
    let zero = api::balances(&mut runtime, None, 0).await??;
    assert!(zero.items.is_empty() && zero.next.is_none());
    assert!(
        !gauge
            .report()?
            .profile
            .unwrap()
            .per_type
            .contains_key(&FuelDiscriminants::KeysNext)
    );
    runtime.gauge = None;
    for cursor in ["", "invalid", "invalid:7", "1:4294967296"] {
        for limit in [0, 100] {
            assert!(
                api::balances(&mut runtime, Some(cursor), limit)
                    .await?
                    .is_err()
            );
        }
    }
    Ok(())
}
