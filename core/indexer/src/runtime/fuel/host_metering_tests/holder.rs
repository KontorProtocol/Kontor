use anyhow::Result;
use wasmtime::component::Resource;

use super::{assert_exhausted, host};
use crate::database::queries::get_identity;
use crate::reg_tester::random_x_only_pubkey;
use crate::runtime::Runtime;
use crate::runtime::wit::Holder;
use crate::runtime::wit::kontor::built_in::context::{
    HolderRef, HostHolderWithStore as HolderHost, OutPoint,
};
use crate::runtime::wit::kontor::built_in::error::Error as WitError;
use crate::test_utils::test_runtime;

#[tokio::test]
async fn invalid_holder_references_charge_bytes_on_every_attempt() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    for input in [
        String::new(),
        "z".repeat(64),
        "z".repeat(4096),
        "é".repeat(32),
    ] {
        let cost = 100 + 10 * input.len() as u64;
        for reference in [
            HolderRef::XOnlyPubkey(input.clone()),
            HolderRef::Utxo(OutPoint {
                txid: input.clone(),
                vout: 0,
            }),
        ] {
            let mut store = runtime.make_store(cost * 2)?;
            for remaining in [cost, 0] {
                let result = host(&mut store, async |accessor| {
                    <Runtime as HolderHost<Runtime>>::from_ref(accessor, reference.clone()).await
                })
                .await?;
                assert!(matches!(result, Err(WitError::Validation(_))));
                assert_eq!(store.get_fuel()?, remaining);
            }
            let result = host(&mut store, async |accessor| {
                <Runtime as HolderHost<Runtime>>::from_ref(accessor, reference.clone()).await
            })
            .await;
            assert_exhausted(result.unwrap_err());

            store.set_fuel(cost - 1)?;
            let result = host(&mut store, async |accessor| {
                <Runtime as HolderHost<Runtime>>::from_ref(accessor, reference.clone()).await
            })
            .await;
            assert_exhausted(result.unwrap_err());
        }
    }
    Ok(())
}

#[tokio::test]
async fn holder_references_preserve_values_and_resource_cleanup() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    for (reference, cost) in [
        (HolderRef::Core, 100),
        (HolderRef::Burner, 100),
        (HolderRef::OrderingPool, 100),
        (HolderRef::StoragePool, 100),
        (HolderRef::SignerId(42), 100),
        (
            HolderRef::Utxo(OutPoint {
                txid: "ab".repeat(32),
                vout: 7,
            }),
            740,
        ),
    ] {
        let mut store = runtime.make_store(cost)?;
        let holder = host(&mut store, async |accessor| {
            <Runtime as HolderHost<Runtime>>::from_ref(accessor, reference.clone()).await
        })
        .await?
        .expect("valid holder reference");
        assert_eq!(store.get_fuel()?, 0);
        store.set_fuel(50)?;
        let roundtrip = host(&mut store, async |accessor| {
            <Runtime as HolderHost<Runtime>>::as_ref(accessor, Resource::new_borrow(holder.rep()))
                .await
        })
        .await?;
        assert_eq!(roundtrip, reference);
        let rep = holder.rep();
        host(&mut store, async |accessor| {
            <Runtime as HolderHost<Runtime>>::drop(accessor, holder).await
        })
        .await?;
        assert!(
            store
                .data()
                .table
                .lock()
                .await
                .get(&Resource::<Holder>::new_borrow(rep))
                .is_err()
        );
    }
    Ok(())
}

#[tokio::test]
async fn holder_reference_budget_precedes_identity_creation() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let pubkey = random_x_only_pubkey();
    let conn = runtime.get_storage_conn();
    let mut store = runtime.make_store(739)?;
    let result = host(&mut store, async |accessor| {
        <Runtime as HolderHost<Runtime>>::from_ref(accessor, HolderRef::XOnlyPubkey(pubkey.clone()))
            .await
    })
    .await;
    assert_exhausted(result.unwrap_err());
    assert!(get_identity(&conn, &pubkey).await?.is_none());

    store.set_fuel(740)?;
    let holder = host(&mut store, async |accessor| {
        <Runtime as HolderHost<Runtime>>::from_ref(
            accessor,
            HolderRef::XOnlyPubkey(pubkey.to_uppercase()),
        )
        .await
    })
    .await?
    .expect("valid public key");
    let identity = get_identity(&conn, &pubkey)
        .await?
        .expect("created identity");
    assert_eq!(store.get_fuel()?, 0);
    assert_eq!(
        store.data().table.lock().await.get(&holder)?.holder_ref,
        HolderRef::SignerId(identity.signer_id())
    );
    host(&mut store, async |accessor| {
        <Runtime as HolderHost<Runtime>>::drop(accessor, holder).await
    })
    .await?;
    Ok(())
}
