use anyhow::Result;
use wasmtime::component::Resource;

use super::{assert_exhausted, host};
use crate::runtime::wit::kontor::built_in::{
    context::{HostContractWithStore as ContractHost, HostViewContextWithStore as ViewHost},
    error::Error as WitError,
    file_registry::{HostProofWithStore as ProofHost, HostWithStore as FileHost},
};
use crate::runtime::wit::{Contract, ViewContext};
use crate::runtime::{
    ChallengeInput, ContractAddress, RawFileDescriptor, Runtime, TransactionContext,
};
use crate::test_utils::test_runtime;

fn descriptor() -> RawFileDescriptor {
    RawFileDescriptor {
        file_id: "file".into(),
        object_id: "object".into(),
        nonce: vec![1; 8],
        root: vec![0; 32],
        padded_len: 1,
        original_size: 1,
        filename: "file.bin".into(),
    }
}

#[tokio::test]
async fn contract_address_charges_name_bytes_on_every_copy() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    for name in [String::new(), "a".repeat(4096), "é".repeat(32)] {
        let address = ContractAddress {
            name,
            height: 1,
            tx_index: 0,
        };
        let cost = 100 + 10 * address.name.len() as u64;
        let mut store = runtime.make_store(2 * cost)?;
        let resource = store.data().table.lock().await.push(Contract {
            address: address.clone(),
        })?;
        for remaining in [cost, 0] {
            let copied = host(&mut store, async |accessor| {
                <Runtime as ContractHost<Runtime>>::address(
                    accessor,
                    Resource::new_borrow(resource.rep()),
                )
                .await
            })
            .await?;
            assert_eq!(copied, address);
            assert_eq!(store.get_fuel()?, remaining);
        }
        store.set_fuel(cost - 1)?;
        let result = host(&mut store, async |accessor| {
            <Runtime as ContractHost<Runtime>>::address(
                accessor,
                Resource::new_borrow(resource.rep()),
            )
            .await
        })
        .await;
        assert_exhausted(result.unwrap_err());
        assert_eq!(
            store.data().table.lock().await.get(&resource)?.address,
            address
        );
        host(&mut store, async |accessor| {
            <Runtime as ContractHost<Runtime>>::drop(accessor, resource).await
        })
        .await?;
    }
    Ok(())
}

#[tokio::test]
async fn missing_contract_names_pay_before_lookup_and_error_formatting() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    for name in ["absent".to_string(), "a".repeat(4096), "é".repeat(32)] {
        let address = ContractAddress {
            name,
            height: 1,
            tx_index: 0,
        };
        let cost = 10 * ("init()".len() + address.name.len()) as u64;
        let outcome = runtime
            .invoke(&address, None, None, "init()", Some(cost))
            .await?;
        assert!(
            outcome
                .result
                .unwrap_err()
                .to_string()
                .contains("Contract not found")
        );
        assert_eq!(outcome.remaining_fuel, 0);
        let outcome = runtime
            .invoke(&address, None, None, "init()", Some(cost - 1))
            .await?;
        assert!(outcome.result.unwrap_err().to_string().contains("fuel"));
    }
    Ok(())
}

#[tokio::test]
async fn aggregate_inputs_charge_even_bytes_after_an_invalid_root() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    for bytes in [0, 32, 4096] {
        let cost = 1000 + 200 * 2 + 50 * 2 + 10 * bytes as u64;
        let mut store = runtime.make_store(2 * cost)?;
        for remaining in [cost, 0] {
            let result = host(&mut store, async |accessor| {
                <Runtime as FileHost<Runtime>>::aggregate_root(
                    accessor,
                    vec![(vec![], 1, 0), (vec![0; bytes], 1, 1)],
                )
                .await
            })
            .await?;
            assert!(matches!(result, Err(WitError::Validation(_))));
            assert_eq!(store.get_fuel()?, remaining);
        }
        store.set_fuel(cost - 1)?;
        let result = host(&mut store, async |accessor| {
            <Runtime as FileHost<Runtime>>::aggregate_root(
                accessor,
                vec![(vec![], 1, 0), (vec![0; bytes], 1, 1)],
            )
            .await
        })
        .await;
        assert_exhausted(result.unwrap_err());
    }
    Ok(())
}

#[tokio::test]
async fn frontier_peaks_and_roots_pay_before_validation() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    for (peaks, root) in [(1, 0), (4096, 0), (1, 4096)] {
        let cost = 1200 + 50 * 2 + 10 * (peaks + root) as u64;
        let mut store = runtime.make_store(cost)?;
        let result = host(&mut store, async |accessor| {
            <Runtime as FileHost<Runtime>>::frontier_append(
                accessor,
                0,
                vec![0; peaks],
                vec![(vec![0; root], 1, 0)],
            )
            .await
        })
        .await?;
        assert!(matches!(result, Err(WitError::Validation(_))));
        assert_eq!(store.get_fuel()?, 0);
        store.set_fuel(cost - 1)?;
        let result = host(&mut store, async |accessor| {
            <Runtime as FileHost<Runtime>>::frontier_append(
                accessor,
                0,
                vec![0; peaks],
                vec![(vec![0; root], 1, 0)],
            )
            .await
        })
        .await;
        assert_exhausted(result.unwrap_err());
    }
    Ok(())
}

#[tokio::test]
async fn challenge_metadata_includes_every_variable_field() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    for field in 0..6 {
        let mut file = descriptor();
        let mut seed = vec![0; 63];
        match field {
            0 => file.file_id = "é".repeat(2048),
            1 => file.object_id = "x".repeat(4096),
            2 => file.nonce = vec![0; 4096],
            3 => file.root = vec![0; 4096],
            4 => file.filename = "x".repeat(4096),
            5 => seed = vec![0; 4096],
            _ => unreachable!(),
        }
        let bytes = file.file_id.len()
            + file.object_id.len()
            + file.nonce.len()
            + file.root.len()
            + file.filename.len()
            + seed.len();
        let cost = 500 + 50 + 10 * bytes as u64;
        let mut store = runtime.make_store(2 * cost)?;
        for remaining in [cost, 0] {
            let result = host(&mut store, async |accessor| {
                <Runtime as FileHost<Runtime>>::compute_challenge_id(
                    accessor,
                    file.clone(),
                    1,
                    1,
                    seed.clone(),
                    1,
                )
                .await
            })
            .await?;
            assert!(matches!(result, Err(WitError::Validation(_))));
            assert_eq!(store.get_fuel()?, remaining);
        }
        store.set_fuel(cost - 1)?;
        let result = host(&mut store, async |accessor| {
            <Runtime as FileHost<Runtime>>::compute_challenge_id(accessor, file, 1, 1, seed, 1)
                .await
        })
        .await;
        assert_exhausted(result.unwrap_err());
    }
    Ok(())
}

#[tokio::test]
async fn proof_metadata_pays_before_resource_access_including_empty_entries() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    for field in 0..10 {
        let mut file = descriptor();
        let mut seed = vec![0; 64];
        let mut id = String::new();
        let mut root = vec![];
        let mut registry_id = String::new();
        let mut registry_root = vec![];
        match field {
            0 => file.file_id = "x".repeat(4096),
            1 => file.object_id = "x".repeat(4096),
            2 => file.nonce = vec![0; 4096],
            3 => file.root = vec![0; 4096],
            4 => file.filename = "x".repeat(4096),
            5 => seed = vec![0; 4096],
            6 => id = "é".repeat(2048),
            7 => root = vec![0; 4096],
            8 => registry_id = "x".repeat(4096),
            9 => registry_root = vec![0; 4096],
            _ => unreachable!(),
        }
        let bytes = file.file_id.len()
            + file.object_id.len()
            + file.nonce.len()
            + file.root.len()
            + file.filename.len()
            + seed.len()
            + id.len()
            + root.len()
            + registry_id.len()
            + registry_root.len();
        let cost = 50_000 + 50 * 3 + 10 * bytes as u64;
        let challenge = ChallengeInput {
            challenge_id: id,
            file,
            block_height: 1,
            num_challenges: 1,
            seed,
            prover_id: 1,
        };
        let mut store = runtime.make_store(cost - 1)?;
        let result = host(&mut store, async |accessor| {
            <Runtime as ProofHost<Runtime>>::verify(
                accessor,
                Resource::new_borrow(u32::MAX),
                vec![challenge.clone()],
                vec![root.clone()],
                vec![(registry_id.clone(), registry_root.clone(), 1, 0)],
            )
            .await
        })
        .await;
        assert_exhausted(result.unwrap_err());
        store.set_fuel(cost)?;
        let result = host(&mut store, async |accessor| {
            <Runtime as ProofHost<Runtime>>::verify(
                accessor,
                Resource::new_borrow(u32::MAX),
                vec![challenge],
                vec![root],
                vec![(registry_id, registry_root, 1, 0)],
            )
            .await
        })
        .await;
        assert!(result.is_err());
        assert_eq!(store.get_fuel()?, 0);
    }
    Ok(())
}

#[tokio::test]
async fn context_contract_resource_charges_the_fetched_name() -> Result<()> {
    let (mut runtime, _dir, _name) = test_runtime().await?;
    runtime
        .set_context(1, Some(TransactionContext::builder().build()), None, None)
        .await;
    let name = "a".repeat(4096);
    let contract_id = runtime
        .storage
        .insert_contract(
            &name,
            include_bytes!("../../../../../../test-contracts/binaries/counter.wasm.br"),
        )
        .await?;
    let cost = 200 + 10 * name.len() as u64;
    let mut store = runtime.make_store(cost - 1)?;
    let context = store
        .data()
        .table
        .lock()
        .await
        .push(ViewContext { contract_id })?;
    let result = host(&mut store, async |accessor| {
        <Runtime as ViewHost<Runtime>>::contract(accessor, Resource::new_borrow(context.rep()))
            .await
    })
    .await;
    assert_exhausted(result.unwrap_err());
    store.set_fuel(2 * cost)?;
    for remaining in [cost, 0] {
        let contract = host(&mut store, async |accessor| {
            <Runtime as ViewHost<Runtime>>::contract(accessor, Resource::new_borrow(context.rep()))
                .await
        })
        .await?;
        assert_eq!(
            store.data().table.lock().await.get(&contract)?.address.name,
            name
        );
        assert_eq!(store.get_fuel()?, remaining);
        host(&mut store, async |accessor| {
            <Runtime as ContractHost<Runtime>>::drop(accessor, contract).await
        })
        .await?;
    }
    host(&mut store, async |accessor| {
        <Runtime as ViewHost<Runtime>>::drop(accessor, context).await
    })
    .await?;
    Ok(())
}

#[tokio::test]
async fn metered_native_metadata_preserves_valid_results() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    let files = vec![(vec![0; 32], 1, 0), (vec![1; 32], 2, 1)];
    let aggregate_cost = 1000 + 200 * 2 + 2 * (50 + 10 * 32);
    let mut store = runtime.make_store(aggregate_cost)?;
    let root = host(&mut store, async |accessor| {
        <Runtime as FileHost<Runtime>>::aggregate_root(accessor, files.clone()).await
    })
    .await?
    .unwrap();
    assert_eq!(store.get_fuel()?, 0);
    store.set_fuel(aggregate_cost + 50)?;
    let (count, peaks, appended_root) = host(&mut store, async |accessor| {
        <Runtime as FileHost<Runtime>>::frontier_append(accessor, 0, vec![], files).await
    })
    .await?
    .unwrap();
    assert_eq!(store.get_fuel()?, 0);
    assert_eq!(count, 2);
    assert_eq!(peaks.len(), 32);
    assert_eq!(root, appended_root);

    let file = descriptor();
    let bytes = file.file_id.len()
        + file.object_id.len()
        + file.nonce.len()
        + file.root.len()
        + file.filename.len()
        + 64;
    let cost = 500 + 50 + 10 * bytes as u64;
    let mut ids = Vec::new();
    for _ in 0..2 {
        store.set_fuel(cost)?;
        ids.push(
            host(&mut store, async |accessor| {
                <Runtime as FileHost<Runtime>>::compute_challenge_id(
                    accessor,
                    file.clone(),
                    1,
                    1,
                    vec![0; 64],
                    1,
                )
                .await
            })
            .await?
            .unwrap(),
        );
        assert_eq!(store.get_fuel()?, 0);
    }
    assert_eq!(ids[0], ids[1]);
    assert_eq!(ids[0].len(), 64);
    Ok(())
}
