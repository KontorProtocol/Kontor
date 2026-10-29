use std::collections::BTreeSet;
use std::ops::AsyncFnOnce;

use anyhow::{Context, Error, Result, ensure};
use bitcoin::Network;
use indexer_types::deserialize;
use kontor_crypto::api::prepare_file;
use kontor_crypto::{LedgerFrontier, aggregate_root_from_files};
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256, Sha512};
use stdlib::{KeyElement, KeyPath};
use tempfile::TempDir;

use super::Snapshot;
use super::validators::execution_fee;
use crate::bls::taproot_derivation_path;
use crate::database::Writer;
use crate::database::queries::get_contract_signer_id;
use crate::database::types::{
    bytes_to_field_element, field_element_to_bytes, validate_padded_len, validate_root,
};
use crate::reg_tester::derive_taproot_keypair_from_seed;
use crate::runtime::filestorage::{address as storage_address, api};
use crate::runtime::numerics::{add_decimal, div_decimal, log10_decimal, mul_decimal, sub_decimal};
use crate::runtime::staking::{address, api as staking};
use crate::runtime::token::api as token;
use crate::runtime::wit::Signer;
use crate::runtime::wit::kontor::built_in::context::HolderRef;
use crate::runtime::{ComponentCache, Decimal, RawFileDescriptor, Runtime, Storage};
use crate::test_utils::test_runtime;

struct Member {
    node: u64,
    signer: Signer,
    liquid: Decimal,
    bond: Decimal,
}

struct Agreement {
    descriptor: RawFileDescriptor,
    weight: Decimal,
    collateral: Decimal,
}

pub(super) struct Population {
    members: Vec<Member>,
    agreements: Vec<Agreement>,
    supply: Decimal,
    burner: Decimal,
    staking_escrow: Decimal,
    registry_root: Vec<u8>,
}

fn core() -> Signer {
    Signer::Core(Box::new(Signer::Nobody))
}

async fn escrow_holder(runtime: &mut Runtime) -> Result<HolderRef> {
    let contract = runtime
        .storage
        .contract_id(&address())
        .await?
        .context("missing staking contract")?;
    Ok(HolderRef::SignerId(
        get_contract_signer_id(&runtime.get_storage_conn(), contract)
            .await?
            .context("missing staking signer")?,
    ))
}

pub(super) async fn stored<T: DeserializeOwned>(
    runtime: &Runtime,
    contract: u64,
    path: &KeyPath,
) -> Result<Option<T>> {
    runtime
        .storage
        .get(u64::MAX, contract, path)
        .await?
        .map(|bytes| deserialize(&bytes))
        .transpose()
}

pub(super) async fn cursor(runtime: &Runtime, contract: u64, field: u8, end: u8) -> Result<u64> {
    Ok(stored(
        runtime,
        contract,
        &KeyPath::new().push_interned(field).push_interned(end),
    )
    .await?
    .unwrap_or(0))
}

impl Population {
    async fn fund(&mut self, runtime: &mut Runtime, member: usize, amount: Decimal) -> Result<()> {
        token::issue_to(
            runtime,
            &core(),
            HolderRef::from(&self.members[member].signer),
            amount,
        )
        .await??;
        self.members[member].liquid = add_decimal(self.members[member].liquid, amount)?;
        self.supply = add_decimal(self.supply, amount)?;
        Ok(())
    }

    async fn paid<T>(
        &mut self,
        runtime: &mut Runtime,
        member: usize,
        call: impl AsyncFnOnce(&mut Runtime) -> Result<T>,
    ) -> Result<T> {
        let previous = runtime.start_usage();
        let result = call(runtime).await;
        let usage = runtime.finish_usage(previous)?;
        let fee = execution_fee(runtime, usage)?;
        self.members[member].liquid = sub_decimal(self.members[member].liquid, fee)?;
        self.supply = sub_decimal(self.supply, fee)?;
        self.burner = add_decimal(self.burner, fee)?;
        result
    }

    pub(super) async fn prepare(
        runtime: &mut Runtime,
        files: usize,
        members: usize,
        seed: [u8; 32],
    ) -> Result<Self> {
        ensure!(
            files > 0 && members >= 3,
            "invalid storage fixture population"
        );
        ensure!(api::get_min_nodes(runtime).await? == 3);
        ensure!(
            api::agreement_count(runtime).await? == 0,
            "fixture needs an empty registry"
        );
        let holder = escrow_holder(runtime).await?;
        let mut population = Self {
            members: Vec::new(),
            agreements: Vec::new(),
            supply: token::total_supply(runtime).await?,
            burner: token::balance(runtime, HolderRef::Burner)
                .await?
                .unwrap_or_default(),
            staking_escrow: token::balance(runtime, holder).await?.unwrap_or_default(),
            registry_root: Vec::new(),
        };
        let calls = files
            .checked_mul(2)
            .and_then(|count| count.checked_add(1))
            .context("fixture call count overflow")?;
        let headroom = add_decimal(
            Decimal::from("1"),
            mul_decimal(
                Decimal::try_from(u64::try_from(calls)?)?,
                Decimal::from("0.0001"),
            )?,
        )?;
        let mut unique = BTreeSet::new();
        for index in 0..members {
            let mut digest = Sha512::new();
            digest.update(b"kontor-workload-storage-host-v1");
            digest.update(seed);
            digest.update(u64::try_from(index)?.to_be_bytes());
            let host_seed: [u8; 64] = digest.finalize().into();
            let key = derive_taproot_keypair_from_seed(
                &host_seed,
                &taproot_derivation_path(Network::Regtest),
            )?
            .x_only_public_key()
            .0
            .to_string();
            ensure!(unique.insert(key.clone()), "duplicate storage host key");
            let identity = runtime.get_or_create_identity(&key).await?;
            let node = identity.signer_id();
            let signer = Signer::Id(identity);
            let holder = HolderRef::from(&signer);
            ensure!(
                token::balance(runtime, holder.clone())
                    .await?
                    .unwrap_or_default()
                    == Decimal::default()
            );
            ensure!(
                staking::get_stake(runtime, &holder.to_string())
                    .await?
                    .is_none()
            );
            population.members.push(Member {
                node,
                signer,
                liquid: Decimal::default(),
                bond: Decimal::default(),
            });
            population.fund(runtime, index, headroom).await?;
        }

        // Prepare every agreement before joining any, so admission observes zero
        // active files and the genesis weight. Later joins reserve the sum exactly.
        let mut reservation = Decimal::default();
        let mut file_ids = BTreeSet::new();
        let publisher = population.members[0].signer.clone();
        for index in 0..files {
            let mut digest = Sha256::new();
            digest.update(b"kontor-workload-storage-file-v1");
            digest.update(seed);
            digest.update(u64::try_from(index)?.to_be_bytes());
            let nonce: [u8; 32] = digest.finalize().into();
            let filename = format!("workload-{index}.bin");
            let mut data = seed.to_vec();
            data.extend_from_slice(&nonce);
            let (_, metadata) = prepare_file(&data, &filename, &nonce)?;
            ensure!(
                file_ids.insert(metadata.file_id.clone()),
                "duplicate storage file"
            );
            let descriptor = RawFileDescriptor {
                file_id: metadata.file_id,
                object_id: metadata.object_id,
                nonce: metadata.nonce,
                root: field_element_to_bytes(&metadata.root).to_vec(),
                padded_len: u64::try_from(metadata.padded_len)?,
                original_size: u64::try_from(metadata.original_size)?,
                filename: metadata.filename,
            };
            let encoded = descriptor
                .padded_len
                .checked_mul(32)
                .context("file size overflow")?;
            let rank = u64::try_from(index)?
                .checked_add(1002)
                .context("file rank overflow")?;
            let weight = div_decimal(
                log10_decimal(Decimal::try_from(encoded)?)?,
                log10_decimal(Decimal::try_from(rank)?)?,
            )?;
            let growth = mul_decimal(
                log10_decimal(Decimal::from("1.001"))?,
                Decimal::from("2.302585092994045684"),
            )?;
            let collateral = div_decimal(
                mul_decimal(mul_decimal(weight, Decimal::from("1000000"))?, growth)?,
                Decimal::from("1000"),
            )?;
            ensure!(collateral > Decimal::default());
            let created = population
                .paid(runtime, 0, async |rt| {
                    Ok(api::create_agreement(rt, &publisher, descriptor.clone()).await??)
                })
                .await?;
            ensure!(created.agreement_id == descriptor.file_id);
            reservation = add_decimal(reservation, collateral)?;
            population.agreements.push(Agreement {
                descriptor,
                weight,
                collateral,
            });
        }
        let bond = add_decimal(reservation, Decimal::from("1"))?;
        for index in 0..members {
            population.fund(runtime, index, bond).await?;
            let signer = population.members[index].signer.clone();
            population
                .paid(runtime, index, async |rt| {
                    Ok(staking::add_stake(rt, &signer, bond).await??)
                })
                .await?;
            population.members[index].bond = bond;
            population.members[index].liquid = sub_decimal(population.members[index].liquid, bond)?;
            population.staking_escrow = add_decimal(population.staking_escrow, bond)?;
            for file in 0..files {
                let id = population.agreements[file].descriptor.file_id.clone();
                let joined = population
                    .paid(runtime, index, async |rt| {
                        Ok(api::join_agreement(rt, &signer, &id).await??)
                    })
                    .await?;
                ensure!(
                    joined.agreement_id == id && joined.node_id == population.members[index].node
                );
                ensure!(joined.activated == (index == 2));
            }
        }
        let files = population
            .agreements
            .iter()
            .enumerate()
            .map(|(slot, agreement)| {
                let (_, root) = validate_root(&agreement.descriptor.root).map_err(Error::msg)?;
                let depth =
                    validate_padded_len(agreement.descriptor.padded_len).map_err(Error::msg)?;
                Ok((root, depth, slot))
            })
            .collect::<Result<Vec<_>>>()?;
        population.registry_root = aggregate_root_from_files(&files)?.to_vec();
        // Seeded files belong to the baseline, not the measured block's append work.
        api::record_block_root(runtime, &core()).await??;
        population.check(runtime).await?;
        Ok(population)
    }

    async fn check(&self, runtime: &mut Runtime) -> Result<()> {
        self.check_registry(runtime).await?;
        ensure!(api::agreement_count(runtime).await? == u64::try_from(self.agreements.len())?);
        let active = api::get_all_active_agreements(runtime).await?;
        ensure!(active.len() == self.agreements.len());
        let mut active_ids: Vec<_> = active
            .iter()
            .map(|item| item.agreement_id.as_str())
            .collect();
        active_ids.sort();
        let mut expected_ids: Vec<_> = self
            .agreements
            .iter()
            .map(|item| item.descriptor.file_id.as_str())
            .collect();
        expected_ids.sort();
        ensure!(active_ids == expected_ids);
        let mut reservation = Decimal::default();
        let mut expected_nodes: Vec<_> = self.members.iter().map(|item| item.node).collect();
        expected_nodes.sort();
        for (index, expected) in self.agreements.iter().enumerate() {
            let descriptor = &expected.descriptor;
            let actual = api::get_agreement(runtime, &descriptor.file_id)
                .await?
                .context("missing agreement")?;
            ensure!(
                actual.agreement_id == descriptor.file_id
                    && actual.file_id == descriptor.file_id
                    && actual.object_id == descriptor.object_id
                    && actual.nonce == descriptor.nonce
                    && actual.root == descriptor.root
                    && actual.padded_len == descriptor.padded_len
                    && actual.original_size == descriptor.original_size
                    && actual.filename == descriptor.filename
                    && actual.ledger_index == u64::try_from(index)?
                    && actual.active
                    && actual.active_challenge.is_none()
                    && actual.storage_weight == expected.weight
                    && actual.required_collateral == expected.collateral,
                "storage fixture descriptor or economic state differs"
            );
            reservation = add_decimal(reservation, expected.collateral)?;
            let nodes = api::get_agreement_nodes(runtime, &descriptor.file_id).await?;
            ensure!(nodes.iter().all(|node| node.active));
            let mut node_ids: Vec<_> = nodes.iter().map(|node| node.node_id).collect();
            node_ids.sort();
            ensure!(
                node_ids == expected_nodes,
                "membership covering index differs"
            );
            for node in &expected_nodes {
                ensure!(api::is_node_in_agreement(runtime, &descriptor.file_id, *node).await?);
            }
        }
        for member in &self.members {
            let node = member.node;
            let holder = HolderRef::from(&member.signer);
            ensure!(token::balance(runtime, holder.clone()).await? == Some(member.liquid));
            ensure!(member.liquid >= token::floor(runtime, holder.clone()).await?);
            let stake = staking::get_stake(runtime, &holder.to_string())
                .await?
                .context("missing storage bond")?;
            ensure!(stake.stake == member.bond && stake.withdrawal_height.is_none());
            ensure!(
                api::get_node_reservation(runtime, node).await? == reservation
                    && reservation < member.bond
            );
            ensure!(
                !api::is_bond_cleanup_pending(runtime, node).await?
                    && api::has_storage_obligations(runtime, node).await?
            );
        }
        let holder = escrow_holder(runtime).await?;
        ensure!(token::balance(runtime, holder).await? == Some(self.staking_escrow));
        ensure!(token::total_supply(runtime).await? == self.supply);
        ensure!(
            token::balance(runtime, HolderRef::Burner)
                .await?
                .unwrap_or_default()
                == self.burner
        );
        Ok(())
    }

    async fn check_registry(&self, runtime: &Runtime) -> Result<()> {
        let contract = runtime
            .storage
            .contract_id(&storage_address())
            .await?
            .context("missing filestorage contract")?;
        let count = u64::try_from(self.agreements.len())?;
        // Field IDs follow the pinned ProtocolState declaration; deque children
        // are head=0, tail=1 and entries=2. These reads do not mutate guest state.
        ensure!(
            cursor(runtime, contract, 20, 0).await? == 0
                && cursor(runtime, contract, 20, 1).await? == count
        );
        ensure!(
            cursor(runtime, contract, 21, 0).await? == 0
                && cursor(runtime, contract, 21, 1).await? == 1
        );
        ensure!(
            cursor(runtime, contract, 22, 0).await? == count
                && cursor(runtime, contract, 22, 1).await? == count
        );
        for field in [23, 25] {
            ensure!(
                stored::<u64>(runtime, contract, &KeyPath::new().push_interned(field)).await?
                    == Some(count)
            );
        }
        let root_path = KeyPath::new()
            .push_interned(21)
            .push_interned(2)
            .push_element(&0u64);
        ensure!(
            stored::<Vec<u8>>(runtime, contract, &root_path).await?
                == Some(self.registry_root.clone())
        );
        let peaks: Vec<u8> = stored(runtime, contract, &KeyPath::new().push_interned(24))
            .await?
            .context("missing frontier peaks")?;
        ensure!(peaks.len().is_multiple_of(32));
        let peaks = peaks
            .as_chunks::<32>()
            .0
            .iter()
            .map(|bytes| bytes_to_field_element(bytes).context("invalid frontier peak"))
            .collect::<Result<Vec<_>>>()?;
        ensure!(LedgerFrontier::from_parts(count, peaks)?.root().to_vec() == self.registry_root);
        let mut weight = Decimal::from("1000");
        for (index, agreement) in self.agreements.iter().enumerate() {
            let path = KeyPath::new()
                .push_interned(20)
                .push_interned(2)
                .push_element(&u64::try_from(index)?);
            ensure!(
                stored::<String>(runtime, contract, &path).await?.as_deref()
                    == Some(agreement.descriptor.file_id.as_str())
            );
            weight = add_decimal(weight, agreement.weight)?;
        }
        ensure!(
            stored::<Vec<u8>>(runtime, contract, &KeyPath::new().push_interned(11)).await?
                == Some(weight.encode())
        );
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn workload_storage_population_restores_valid_agreements() -> Result<()> {
    let (mut runtime, _source_dir, _source_name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    let population = Population::prepare(&mut runtime, 2, 3, [81; 32]).await?;
    let directory = TempDir::new()?;
    let snapshot = Snapshot::export(
        &runtime.get_storage_conn(),
        &directory.path().join("storage.db"),
    )
    .await?;
    for name in ["first.db", "second.db"] {
        snapshot.copy_to(&directory.path().join(name))?;
        let writer = Writer::new(directory.path(), name).await?;
        let storage = Storage::builder()
            .height(1)
            .conn(writer.connection())
            .build();
        let mut restored = Runtime::new(ComponentCache::new(), storage).await?;
        restored.network = Network::Regtest;
        population.check(&mut restored).await?;
        api::record_block_root(&mut restored, &core()).await??;
        population.check(&mut restored).await?;
    }
    population.check(&mut runtime).await?;
    Ok(())
}
