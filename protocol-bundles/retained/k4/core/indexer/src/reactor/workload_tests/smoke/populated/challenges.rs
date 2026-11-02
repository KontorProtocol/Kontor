use std::collections::{BTreeMap, BTreeSet};

use anyhow::{Context, Result, anyhow, ensure};
use bitcoin::BlockHash;
use bitcoin::hashes::Hash;
use hkdf::Hkdf;
use indexer_types::ResultRow;
use sha2::Sha256;
use stdlib::KeyPath;

use super::super::super::storage::Population;
use super::super::super::storage::{cursor, stored};
use super::super::accounting::lifecycle_value;
use crate::runtime::filestorage::{address, api};
use crate::runtime::wit::{FileDescriptor, Signer};
use crate::runtime::{Decimal, RawFileDescriptor, Runtime};
use crate::test_utils::test_runtime;

#[derive(Clone)]
struct Agreement {
    descriptor: RawFileDescriptor,
    nodes: Vec<u64>,
    ledger_index: u64,
    weight: Decimal,
    collateral: Decimal,
}

#[derive(Clone)]
pub(super) struct Challenges {
    order: Vec<String>,
    agreements: BTreeMap<String, Agreement>,
    expected: BTreeMap<String, api::ChallengeData>,
}

fn derive(ikm: &[u8], salt: &[u8], info: &[u8]) -> Result<[u8; 64]> {
    let mut result = [0; 64];
    Hkdf::<Sha256>::new(Some(salt), ikm)
        .expand(info, &mut result)
        .map_err(|_| anyhow!("challenge HKDF length rejected"))?;
    Ok(result)
}

fn draw(seed: &[u8; 64], counter: &mut u64, domain: &[u8], count: usize) -> Result<usize> {
    ensure!(count > 0);
    let n = u64::try_from(count)?;
    let limit = u64::MAX - u64::MAX % n;
    loop {
        let bytes = derive(
            seed,
            &counter.to_le_bytes(),
            &[b"KONTOR-RNG::v1/".as_slice(), domain].concat(),
        )?;
        *counter = counter.wrapping_add(1);
        let value = u64::from_le_bytes(bytes[..8].try_into()?);
        if value < limit {
            return Ok(usize::try_from(value % n)?);
        }
    }
}

fn same(left: &api::ChallengeData, right: &api::ChallengeData) -> bool {
    left.challenge_id == right.challenge_id
        && left.agreement_id == right.agreement_id
        && left.block_height == right.block_height
        && left.num_challenges == right.num_challenges
        && left.seed == right.seed
        && left.prover_id == right.prover_id
        && left.deadline_height == right.deadline_height
        && left.status == right.status
}

impl Challenges {
    pub(super) async fn capture(runtime: &mut Runtime) -> Result<Self> {
        let contract = runtime
            .storage
            .contract_id(&address())
            .await?
            .context("missing filestorage")?;
        for (field, expected) in [(1, 2016), (2, 12), (3, 8), (4, 52560)] {
            ensure!(
                stored::<u64>(runtime, contract, &KeyPath::new().push_interned(field)).await?
                    == Some(expected),
                "challenge parameters changed"
            );
        }
        ensure!(api::get_active_challenges(runtime).await?.is_empty());
        ensure!(cursor(runtime, contract, 20, 0).await? == 0);
        let count = cursor(runtime, contract, 20, 1).await?;
        let mut order = Vec::new();
        let mut ids = BTreeSet::new();
        for index in 0..count {
            let id: String = stored(
                runtime,
                contract,
                &KeyPath::new()
                    .push_interned(20)
                    .push_interned(2)
                    .push_element(&index),
            )
            .await?
            .context("missing dense active file")?;
            ensure!(ids.insert(id.clone()));
            order.push(id);
        }
        let active = api::get_all_active_agreements(runtime).await?;
        ensure!(active.len() == order.len());
        let mut agreements = BTreeMap::new();
        for file in active {
            ensure!(ids.contains(&file.file_id) && file.active_challenge.is_none());
            let members = api::get_agreement_nodes(runtime, &file.file_id).await?;
            ensure!(!members.is_empty() && members.iter().all(|node| node.active));
            let mut nodes = Vec::new();
            for member in members {
                ensure!(
                    !stored::<bool>(
                        runtime,
                        contract,
                        &KeyPath::new()
                            .push_interned(9)
                            .push_element(&member.node_id)
                    )
                    .await?
                    .unwrap_or(false)
                );
                nodes.push(member.node_id);
            }
            ensure!(nodes.iter().collect::<BTreeSet<_>>().len() == nodes.len());
            let descriptor = RawFileDescriptor {
                file_id: file.file_id.clone(),
                object_id: file.object_id,
                nonce: file.nonce,
                root: file.root,
                padded_len: file.padded_len,
                original_size: file.original_size,
                filename: file.filename,
            };
            ensure!(
                agreements
                    .insert(
                        file.file_id,
                        Agreement {
                            descriptor,
                            nodes,
                            ledger_index: file.ledger_index,
                            weight: file.storage_weight,
                            collateral: file.required_collateral
                        }
                    )
                    .is_none()
            );
        }
        Ok(Self {
            order,
            agreements,
            expected: BTreeMap::new(),
        })
    }

    fn advance(&self, height: u64, hash: BlockHash) -> Result<(Self, Vec<api::ChallengeData>)> {
        ensure!(
            self.expected
                .values()
                .all(|challenge| challenge.deadline_height > height),
            "ordinary sequence reached challenge expiry"
        );
        let mut next = self.clone();
        let challenged: BTreeSet<_> = self
            .expected
            .values()
            .map(|challenge| &challenge.agreement_id)
            .collect();
        let eligible = self
            .order
            .len()
            .checked_sub(challenged.len())
            .context("more challenges than active files")?;
        if eligible == 0 {
            return Ok((next, Vec::new()));
        }
        let sigma = derive(
            &hash.to_byte_array(),
            &[],
            &[
                b"KONTOR-CHAL::v1".as_slice(),
                height.to_le_bytes().as_slice(),
            ]
            .concat(),
        )?;
        let agreement_seed = derive(&sigma, &[], b"KONTOR-CHAL-STREAM::v1/agreement_selection")?;
        let mut counter = 0;
        let roll = draw(&agreement_seed, &mut counter, b"roll", 52560)?;
        let scaled = eligible
            .checked_mul(12)
            .context("challenge count overflow")?;
        let count = (scaled / 52560 + usize::from(roll < scaled % 52560)).min(eligible);
        let mut selected = BTreeSet::new();
        while selected.len() < count {
            let id = &self.order[draw(&agreement_seed, &mut counter, b"select", self.order.len())?];
            if !challenged.contains(id) {
                selected.insert(id.clone());
            }
        }
        let mut created = Vec::new();
        for id in selected {
            let file = self.agreements.get(&id).context("selected unknown file")?;
            let node_seed = derive(
                &sigma,
                id.as_bytes(),
                b"KONTOR-CHAL-STREAM::v1/node_selection",
            )?;
            let mut node_counter = 0;
            let node = file.nodes[draw(&node_seed, &mut node_counter, b"node", file.nodes.len())?];
            let seed = derive(&sigma, id.as_bytes(), b"KONTOR-SEED::v1")?.to_vec();
            let descriptor = FileDescriptor::try_from_raw(file.descriptor.clone())?;
            let challenge = api::ChallengeData {
                challenge_id: descriptor.compute_challenge_id(height, 8, &seed, node)?,
                agreement_id: id,
                block_height: height,
                num_challenges: 8,
                seed,
                prover_id: node,
                deadline_height: height
                    .checked_add(2016)
                    .context("challenge deadline overflow")?,
                status: api::ChallengeStatus::Active,
            };
            ensure!(
                next.expected
                    .insert(challenge.challenge_id.clone(), challenge.clone())
                    .is_none()
            );
            created.push(challenge);
        }
        Ok((next, created))
    }

    async fn check_state(&self, runtime: &mut Runtime) -> Result<()> {
        ensure!(
            api::get_all_active_agreements(runtime).await?.len() == self.agreements.len(),
            "active agreement population changed"
        );
        let actual = api::get_active_challenges(runtime).await?;
        ensure!(
            actual.len() == self.expected.len(),
            "active challenge count differs"
        );
        let mut seen = BTreeSet::new();
        for challenge in actual {
            ensure!(seen.insert(challenge.challenge_id.clone()));
            ensure!(
                same(
                    &challenge,
                    self.expected
                        .get(&challenge.challenge_id)
                        .context("unexpected challenge")?
                ),
                "challenge metadata differs"
            );
        }
        for (id, baseline) in &self.agreements {
            let actual = api::get_agreement(runtime, id)
                .await?
                .context("lost active agreement")?;
            let expected = self
                .expected
                .values()
                .find(|challenge| &challenge.agreement_id == id)
                .map(|challenge| &challenge.challenge_id);
            ensure!(actual.active && actual.active_challenge.as_ref() == expected);
            let descriptor = &baseline.descriptor;
            ensure!(
                actual.agreement_id == *id
                    && actual.file_id == descriptor.file_id
                    && actual.object_id == descriptor.object_id
                    && actual.nonce == descriptor.nonce
                    && actual.root == descriptor.root
                    && actual.padded_len == descriptor.padded_len
                    && actual.original_size == descriptor.original_size
                    && actual.filename == descriptor.filename
                    && actual.ledger_index == baseline.ledger_index
                    && actual.storage_weight == baseline.weight
                    && actual.required_collateral == baseline.collateral,
                "active agreement metadata changed"
            );
            let members = api::get_agreement_nodes(runtime, id).await?;
            ensure!(
                members.len() == baseline.nodes.len()
                    && members
                        .iter()
                        .zip(&baseline.nodes)
                        .all(|(actual, expected)| actual.active && actual.node_id == *expected)
            );
        }
        Ok(())
    }

    pub(super) async fn check_next(
        &self,
        runtime: &mut Runtime,
        rows: &[ResultRow],
        height: u64,
        hash: BlockHash,
    ) -> Result<Self> {
        let (next, created) = self.advance(height, hash)?;
        let returned = api::wave::generate_challenges_for_block_parse_return_expr(lifecycle_value(
            rows,
            &address(),
            "generate-challenges-for-block",
        )?);
        ensure!(
            returned.len() == created.len()
                && returned
                    .iter()
                    .zip(&created)
                    .all(|(actual, expected)| same(actual, expected)),
            "challenge lifecycle omitted or changed selected files"
        );
        next.check_state(runtime).await?;
        Ok(next)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real native contracts with deliberately selected synthetic hashes; challenge oracle diagnostic"]
async fn workload_sequence_challenges_detect_omission_and_preserve_prior() -> Result<()> {
    let (mut runtime, _directory, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    Population::prepare(&mut runtime, 2, 3, [81; 32]).await?;
    let mut model = Challenges::capture(&mut runtime).await?;
    let core = Signer::Core(Box::new(Signer::Nobody));
    for height in [102u64, 103] {
        let mut selected = None;
        // Ordinary tiny-population blocks almost always select zero files. Force
        // a nonempty expected selection without altering the contract parameters.
        for nonce in 0..100_000u64 {
            let mut bytes = [0; 32];
            bytes[..8].copy_from_slice(&nonce.to_le_bytes());
            bytes[8..16].copy_from_slice(&height.to_le_bytes());
            let hash = BlockHash::from_byte_array(bytes);
            let (next, created) = model.advance(height, hash)?;
            if created.len() == 1 {
                selected = Some((hash, next, created));
                break;
            }
        }
        let (hash, next, created) = selected.context("no deterministic challenge candidate")?;
        ensure!(
            next.check_state(&mut runtime).await.is_err(),
            "omitted challenge accepted"
        );
        let returned = api::generate_challenges_for_block(
            &mut runtime,
            &core,
            height,
            hash.to_byte_array().to_vec(),
        )
        .await?;
        ensure!(returned.len() == 1 && same(&returned[0], &created[0]));
        next.check_state(&mut runtime).await?;
        let mut altered = next.clone();
        altered
            .expected
            .values_mut()
            .next()
            .context("missing expected challenge")?
            .prover_id += 1;
        ensure!(
            altered.check_state(&mut runtime).await.is_err(),
            "wrong challenge prover accepted"
        );
        model = next;
    }
    ensure!(model.expected.len() == 2);
    let hash = BlockHash::from_byte_array([19; 32]);
    let (next, created) = model.advance(104, hash)?;
    ensure!(created.is_empty());
    ensure!(
        api::generate_challenges_for_block(&mut runtime, &core, 104, hash.to_byte_array().to_vec())
            .await?
            .is_empty()
    );
    next.check_state(&mut runtime).await?;
    Ok(())
}
