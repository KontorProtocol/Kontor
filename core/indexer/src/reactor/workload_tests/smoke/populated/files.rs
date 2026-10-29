use std::collections::BTreeSet;

use anyhow::{Context, Error, Result, ensure};
use indexer_types::ResultRow;
use kontor_crypto::api::prepare_file;
use kontor_crypto::{LedgerFrontier, aggregate_root_from_files};
use sha2::{Digest, Sha256};
use stdlib::KeyPath;

use super::super::super::storage::{Population, cursor, stored};
use super::super::accounting::lifecycle_value;
use crate::database::types::{
    bytes_to_field_element, field_element_to_bytes, validate_padded_len, validate_root,
};
use crate::runtime::filestorage::{address, api};
use crate::runtime::numerics::{add_decimal, div_decimal, log10_decimal, mul_decimal};
use crate::runtime::wit::Signer;
use crate::runtime::{Decimal, RawFileDescriptor, Runtime};
use crate::test_utils::test_runtime;

#[derive(Clone)]
struct Agreement {
    descriptor: RawFileDescriptor,
    ledger_index: u64,
    weight: Decimal,
    collateral: Decimal,
}

#[derive(Clone)]
pub(super) struct FileWorkload {
    agreements: Vec<Agreement>,
    initial_files: Vec<(Vec<u8>, u64)>,
    active_ids: BTreeSet<String>,
    roots: Vec<Vec<u8>>,
    total_weight: Decimal,
    growth: Decimal,
    step_start: usize,
    step: u64,
}

impl FileWorkload {
    pub(super) async fn prepare(runtime: &mut Runtime, count: usize) -> Result<Self> {
        let baseline_count = api::agreement_count(runtime).await?;
        let mut existing = api::get_all_active_agreements(runtime).await?;
        existing.sort_by_key(|file| file.ledger_index);
        ensure!(existing.len() == usize::try_from(baseline_count)?);
        let mut active_ids = BTreeSet::new();
        let mut initial_files = Vec::new();
        let mut total_weight = Decimal::from("1000");
        for (index, file) in existing.iter().enumerate() {
            ensure!(file.ledger_index == u64::try_from(index)?);
            ensure!(active_ids.insert(file.file_id.clone()));
            initial_files.push((file.root.clone(), file.padded_len));
            total_weight = add_decimal(total_weight, file.storage_weight)?;
        }
        // New registrations remain inactive. Their ranks advance, while the
        // active population and collateral growth factor stay fixed.
        let growth = mul_decimal(
            log10_decimal(add_decimal(
                Decimal::from("1"),
                div_decimal(
                    Decimal::try_from(
                        baseline_count
                            .checked_add(1)
                            .context("file count overflow")?,
                    )?,
                    Decimal::from("1000"),
                )?,
            )?)?,
            Decimal::from("2.302585092994045684"),
        )?;
        let mut workload = Self {
            agreements: Vec::new(),
            initial_files,
            active_ids,
            roots: Vec::new(),
            total_weight,
            growth,
            step_start: 0,
            step: 0,
        };
        workload.roots.push(workload.aggregate_root()?);
        workload.append(count)?;
        Ok(workload)
    }

    pub(super) fn next_step(&self) -> Result<Self> {
        ensure!(self.step < 6, "sequence exceeds seven blocks");
        let mut next = self.clone();
        next.step += 1;
        next.step_start = next.agreements.len();
        next.append(self.len())?;
        Ok(next)
    }

    fn aggregate_root(&self) -> Result<Vec<u8>> {
        let roots = self
            .initial_files
            .iter()
            .map(|(root, len)| (root, *len))
            .chain(
                self.agreements
                    .iter()
                    .map(|file| (&file.descriptor.root, file.descriptor.padded_len)),
            )
            .enumerate()
            .map(|(index, (root, len))| {
                let (_, root) = validate_root(root).map_err(Error::msg)?;
                Ok((root, validate_padded_len(len).map_err(Error::msg)?, index))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(aggregate_root_from_files(&roots)?.to_vec())
    }

    fn append(&mut self, count: usize) -> Result<()> {
        ensure!(count > 0 && count <= 100);
        let mut ids = self.active_ids.clone();
        ids.extend(
            self.agreements
                .iter()
                .map(|file| file.descriptor.file_id.clone()),
        );
        for index in 0..count {
            let mut digest = Sha256::new();
            if self.step == 0 {
                digest.update(b"kontor-signed-workload-file-v1");
            } else {
                digest.update(b"kontor-signed-workload-file-sequence-v1");
                digest.update(self.step.to_be_bytes());
            }
            digest.update(u64::try_from(index)?.to_be_bytes());
            let nonce: [u8; 32] = digest.finalize().into();
            let suffix = if self.step == 0 {
                index.to_string()
            } else {
                format!("{}-{index}", self.step)
            };
            let data = format!("signed workload file {suffix}").into_bytes();
            let (_, metadata) = prepare_file(&data, &format!("signed-{suffix}.bin"), &nonce)?;
            ensure!(ids.insert(metadata.file_id.clone()));
            let descriptor = RawFileDescriptor {
                file_id: metadata.file_id,
                object_id: metadata.object_id,
                nonce: metadata.nonce,
                root: field_element_to_bytes(&metadata.root).to_vec(),
                padded_len: u64::try_from(metadata.padded_len)?,
                original_size: u64::try_from(metadata.original_size)?,
                filename: metadata.filename,
            };
            let ledger_index = u64::try_from(self.initial_files.len())?
                .checked_add(u64::try_from(self.agreements.len())?)
                .context("file index overflow")?;
            let weight = div_decimal(
                log10_decimal(Decimal::try_from(
                    descriptor
                        .padded_len
                        .checked_mul(32)
                        .context("file size overflow")?,
                )?)?,
                log10_decimal(Decimal::try_from(
                    ledger_index
                        .checked_add(1002)
                        .context("file rank overflow")?,
                )?)?,
            )?;
            let collateral = div_decimal(
                mul_decimal(mul_decimal(weight, Decimal::from("1000000"))?, self.growth)?,
                self.total_weight,
            )?;
            self.agreements.push(Agreement {
                descriptor,
                ledger_index,
                weight,
                collateral,
            });
        }
        self.roots.push(self.aggregate_root()?);
        Ok(())
    }

    pub(super) fn len(&self) -> usize {
        self.agreements.len() - self.step_start
    }

    pub(super) fn call(&self, round: usize) -> String {
        api::wave::create_agreement_call_expr(
            self.agreements[self.step_start + round].descriptor.clone(),
        )
    }

    pub(super) fn check_receipt(&self, round: usize, value: &str) -> Result<()> {
        let result = api::wave::create_agreement_parse_return_expr(value)?;
        ensure!(result.agreement_id == self.agreements[self.step_start + round].descriptor.file_id);
        Ok(())
    }

    pub(super) async fn check(&self, runtime: &mut Runtime, rows: &[ResultRow]) -> Result<()> {
        api::wave::record_block_root_parse_return_expr(lifecycle_value(
            rows,
            &address(),
            "record-block-root",
        )?)?;
        self.check_state(runtime).await
    }

    async fn check_state(&self, runtime: &mut Runtime) -> Result<()> {
        let total = u64::try_from(self.initial_files.len())?
            .checked_add(u64::try_from(self.agreements.len())?)
            .context("file count overflow")?;
        ensure!(api::agreement_count(runtime).await? == total);
        let active = api::get_all_active_agreements(runtime).await?;
        ensure!(active.len() == self.active_ids.len());
        ensure!(
            active
                .iter()
                .map(|file| file.file_id.clone())
                .collect::<BTreeSet<_>>()
                == self.active_ids
        );
        for expected in &self.agreements {
            let descriptor = &expected.descriptor;
            let actual = api::get_agreement(runtime, &descriptor.file_id)
                .await?
                .context("missing signed file")?;
            ensure!(
                actual.agreement_id == descriptor.file_id
                    && actual.file_id == descriptor.file_id
                    && actual.object_id == descriptor.object_id
                    && actual.nonce == descriptor.nonce
                    && actual.root == descriptor.root
                    && actual.padded_len == descriptor.padded_len
                    && actual.original_size == descriptor.original_size
                    && actual.filename == descriptor.filename
                    && actual.ledger_index == expected.ledger_index
                    && !actual.active
                    && actual.active_challenge.is_none()
                    && actual.storage_weight == expected.weight
                    && actual.required_collateral == expected.collateral
            );
            ensure!(
                api::get_agreement_nodes(runtime, &descriptor.file_id)
                    .await?
                    .is_empty()
            );
        }
        let contract = runtime
            .storage
            .contract_id(&address())
            .await?
            .context("missing filestorage contract")?;
        // These field IDs are tied to the pinned native ProtocolState, as in the
        // population oracle. Inactive registrations advance the ledger, not active_ids.
        ensure!(
            cursor(runtime, contract, 20, 0).await? == 0
                && cursor(runtime, contract, 20, 1).await?
                    == u64::try_from(self.initial_files.len())?
        );
        ensure!(
            cursor(runtime, contract, 21, 0).await? == 0
                && cursor(runtime, contract, 21, 1).await? == u64::try_from(self.roots.len())?
        );
        ensure!(
            cursor(runtime, contract, 22, 0).await? == total
                && cursor(runtime, contract, 22, 1).await? == total
        );
        for field in [23, 25] {
            ensure!(
                stored::<u64>(runtime, contract, &KeyPath::new().push_interned(field)).await?
                    == Some(total)
            );
        }
        for (index, expected) in self.roots.iter().enumerate() {
            let index = u64::try_from(index)?;
            let path = KeyPath::new()
                .push_interned(21)
                .push_interned(2)
                .push_element(&index);
            ensure!(stored::<Vec<u8>>(runtime, contract, &path).await?.as_ref() == Some(expected));
        }
        let peaks: Vec<u8> = stored(runtime, contract, &KeyPath::new().push_interned(24))
            .await?
            .context("missing registry frontier")?;
        ensure!(peaks.len().is_multiple_of(32));
        let peaks = peaks
            .as_chunks::<32>()
            .0
            .iter()
            .map(|bytes| bytes_to_field_element(bytes).context("invalid registry peak"))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            LedgerFrontier::from_parts(total, peaks)?.root().to_vec()
                == *self
                    .roots
                    .last()
                    .context("missing expected registry root")?
        );
        Ok(())
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "real native contracts; evolving registry diagnostic, not full block execution"]
async fn workload_sequence_files_preserve_inactive_ledger() -> Result<()> {
    let (mut runtime, _directory, _name) = test_runtime().await?;
    runtime.set_context(1, None, None, None).await;
    Population::prepare(&mut runtime, 2, 3, [81; 32]).await?;
    let mut workload = FileWorkload::prepare(&mut runtime, 5).await?;
    let core = Signer::Core(Box::new(Signer::Nobody));
    for step in 0..7 {
        runtime.set_context(1, None, None, None).await;
        ensure!(
            workload.check_state(&mut runtime).await.is_err(),
            "omitted registrations accepted"
        );
        for index in workload.step_start..workload.agreements.len() {
            let expected = &workload.agreements[index];
            let result =
                api::create_agreement(&mut runtime, &core, expected.descriptor.clone()).await??;
            ensure!(result.agreement_id == expected.descriptor.file_id);
        }
        ensure!(
            workload.check_state(&mut runtime).await.is_err(),
            "undrained registry accepted"
        );
        api::record_block_root(&mut runtime, &core).await??;
        workload.check_state(&mut runtime).await?;
        // An idle lifecycle must not append a duplicate root or lose old inactive files.
        api::record_block_root(&mut runtime, &core).await??;
        workload.check_state(&mut runtime).await?;
        ensure!(
            api::create_agreement(
                &mut runtime,
                &core,
                workload.agreements[0].descriptor.clone()
            )
            .await?
            .is_err()
        );
        workload.check_state(&mut runtime).await?;
        if step < 6 {
            workload = workload.next_step()?;
        }
    }
    ensure!(api::agreement_count(&mut runtime).await? == 37);
    ensure!(workload.next_step().is_err());
    Ok(())
}
