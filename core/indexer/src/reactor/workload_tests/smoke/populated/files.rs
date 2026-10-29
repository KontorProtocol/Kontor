use std::collections::BTreeSet;

use anyhow::{Context, Error, Result, ensure};
use indexer_types::ResultRow;
use kontor_crypto::api::prepare_file;
use kontor_crypto::{LedgerFrontier, aggregate_root_from_files};
use sha2::{Digest, Sha256};
use stdlib::KeyPath;

use super::super::super::storage::{cursor, stored};
use super::super::accounting::lifecycle_value;
use crate::database::types::{
    bytes_to_field_element, field_element_to_bytes, validate_padded_len, validate_root,
};
use crate::runtime::filestorage::{address, api};
use crate::runtime::numerics::{add_decimal, div_decimal, log10_decimal, mul_decimal};
use crate::runtime::{Decimal, RawFileDescriptor, Runtime};

struct Agreement {
    descriptor: RawFileDescriptor,
    ledger_index: u64,
    weight: Decimal,
    collateral: Decimal,
}

pub(super) struct FileWorkload {
    agreements: Vec<Agreement>,
    baseline_count: u64,
    baseline_root: Vec<u8>,
    expected_root: Vec<u8>,
}

impl FileWorkload {
    pub(super) async fn prepare(runtime: &mut Runtime, count: usize) -> Result<Self> {
        let baseline_count = api::agreement_count(runtime).await?;
        let mut existing = api::get_all_active_agreements(runtime).await?;
        existing.sort_by_key(|file| file.ledger_index);
        ensure!(existing.len() == usize::try_from(baseline_count)?);
        let mut ids = BTreeSet::new();
        let mut roots = Vec::new();
        let mut total_weight = Decimal::from("1000");
        for (index, file) in existing.iter().enumerate() {
            ensure!(file.ledger_index == u64::try_from(index)?);
            ensure!(ids.insert(file.file_id.clone()));
            let (_, root) = validate_root(&file.root).map_err(Error::msg)?;
            roots.push((
                root,
                validate_padded_len(file.padded_len).map_err(Error::msg)?,
                index,
            ));
            total_weight = add_decimal(total_weight, file.storage_weight)?;
        }
        let baseline_root = aggregate_root_from_files(&roots)?.to_vec();
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
        let mut agreements = Vec::new();
        for index in 0..count {
            let mut digest = Sha256::new();
            digest.update(b"kontor-signed-workload-file-v1");
            digest.update(u64::try_from(index)?.to_be_bytes());
            let nonce: [u8; 32] = digest.finalize().into();
            let data = format!("signed workload file {index}").into_bytes();
            let (_, metadata) = prepare_file(&data, &format!("signed-{index}.bin"), &nonce)?;
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
            let ledger_index = baseline_count
                .checked_add(u64::try_from(index)?)
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
                mul_decimal(mul_decimal(weight, Decimal::from("1000000"))?, growth)?,
                total_weight,
            )?;
            let (_, root) = validate_root(&descriptor.root).map_err(Error::msg)?;
            roots.push((
                root,
                validate_padded_len(descriptor.padded_len).map_err(Error::msg)?,
                usize::try_from(ledger_index)?,
            ));
            agreements.push(Agreement {
                descriptor,
                ledger_index,
                weight,
                collateral,
            });
        }
        Ok(Self {
            agreements,
            baseline_count,
            baseline_root,
            expected_root: aggregate_root_from_files(&roots)?.to_vec(),
        })
    }

    pub(super) fn call(&self, round: usize) -> String {
        api::wave::create_agreement_call_expr(self.agreements[round].descriptor.clone())
    }

    pub(super) fn check_receipt(&self, round: usize, value: &str) -> Result<()> {
        let result = api::wave::create_agreement_parse_return_expr(value)?;
        ensure!(result.agreement_id == self.agreements[round].descriptor.file_id);
        Ok(())
    }

    pub(super) async fn check(&self, runtime: &mut Runtime, rows: &[ResultRow]) -> Result<()> {
        let total = self
            .baseline_count
            .checked_add(u64::try_from(self.agreements.len())?)
            .context("file count overflow")?;
        ensure!(api::agreement_count(runtime).await? == total);
        ensure!(
            api::get_all_active_agreements(runtime).await?.len()
                == usize::try_from(self.baseline_count)?
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
        api::wave::record_block_root_parse_return_expr(lifecycle_value(
            rows,
            &address(),
            "record-block-root",
        )?)?;
        let contract = runtime
            .storage
            .contract_id(&address())
            .await?
            .context("missing filestorage contract")?;
        // These field IDs are tied to the pinned native ProtocolState, as in the
        // population oracle. Inactive registrations advance the ledger, not active_ids.
        ensure!(
            cursor(runtime, contract, 20, 0).await? == 0
                && cursor(runtime, contract, 20, 1).await? == self.baseline_count
        );
        ensure!(
            cursor(runtime, contract, 21, 0).await? == 0
                && cursor(runtime, contract, 21, 1).await? == 2
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
        for (index, expected) in [(0u64, &self.baseline_root), (1, &self.expected_root)] {
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
        ensure!(LedgerFrontier::from_parts(total, peaks)?.root().to_vec() == self.expected_root);
        Ok(())
    }
}
