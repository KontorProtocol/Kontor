use anyhow::{Result, anyhow, ensure};
use built_in_types::numbers_types::Decimal;
use serde::de::DeserializeOwned;
use stdlib::{KeyElement, KeyPath};

use super::native::{NATIVE_CONTRACTS, STAKING_CONTRACT_ID, TOKEN_CONTRACT_ID};
use super::storage_identity::CORE_SIGNER_ID;
use crate::protocol::native_bootstrap::{
    BootstrapRead, BootstrapReceipt as ReceiptFields, BootstrapSnapshot as SnapshotFields,
};

struct BootstrapReceipt {
    contract_id: i64,
    function: String,
    tx_id: Option<i64>,
    input_index: Option<i64>,
    op_index: Option<i64>,
    result_index: i64,
    signer_id: i64,
    payer_signer_id: Option<i64>,
    status: String,
}

struct BootstrapSnapshot {
    published_count: u64,
    receipts: Vec<BootstrapReceipt>,
    admission_floor: Option<Vec<u8>>,
    validators_initialized: Option<Vec<u8>>,
}

impl From<ReceiptFields> for BootstrapReceipt {
    fn from(fields: ReceiptFields) -> Self {
        let (
            contract_id,
            function,
            tx_id,
            input_index,
            op_index,
            result_index,
            signer_id,
            payer_signer_id,
            status,
        ) = fields;
        Self {
            contract_id,
            function,
            tx_id,
            input_index,
            op_index,
            result_index,
            signer_id,
            payer_signer_id,
            status,
        }
    }
}

impl From<SnapshotFields> for BootstrapSnapshot {
    fn from(fields: SnapshotFields) -> Self {
        let (published_count, receipts, admission_floor, validators_initialized) = fields;
        Self {
            published_count,
            receipts: receipts.into_iter().map(BootstrapReceipt::from).collect(),
            admission_floor,
            validators_initialized,
        }
    }
}

pub(crate) struct BootstrapProgress {
    pub(crate) next_result_index: u32,
    pub(crate) admission_floor_initialized: bool,
    pub(crate) validators_initialized: bool,
}

pub(crate) async fn read_progress(read: BootstrapRead) -> Result<BootstrapProgress> {
    // Field positions belong to the retained staking artifact's StorageRoot.
    // They are not a schema inferred from whichever native source builds today.
    let snapshot = read(
        STAKING_CONTRACT_ID,
        KeyPath::new().push_interned(0).as_bytes().to_vec(),
        KeyPath::new().push_interned(4).as_bytes().to_vec(),
    )
    .await
    .map_err(|error| anyhow!(error))?;
    validate(snapshot.into())
}

fn outer(receipt: &BootstrapReceipt, contract_id: u64, function: &str) -> bool {
    receipt.contract_id == contract_id as i64
        && receipt.function == function
        && receipt.payer_signer_id == Some(CORE_SIGNER_ID as i64)
}

fn decode_state<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
    let (value, remaining) = postcard::take_from_bytes(bytes)?;
    ensure!(remaining.is_empty(), "trailing genesis state bytes");
    Ok(value)
}

fn validate(snapshot: BootstrapSnapshot) -> Result<BootstrapProgress> {
    let count = usize::try_from(snapshot.published_count)?;
    ensure!(
        count <= NATIVE_CONTRACTS.len(),
        "unexpected native publication count"
    );
    let receipts = &snapshot.receipts;
    let next_result_index = u32::try_from(receipts.len())?;
    for (index, receipt) in receipts.iter().enumerate() {
        ensure!(
            u32::try_from(receipt.result_index)? == u32::try_from(index)?
                && receipt.tx_id.is_none()
                && receipt.input_index == Some(0)
                && receipt.op_index == Some(0)
                && receipt.signer_id == CORE_SIGNER_ID as i64
                && receipt.status == "Ok",
            "inconsistent genesis receipt at index {index}"
        );
    }
    ensure!(
        receipts.len() >= count,
        "missing native initialization receipt"
    );
    for (index, receipt) in receipts.iter().take(count).enumerate() {
        ensure!(
            outer(receipt, index as u64 + 1, "init"),
            "native initialization receipt mismatch"
        );
    }
    let mut remaining = &receipts[count..];
    ensure!(
        count == NATIVE_CONTRACTS.len() || remaining.is_empty(),
        "initialization stage before complete publication"
    );
    let floor_initialized = remaining
        .first()
        .is_some_and(|row| outer(row, STAKING_CONTRACT_ID, "set-sigma-min"));
    if floor_initialized {
        remaining = &remaining[1..];
    }
    let validators_initialized = !remaining.is_empty();
    if validators_initialized {
        ensure!(
            floor_initialized,
            "validator initialization before admission floor"
        );
        let (last, issuance) = remaining.split_last().expect("nonempty validator receipts");
        ensure!(
            !issuance.is_empty() && outer(last, STAKING_CONTRACT_ID, "set-genesis-set"),
            "missing outer validator initialization receipt"
        );
        ensure!(
            issuance
                .iter()
                .all(|row| row.contract_id == TOKEN_CONTRACT_ID as i64
                    && row.function == "issue-to"
                    && row.payer_signer_id.is_none()),
            "unexpected nested genesis operation"
        );
    }
    if count >= STAKING_CONTRACT_ID as usize {
        let bytes: Vec<u8> = decode_state(
            snapshot
                .admission_floor
                .as_deref()
                .ok_or_else(|| anyhow!("missing genesis admission floor"))?,
        )?;
        let (floor, rest) = Decimal::decode_from(&bytes)
            .map_err(|error| anyhow!("invalid genesis admission floor: {error:?}"))?;
        ensure!(
            rest.is_empty()
                && if floor_initialized {
                    floor > Decimal::default()
                } else {
                    floor == Decimal::default()
                },
            "admission-floor state and receipt disagree"
        );
        let initialized: bool = decode_state(
            snapshot
                .validators_initialized
                .as_deref()
                .ok_or_else(|| anyhow!("missing validator initialization state"))?,
        )?;
        ensure!(
            initialized == validators_initialized,
            "validator initialization state and receipt disagree"
        );
    } else {
        ensure!(
            snapshot.admission_floor.is_none() && snapshot.validators_initialized.is_none(),
            "staking state before publication"
        );
    }
    Ok(BootstrapProgress {
        next_result_index,
        admission_floor_initialized: floor_initialized,
        validators_initialized,
    })
}
