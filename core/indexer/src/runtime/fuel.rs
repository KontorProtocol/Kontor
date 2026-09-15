use anyhow::Result;
use strum::{EnumDiscriminants, EnumIter};
use wasmtime::{AsContextMut, Store, Trap, component::Accessor};

use crate::runtime::Runtime;

mod gauge;
pub use gauge::{ExecutionUsage, FuelCharge, FuelGauge, FuelProfile, FuelReport, FuelStats};
pub(crate) use gauge::{UsageKind, record_fuel};

#[cfg(test)]
mod cow_costs;
#[cfg(test)]
mod host_metering_tests;
#[cfg(test)]
mod profiling_tests;

#[derive(Debug, Clone, EnumDiscriminants, EnumIter)]
#[strum_discriminants(derive(Hash))]
pub enum Fuel {
    SignerToString,
    SignerAsHolder,
    HolderKey,
    HolderFromRef,
    HolderAsRef,
    StorageScan,
    /// Returned bytes only; StorageScan charges each attempt before advancing.
    KeysNext(u64),
    Path(u64),
    ExtendPathWithMatch(u64),
    GetKeys,
    Exists,
    StorageRead,
    StorageWrite,
    StorageDelete,
    /// Payload only; StorageRead pays for the lookup, including a miss.
    Get(usize),
    /// Serialized payload only; StorageWrite pays the entry cost first.
    Set(u64),
    /// Per-row/byte portion of a delete, after the StorageDelete entry charge:
    /// `(rows, bytes)`. A flat per-call fee would let a cheap call tombstone an
    /// arbitrarily large subtree on every node, so the cost scales with both the
    /// row count and the bytes freed (`path.len() + value size`).
    Delete(u64, u64),
    /// The storage DEPOSIT for a written row, expressed directly in fuel (the
    /// payload IS the cost). It is a refundable slice of the op's gas budget — not
    /// host work — so charging it here makes an unaffordable deposit trip the
    /// same out-of-gas path as any other over-budget op. The caller computes the
    /// amount from the runtime's gas→fuel rate (which `cost` can't see).
    Deposit(u64),
    ContractAddress,
    ProcSigner,
    ProcPayer,
    ProcContract,
    ProcContractSigner,
    ProcViewContext,
    ProcTransaction,
    BlockHeight,
    Network,
    TransactionId,
    TransactionOutPoint,
    TransactionData(u64),
    StorageFloor,
    ProcStorage,
    BlockEntropy,
    ViewStorage,
    ViewContract,
    FallSigner,
    FallPayer,
    FallProcContext,
    FallViewContext,
    CoreProcContext,
    CoreContract,
    CryptoHash(u64),
    CryptoGenerateId,
    AggregateRoot(u64),
    FrontierAppend(u64),
    ComputeChallengeId,
    ProofFromBytes(u64),
    ProofVerify,
    NumbersU64ToInteger,
    NumbersS64ToInteger,
    NumbersStringToInteger(u64),
    NumbersIntegerToString(u64),
    NumbersEqInteger,
    NumbersCmpInteger,
    NumbersAddInteger,
    NumbersSubInteger,
    NumbersMulInteger,
    NumbersDivInteger,
    NumbersMulAddDivRemInteger,
    NumbersSqrtInteger,
    NumbersIntegerToDecimal,
    NumbersDecimalToInteger,
    NumbersU64ToDecimal,
    NumbersS64ToDecimal,
    NumbersF64ToDecimal,
    NumbersStringToDecimal(u64),
    NumbersDecimalToString(u64),
    NumbersEqDecimal,
    NumbersCmpDecimal,
    NumbersAddDecimal,
    NumbersSubDecimal,
    NumbersMulDecimal,
    NumbersDivDecimal,
    NumbersLog10Decimal,
    Result(u64),
    // TODO: recalibrate with the rest of the Fuel table against measured
    // benchmarks. Currently sized to match other non-zk "non-trivial"
    // operations (Delete, ProofFromBytes base cost).
    RegisterBlsKey,
    // A host-side provenance-log append (one row). Same flat sizing as
    // RegisterBlsKey — recalibrate with the rest of the table later.
    UpdateProvenance,
}

impl Fuel {
    pub fn cost(&self) -> u64 {
        match self {
            Self::SignerToString => 50,
            Self::SignerAsHolder => 50,
            Self::HolderKey => 50,
            Self::HolderFromRef => 100,
            Self::HolderAsRef => 50,
            Self::StorageScan => 100,
            Self::KeysNext(bytes) | Self::Path(bytes) => bytes.saturating_mul(10),
            Self::StorageRead => 50,
            Self::StorageWrite | Self::StorageDelete => 200,
            Self::Get(value_len) => (*value_len as u64).saturating_mul(10),
            Self::GetKeys => 200,
            Self::Exists => 50,
            Self::ExtendPathWithMatch(candidate_count) => 500 + 10 * candidate_count,
            Self::Set(value_len) => value_len.saturating_mul(10),
            Self::Result(value_len) => 200 + 10 * value_len,
            // Charge mutations and freed footprint bytes; tombstones omit values.
            Self::Delete(rows, bytes) => 200 * rows + 10 * bytes,
            Self::Deposit(fuel) => *fuel,
            Self::ContractAddress => 100,
            Self::ProcSigner | Self::ProcContractSigner | Self::ProcTransaction => 500,
            Self::ProcPayer | Self::ProcContract => 500,
            Self::ViewContract => 200,
            Self::ProcViewContext => 200,
            Self::ProcStorage => 200,
            Self::BlockEntropy => 200,
            Self::BlockHeight
            | Self::Network
            | Self::TransactionId
            | Self::TransactionOutPoint
            | Self::StorageFloor => 50,
            Self::TransactionData(bytes) => 50_u64.saturating_add(bytes.saturating_mul(10)),
            Self::ViewStorage => 200,
            Self::FallSigner
            | Self::FallPayer
            | Self::FallProcContext
            | Self::FallViewContext
            | Self::CoreProcContext
            | Self::CoreContract => 100,
            Self::CryptoHash(input_len) => 500 + 10 * input_len,
            Self::CryptoGenerateId => 500,
            // Rebuilds the aggregated Merkle tree over the file set (~Poseidon
            // hashing per file); scales with the number of files.
            Self::AggregateRoot(num_files) => 1000 + 200 * num_files,
            // Folds this block's new files into the persisted frontier — an O(log n)
            // peak-merge per file (a handful of Poseidon hashes), plus one root
            // recompute. Scales with the files added THIS block, not the total set.
            Self::FrontierAppend(num_files) => 1000 + 200 * num_files,
            Self::ComputeChallengeId => 500,
            Self::ProofFromBytes(bytes_len) => 1000 + 10 * bytes_len,
            Self::ProofVerify => 50_000,
            Self::NumbersU64ToInteger
            | Self::NumbersS64ToInteger
            | Self::NumbersIntegerToDecimal
            | Self::NumbersDecimalToInteger
            | Self::NumbersU64ToDecimal
            | Self::NumbersS64ToDecimal
            | Self::NumbersF64ToDecimal => 50,
            Self::NumbersStringToInteger(s_len) | Self::NumbersStringToDecimal(s_len) => {
                100 + 10 * s_len
            }
            Self::NumbersIntegerToString(output_len) | Self::NumbersDecimalToString(output_len) => {
                100 + 10 * output_len
            }
            Self::NumbersEqInteger | Self::NumbersEqDecimal => 50,
            Self::NumbersCmpInteger | Self::NumbersCmpDecimal => 75,
            Self::NumbersAddInteger
            | Self::NumbersSubInteger
            | Self::NumbersMulInteger
            | Self::NumbersDivInteger
            | Self::NumbersAddDecimal
            | Self::NumbersSubDecimal
            | Self::NumbersMulDecimal
            | Self::NumbersDivDecimal => 100,
            Self::NumbersSqrtInteger => 500,
            Self::NumbersMulAddDivRemInteger => 500,
            Self::NumbersLog10Decimal => 500,
            Self::RegisterBlsKey => 1_000,
            Self::UpdateProvenance => 1_000,
        }
    }

    pub fn consume<T>(&self, accessor: &Accessor<T, Runtime>) -> Result<u64> {
        accessor.with(|mut access| {
            let result = self.subtract(access.as_context_mut());
            if let Some(gauge) = &access.get().gauge {
                gauge.track(self, result.is_ok())?;
            }
            result
        })
    }

    pub fn consume_with_store(&self, store: &mut Store<Runtime>) -> Result<u64> {
        let result = self.subtract(&mut *store);
        if let Some(gauge) = &store.data().gauge {
            gauge.track(self, result.is_ok())?;
        }
        result
    }

    fn subtract(&self, mut store: impl AsContextMut) -> Result<u64> {
        let mut store = store.as_context_mut();
        let fuel = store
            .get_fuel()?
            .checked_sub(self.cost())
            .ok_or(Trap::OutOfFuel)?;
        store.set_fuel(fuel)?;
        Ok(fuel)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    // Preserve the total mutation charge when moving the base before discovery.
    #[test]
    fn delete_cost_scales_with_rows_and_bytes() {
        assert_eq!(Fuel::StorageDelete.cost() + Fuel::Delete(0, 0).cost(), 200);
        assert_eq!(
            Fuel::StorageDelete.cost() + Fuel::Delete(3, 0).cost(),
            200 + 200 * 3
        );
        assert_eq!(
            Fuel::StorageDelete.cost() + Fuel::Delete(3, 50).cost(),
            200 + 200 * 3 + 10 * 50
        );
        // A real (non-empty) delete now costs strictly more than the old flat fee.
        assert!(Fuel::Delete(2, 10).cost() > Fuel::StorageWrite.cost());
    }
}
