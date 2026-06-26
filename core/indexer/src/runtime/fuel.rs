use std::sync::Arc;

use anyhow::{Result, anyhow};
use futures_util::future::OptionFuture;
use indexmap::IndexMap;
use strum::{EnumDiscriminants, EnumIter};
use tokio::sync::Mutex;
use wasmtime::{
    AsContextMut, Store,
    component::{Accessor, HasData},
};

use crate::runtime::Runtime;

#[derive(Debug, Clone, EnumDiscriminants, EnumIter)]
#[strum_discriminants(derive(Hash))]
pub enum Fuel {
    SignerToString,
    SignerAsHolder,
    HolderKey,
    HolderFromRef,
    HolderAsRef,
    KeysNext(u64),
    Path(Vec<u8>),
    ExtendPathWithMatch(u64),
    GetKeys,
    Exists,
    Get(usize),
    Set(u64),
    /// A subtree delete (tombstone or hard delete), metered by what it removes:
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
    ComputeChallengeId,
    ProofFromBytes(u64),
    ProofChallengeIds,
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
            Self::KeysNext(key_len) => 100 + 10 * key_len,
            Self::Path(path) => {
                // Meter by element (segment) count — walk the codec elements. A
                // malformed guest path must NOT panic metering: stop counting at the
                // first ill-formed element. This stays deterministic (same bytes →
                // same count), and the storage op itself surfaces the bad path as an
                // error rather than crashing the host. `next_element` always consumes
                // ≥1 byte on `Ok`, so the loop terminates.
                let mut rest = path.as_slice();
                let mut segments = 0u64;
                while !rest.is_empty() {
                    match stdlib::next_element(rest) {
                        Ok((_, r)) => {
                            rest = r;
                            segments += 1;
                        }
                        Err(_) => break,
                    }
                }
                10 * segments
            }
            Self::Get(value_len) => 10 * *value_len as u64,
            Self::GetKeys => 200,
            Self::Exists => 50,
            Self::ExtendPathWithMatch(regexp_len) => 500 + 10 * regexp_len,
            Self::Set(value_len) | Self::Result(value_len) => 200 + 10 * value_len,
            // ~one tombstone insert (200 base) per row, plus the value bytes
            // re-written into each tombstone (10/byte).
            Self::Delete(rows, bytes) => 200 + 200 * rows + 10 * bytes,
            Self::Deposit(fuel) => *fuel,
            Self::ContractAddress => 100,
            Self::ProcSigner | Self::ProcContractSigner | Self::ProcTransaction => 500,
            Self::ProcPayer | Self::ProcContract => 500,
            Self::ViewContract => 200,
            Self::ProcViewContext => 200,
            Self::ProcStorage => 200,
            Self::BlockEntropy => 200,
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
            Self::ComputeChallengeId => 500,
            Self::ProofFromBytes(bytes_len) => 1000 + 10 * bytes_len,
            Self::ProofChallengeIds => 100,
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
            Self::NumbersLog10Decimal => 500,
            Self::RegisterBlsKey => 1_000,
            Self::UpdateProvenance => 1_000,
        }
    }

    pub async fn consume<T, R: HasData>(
        &self,
        accessor: &Accessor<T, R>,
        gauge: Option<&FuelGauge>,
    ) -> Result<u64> {
        OptionFuture::from(gauge.map(|g| g.track(self))).await;
        accessor.with(|mut access| {
            let mut store = access.as_context_mut();
            let fuel = store
                .get_fuel()?
                .checked_sub(self.cost())
                .ok_or(anyhow!("Insufficient fuel"))?;
            store.set_fuel(fuel)?;
            Ok(fuel)
        })
    }

    pub async fn consume_with_store(
        &self,
        gauge: Option<&FuelGauge>,
        store: &mut Store<Runtime>,
    ) -> Result<u64> {
        OptionFuture::from(gauge.map(|g| g.track(self))).await;
        let fuel = store
            .get_fuel()?
            .checked_sub(self.cost())
            .ok_or(anyhow!("Insufficient fuel"))?;
        store.set_fuel(fuel)?;
        Ok(fuel)
    }
}

#[derive(Debug, Clone)]
pub struct FuelStats {
    pub count: u64,
    pub total_fuel: u64,
    pub percentage: f64,
}

#[derive(Debug)]
pub struct InnerFuelGauge {
    history: Vec<(FuelDiscriminants, u64)>,
    total_host_fuel: u64,
    per_type: IndexMap<FuelDiscriminants, FuelStats>,
    starting_fuel: Option<u64>,
    ending_fuel: Option<u64>,
}

#[derive(Debug, Clone)]
pub struct FuelGauge {
    inner: Arc<Mutex<InnerFuelGauge>>,
}

impl FuelGauge {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(Mutex::new(InnerFuelGauge {
                history: Vec::new(),
                total_host_fuel: 0,
                per_type: IndexMap::new(),
                starting_fuel: None,
                ending_fuel: None,
            })),
        }
    }

    pub async fn track(&self, fuel: &Fuel) {
        let cost = fuel.cost();
        let typ = fuel.into();
        let mut inner = self.inner.lock().await;
        inner.total_host_fuel += cost;

        let entry = inner.per_type.entry(typ).or_insert(FuelStats {
            count: 0,
            total_fuel: 0,
            percentage: 0.0,
        });
        entry.count += 1;
        entry.total_fuel += cost;

        let total = inner.total_host_fuel as f64;
        if total > 0.0 {
            for stats in inner.per_type.values_mut() {
                stats.percentage = (stats.total_fuel as f64 / total) * 100.0;
            }
        } else {
            for stats in inner.per_type.values_mut() {
                stats.percentage = 0.0;
            }
        }

        inner.history.push((typ, cost));
    }

    pub async fn starting_fuel(&self) -> u64 {
        self.inner.lock().await.starting_fuel.unwrap_or_default()
    }

    pub async fn set_starting_fuel(&self, fuel: u64) {
        self.inner.lock().await.starting_fuel = Some(fuel);
    }

    pub async fn ending_fuel(&self) -> u64 {
        self.inner.lock().await.ending_fuel.unwrap_or_default()
    }

    pub async fn set_ending_fuel(&self, fuel: u64) {
        self.inner.lock().await.ending_fuel = Some(fuel);
    }

    pub async fn total_host_fuel(&self) -> u64 {
        self.inner.lock().await.total_host_fuel
    }

    pub async fn history(&self) -> Vec<(FuelDiscriminants, u64)> {
        self.inner.lock().await.history.clone()
    }

    pub async fn per_type_stats(&self) -> IndexMap<FuelDiscriminants, FuelStats> {
        self.inner.lock().await.per_type.clone()
    }

    pub async fn host_vs_non_host_percentages(&self) -> (f64, f64) {
        let inner = self.inner.lock().await;
        match (inner.starting_fuel, inner.ending_fuel) {
            (Some(start), Some(end)) => {
                let total_used = start.saturating_sub(end);
                if total_used == 0 {
                    return (0.0, 0.0);
                }
                let host_fuel = inner.total_host_fuel;
                let non_host_fuel = total_used.saturating_sub(host_fuel);
                let host_percent = (host_fuel as f64 / total_used as f64) * 100.0;
                let non_host_percent = (non_host_fuel as f64 / total_used as f64) * 100.0;
                (host_percent, non_host_percent)
            }
            _ => (0.0, 0.0),
        }
    }

    pub async fn reset(&self) {
        let mut inner = self.inner.lock().await;
        inner.history.clear();
        inner.total_host_fuel = 0;
        inner.per_type.clear();
        inner.starting_fuel = None;
        inner.ending_fuel = None;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use stdlib::KeyElement;

    proptest! {
        // Fuzz: arbitrary path bytes must never panic metering, and the cost is
        // bounded by the byte length (≤ 10 fuel per element, ≤ 1 element per byte).
        #[test]
        fn path_cost_never_panics(bytes in proptest::collection::vec(any::<u8>(), 0..64)) {
            let cost = Fuel::Path(bytes.clone()).cost();
            prop_assert!(cost <= 10 * bytes.len() as u64);
        }
    }

    // A subtree delete must cost proportionally to the rows tombstoned and the
    // bytes re-written — never the old flat `Set(0)`, which let a cheap call force
    // unbounded work on every node.
    #[test]
    fn delete_cost_scales_with_rows_and_bytes() {
        assert_eq!(Fuel::Delete(0, 0).cost(), 200);
        assert_eq!(Fuel::Delete(3, 0).cost(), 200 + 200 * 3);
        assert_eq!(Fuel::Delete(3, 50).cost(), 200 + 200 * 3 + 10 * 50);
        // A real (non-empty) delete now costs strictly more than the old flat fee.
        assert!(Fuel::Delete(2, 10).cost() > Fuel::Set(0).cost());
    }

    // A malformed guest path must not panic fuel metering (it used to `expect` a
    // valid codec path). Cost is deterministic — well-formed elements up to the
    // first ill-formed byte — and finite.
    #[test]
    fn malformed_path_does_not_panic_metering() {
        // Pure garbage (no valid leading tag) → zero countable segments, no panic.
        assert_eq!(Fuel::Path(vec![0xFF, 0xFF, 0xFF]).cost(), 0);
        // A valid string element followed by a truncated one → counts the good
        // prefix, stops at the bad tail.
        let mut bytes = stdlib::KeyElement::encode(&"ok".to_string());
        bytes.push(0x02); // dangling string tag with no terminator
        assert_eq!(Fuel::Path(bytes).cost(), 10); // one well-formed segment
        // Empty path → zero.
        assert_eq!(Fuel::Path(Vec::new()).cost(), 0);
        // Well-formed multi-element path counts every segment.
        let mut p = Vec::new();
        "a".to_string().encode_to(&mut p);
        7u64.encode_to(&mut p);
        assert_eq!(Fuel::Path(p).cost(), 20); // two segments
    }
}
