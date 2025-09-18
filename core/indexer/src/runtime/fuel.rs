use std::{str::FromStr, sync::Arc};

use anyhow::Result;
use futures_util::future::OptionFuture;
use indexmap::IndexMap;
use stdlib::DotPathBuf;
use strum::{EnumDiscriminants, EnumIter};
use tokio::sync::Mutex;
use wasmtime::{
    AsContextMut,
    component::{Accessor, HasData},
};

#[allow(dead_code)]
#[derive(Debug, Clone, EnumDiscriminants, EnumIter)]
#[strum_discriminants(derive(Hash))]
pub enum Fuel {
    SignerToString,
    KeysNext,
    Path(String),
    MatchingPath {
        regexp_len: u64,
        output_len: u64,
    },
    GetKeys,
    Exists,
    Get(usize),
    Set {
        value_len: u64,
    },
    DeleteMatchingPaths {
        regexp_len: u64,
        num_deleted: u64,
    },
    ProcSigner,
    ProcContractSigner,
    ProcViewContext,
    FallSigner,
    FallProcContext,
    FallViewContext,
    ForeignCall {
        expr_len: u64,
        output_len: u64,
    },
    CryptoHash {
        input_len: u64,
        output_len: u64,
    },
    CryptoHashWithSalt {
        input_len: u64,
        salt_len: u64,
        output_len: u64,
    },
    CryptoGenerateId,
    NumbersU64ToInteger,
    NumbersS64ToInteger,
    NumbersStringToInteger {
        s_len: u64,
    },
    NumbersIntegerToString {
        output_len: u64,
    },
    NumbersEqInteger,
    NumbersCmpInteger,
    NumbersAddInteger,
    NumbersSubInteger,
    NumbersMulInteger,
    NumbersDivInteger,
    NumbersIntegerToDecimal,
    NumbersDecimalToInteger,
    NumbersU64ToDecimal,
    NumbersS64ToDecimal,
    NumbersF64ToDecimal,
    NumbersStringToDecimal {
        s_len: u64,
    },
    NumbersDecimalToString {
        output_len: u64,
    },
    NumbersEqDecimal,
    NumbersCmpDecimal,
    NumbersAddDecimal,
    NumbersSubDecimal,
    NumbersMulDecimal,
    NumbersDivDecimal,
    NumbersLog10,
}

impl Fuel {
    pub fn cost(&self) -> u64 {
        match self {
            Self::SignerToString => 50,
            Self::KeysNext => 100,
            Self::Path(path) => 10 * DotPathBuf::from_str(path).unwrap().num_segments(),
            Self::Get(value_len) => 10 * *value_len as u64,
            Self::GetKeys => 200,
            Self::Exists => 50,
            Self::MatchingPath {
                regexp_len,
                output_len,
            } => 500 + 10 * regexp_len + 10 * output_len,
            Self::Set { value_len } => 200 + 10 * value_len,
            Self::DeleteMatchingPaths {
                regexp_len,
                num_deleted,
            } => 1000 + 10 * regexp_len + 50 * num_deleted,
            Self::ProcSigner | Self::ProcContractSigner => 500,
            Self::ProcViewContext => 200,
            Self::FallSigner | Self::FallProcContext | Self::FallViewContext => 100,
            Self::ForeignCall {
                expr_len,
                output_len,
            } => 5000 + 10 * expr_len + 10 * output_len,
            Self::CryptoHash {
                input_len,
                output_len,
            } => 500 + 10 * input_len + 10 * output_len,
            Self::CryptoHashWithSalt {
                input_len,
                salt_len,
                output_len,
            } => 600 + 10 * input_len + 10 * salt_len + 10 * output_len,
            Self::CryptoGenerateId => 500,
            Self::NumbersU64ToInteger
            | Self::NumbersS64ToInteger
            | Self::NumbersIntegerToDecimal
            | Self::NumbersDecimalToInteger
            | Self::NumbersU64ToDecimal
            | Self::NumbersS64ToDecimal
            | Self::NumbersF64ToDecimal => 50,
            Self::NumbersStringToInteger { s_len } | Self::NumbersStringToDecimal { s_len } => {
                100 + 10 * s_len
            }
            Self::NumbersIntegerToString { output_len }
            | Self::NumbersDecimalToString { output_len } => 100 + 10 * output_len,
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
            Self::NumbersLog10 => 500,
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
            let fuel = store.get_fuel()? - self.cost();
            store.set_fuel(fuel)?;
            Ok(fuel)
        })
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
