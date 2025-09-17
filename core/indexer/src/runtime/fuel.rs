use std::str::FromStr;

use anyhow::Result;
use stdlib::DotPathBuf;
use wasmtime::{
    AsContextMut,
    component::{Accessor, HasData},
};

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub enum Fuel<'a> {
    SignerToString,
    KeysNext,
    Path(&'a str),
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

impl<'a> Fuel<'a> {
    pub fn cost(&self) -> u64 {
        match *self {
            Self::SignerToString => 50,
            Self::KeysNext => 100,
            Self::Path(path) => 10 * DotPathBuf::from_str(path).unwrap().num_segments(),
            Self::Get(value_len) => 10 * value_len as u64,
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

    pub fn consume<T, R: HasData>(&self, accessor: &Accessor<T, R>) -> Result<u64> {
        accessor.with(|mut access| {
            let mut store = access.as_context_mut();
            let fuel = store.get_fuel()? - self.cost();
            store.set_fuel(fuel)?;
            Ok(fuel)
        })
    }
}
