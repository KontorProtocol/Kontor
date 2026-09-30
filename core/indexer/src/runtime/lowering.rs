use anyhow::Result;
use wasmtime::Trap;
use wasmtime::component::Resource;

use super::wit::kontor::built_in::context::{HolderRef, Network, OutPoint};
use super::{ContractAddress, Decimal, Error, Integer, NumericOrdering, NumericSign, VerifyResult};

/// Only variable host-to-guest work belongs here. Existing import tariffs cover
/// fixed ABI structure; guest allocator instructions still spend Wasmtime fuel.
/// No recursive Vec implementation: today's variable outputs are flat bytes.
pub trait Lowering {
    fn lowering_bytes(&self) -> Result<u64>;
}

mod linker;
#[cfg(test)]
pub(super) use linker::charge;
pub use linker::{Linker, LinkerInstance, bindings};

impl Lowering for [u8] {
    fn lowering_bytes(&self) -> Result<u64> {
        Ok(u64::try_from(self.len()).map_err(|_| Trap::OutOfFuel)?)
    }
}

impl Lowering for Vec<u8> {
    fn lowering_bytes(&self) -> Result<u64> {
        self.as_slice().lowering_bytes()
    }
}

impl Lowering for str {
    fn lowering_bytes(&self) -> Result<u64> {
        // Reserve for all supported canonical encodings without scanning text:
        // compact UTF-16 may write a Latin-1 prefix and then widen it in place.
        // The same price applies to UTF-8; this is a tariff, not exact CPU fuel.
        Ok(self
            .as_bytes()
            .lowering_bytes()?
            .checked_mul(3)
            .ok_or(Trap::OutOfFuel)?)
    }
}

impl Lowering for String {
    fn lowering_bytes(&self) -> Result<u64> {
        self.as_str().lowering_bytes()
    }
}

impl<T: Lowering> Lowering for Option<T> {
    fn lowering_bytes(&self) -> Result<u64> {
        self.as_ref().map_or(Ok(0), Lowering::lowering_bytes)
    }
}

impl<T: Lowering, E: Lowering> Lowering for Result<T, E> {
    fn lowering_bytes(&self) -> Result<u64> {
        match self {
            Ok(value) => value.lowering_bytes(),
            Err(error) => error.lowering_bytes(),
        }
    }
}

impl<A: Lowering, B: Lowering> Lowering for (A, B) {
    fn lowering_bytes(&self) -> Result<u64> {
        Ok(self
            .0
            .lowering_bytes()?
            .checked_add(self.1.lowering_bytes()?)
            .ok_or(Trap::OutOfFuel)?)
    }
}

impl<A: Lowering> Lowering for (A,) {
    fn lowering_bytes(&self) -> Result<u64> {
        self.0.lowering_bytes()
    }
}

impl<A: Lowering, B: Lowering, C: Lowering> Lowering for (A, B, C) {
    fn lowering_bytes(&self) -> Result<u64> {
        let third = self.2.lowering_bytes()?;
        Ok(self
            .0
            .lowering_bytes()?
            .checked_add(self.1.lowering_bytes()?)
            .and_then(|bytes| bytes.checked_add(third))
            .ok_or(Trap::OutOfFuel)?)
    }
}

// Exhaustive patterns make changes to existing WIT shapes fail compilation too.
macro_rules! record {
    ($ty:ty { $($field:ident),* $(,)? }) => {
        impl Lowering for $ty {
            fn lowering_bytes(&self) -> Result<u64> {
                let Self { $($field),* } = self;
                let mut bytes = 0_u64;
                $(bytes = bytes.checked_add($field.lowering_bytes()?).ok_or(Trap::OutOfFuel)?;)*
                Ok(bytes)
            }
        }
    };
}

record!(ContractAddress {
    name,
    height,
    tx_index
});
record!(OutPoint { txid, vout });
record!(Integer {
    r0,
    r1,
    r2,
    r3,
    sign
});
record!(Decimal {
    r0,
    r1,
    r2,
    r3,
    sign
});

impl Lowering for HolderRef {
    fn lowering_bytes(&self) -> Result<u64> {
        match self {
            Self::XOnlyPubkey(value) => value.lowering_bytes(),
            Self::Utxo(value) => value.lowering_bytes(),
            Self::SignerId(value) => value.lowering_bytes(),
            Self::Core | Self::Burner | Self::OrderingPool | Self::StoragePool => Ok(0),
        }
    }
}

impl Lowering for Error {
    fn lowering_bytes(&self) -> Result<u64> {
        match self {
            Self::Message(value)
            | Self::Overflow(value)
            | Self::DivByZero(value)
            | Self::Syntax(value)
            | Self::Validation(value) => value.lowering_bytes(),
        }
    }
}

impl<T> Lowering for Resource<T> {
    fn lowering_bytes(&self) -> Result<u64> {
        Ok(0)
    }
}

macro_rules! fixed {
    ($($ty:ty),* $(,)?) => {$(
        impl Lowering for $ty {
            fn lowering_bytes(&self) -> Result<u64> { Ok(0) }
        }
    )*};
}

fixed!((), bool, u32, u64, i64);

macro_rules! enumeration {
    ($ty:ty { $($case:ident),* $(,)? }) => {
        impl Lowering for $ty {
            fn lowering_bytes(&self) -> Result<u64> {
                match self { $(Self::$case => Ok(0),)* }
            }
        }
    };
}

enumeration!(NumericSign { Plus, Minus });
enumeration!(NumericOrdering {
    Less,
    Equal,
    Greater
});
enumeration!(VerifyResult {
    Verified,
    Rejected,
    Invalid
});
enumeration!(Network {
    Mainnet,
    Signet,
    Testnet,
    Regtest
});

#[cfg(test)]
mod tests;
