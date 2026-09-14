use anyhow::{Result, ensure};

use super::{CheckedArithmetics, Decimal};

#[cfg(test)]
mod tests;

/// Runtime policy resolved by the protocol, never selected by a contract or node
/// operator. Storage reservations are recorded in fixed-denomination units so
/// changing the rate for future writes cannot reprice untouched state.
#[derive(Clone, Copy, Debug)]
pub struct Pricing {
    execution_price: Decimal,
    storage_gas_per_byte: u64,
}

impl Default for Pricing {
    fn default() -> Self {
        Self {
            execution_price: Decimal::from("1e-9"),
            storage_gas_per_byte: 1,
        }
    }
}

impl Pricing {
    pub fn new(execution_price: Decimal, storage_gas_per_byte: u64) -> Result<Self> {
        ensure!(
            execution_price >= Decimal::default(),
            "negative execution price"
        );
        ensure!(storage_gas_per_byte > 0, "storage rate must be positive");
        Ok(Self {
            execution_price,
            storage_gas_per_byte,
        })
    }

    // This defines the denomination of persisted `deposited_gas`, not a tunable
    // storage rate. Repricing storage means changing units charged to future writes.
    pub fn collateral_unit_price() -> Decimal {
        Decimal::from("1e-9")
    }

    pub fn storage_collateral(gas: u64) -> Result<Decimal> {
        Ok(Decimal::try_from(gas)?.mul(Self::collateral_unit_price())?)
    }

    pub fn execution_fee(&self, gas: u64) -> Result<Decimal> {
        Ok(Decimal::try_from(gas)?.mul(self.execution_price)?)
    }

    pub fn gas_hold(&self, gas_limit: u64) -> Result<Decimal> {
        // E + D <= G: holding G * max(Pe, Ps), then burning E * Pe,
        // leaves at least D * Ps for collateral, including when Pe is zero.
        let collateral_price = Self::collateral_unit_price();
        let price = if self.execution_price > collateral_price {
            self.execution_price
        } else {
            collateral_price
        };
        Ok(Decimal::try_from(gas_limit)?.mul(price)?)
    }

    pub fn storage_deposit_gas(&self, bytes: u64) -> Option<u64> {
        bytes.checked_mul(self.storage_gas_per_byte)
    }
}
