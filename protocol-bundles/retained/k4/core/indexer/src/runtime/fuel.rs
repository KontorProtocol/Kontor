pub use crate::protocol::v1::fuel::*;

mod gauge;
pub use gauge::{FuelCharge, FuelGauge, FuelProfile, FuelReport, FuelStats};
mod usage;
pub(crate) use gauge::{UsageKind, record_fuel};
pub use usage::ExecutionUsage;

#[cfg(test)]
mod cow_costs;
#[cfg(test)]
mod host_metering_tests;
#[cfg(test)]
mod profiling_tests;

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
