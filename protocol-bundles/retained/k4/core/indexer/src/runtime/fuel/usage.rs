#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ExecutionUsage {
    pub user_fuel: u64,
    pub system_fuel: u64,
    pub deposit_fuel: u64,
}
