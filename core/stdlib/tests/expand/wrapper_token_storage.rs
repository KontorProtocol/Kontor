use stdlib::Wrapper;

#[derive(Wrapper)]
struct TokenStorage {
    pub ledger: Map<String, u64>,
}
