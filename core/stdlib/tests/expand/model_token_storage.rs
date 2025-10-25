use stdlib::Model;

#[derive(Model)]
struct TokenStorage {
    pub ledger: Map<String, u64>,
}
