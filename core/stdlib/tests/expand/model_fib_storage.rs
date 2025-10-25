use stdlib::Model;

#[derive(Model)]
struct FibValue {
    pub value: u64,
}

#[derive(Model)]
struct FibStorage {
    pub cache: Map<u64, FibValue>,
}
