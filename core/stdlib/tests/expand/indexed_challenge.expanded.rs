use stdlib::Indexed;
struct Challenge {
    id: String,
    #[index]
    status: u64,
    #[index]
    prover_id: u64,
    seed: u64,
}
#[automatically_derived]
impl stdlib::Indexed for Challenge {
    fn index_entries(&self) -> alloc::vec::Vec<(&'static str, alloc::string::String)> {
        let mut entries = alloc::vec::Vec::new();
        entries.push(("status", alloc::string::ToString::to_string(&self.status)));
        entries.push(("prover_id", alloc::string::ToString::to_string(&self.prover_id)));
        entries
    }
}
