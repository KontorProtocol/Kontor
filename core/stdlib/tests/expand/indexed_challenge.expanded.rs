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
    fn index_entries(&self) -> alloc::vec::Vec<stdlib::IndexEntry> {
        let mut entries = alloc::vec::Vec::new();
        entries
            .push(stdlib::IndexEntry {
                name: "status",
                bucket: (/*ERROR*/),
                sort: None,
            });
        entries
            .push(stdlib::IndexEntry {
                name: "prover_id",
                bucket: (/*ERROR*/),
                sort: None,
            });
        entries
    }
}
pub trait ChallengeIndex<K>
where
    K: alloc::string::ToString + core::str::FromStr + Clone,
    <K as core::str::FromStr>::Err: core::fmt::Debug,
{
    /// Raw bucket scan — the single primitive the field model supplies;
    /// the typed `where_*` methods wrap it. Kept public as an escape
    /// hatch for index keys built at runtime. The returned iterator owns
    /// its source (`use<Self, K>`, no lifetime capture), so the typed
    /// wrappers can hand it a borrow of a temporary key string.
    fn by_index(
        &self,
        index_name: &str,
        index_key: &str,
    ) -> impl Iterator<Item = K> + use<Self, K>;
    /// O(1) member count of a `(index_name, index_key)` bucket, the
    /// framework-maintained size of what `by_index` would scan. The other
    /// required primitive the field model supplies.
    fn bucket_count(&self, index_name: &str, index_key: &str) -> u64;
    fn where_status(&self, status: u64) -> impl Iterator<Item = K> {
        self.by_index("status", &stdlib::IndexKey::index_key(&status))
    }
    fn count_status(&self, status: u64) -> u64 {
        self.bucket_count("status", &stdlib::IndexKey::index_key(&status))
    }
    fn where_prover_id(&self, prover_id: u64) -> impl Iterator<Item = K> {
        self.by_index("prover_id", &stdlib::IndexKey::index_key(&prover_id))
    }
    fn count_prover_id(&self, prover_id: u64) -> u64 {
        self.bucket_count("prover_id", &stdlib::IndexKey::index_key(&prover_id))
    }
}
