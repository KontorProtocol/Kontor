use stdlib::Indexed;
#[index(due, by = status, sort = deadline_height)]
struct Challenge {
    id: String,
    #[index]
    status: u64,
    deadline_height: u64,
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
                name: "due",
                bucket: (/*ERROR*/),
                sort: Some(stdlib::SortKey::sort_key(&self.deadline_height).into()),
            });
        entries
    }
}
pub trait ChallengeIndex<K>
where
    K: alloc::string::ToString + core::str::FromStr + Clone,
    <K as core::str::FromStr>::Err: core::fmt::Debug,
{
    /// Raw bucket scan — yields the primary keys of an unsorted index
    /// bucket. The returned iterator owns its source (`use<Self, K>`, no
    /// lifetime capture), so the typed wrappers can hand it a borrow of a
    /// temporary key string.
    fn by_index(
        &self,
        index_name: &str,
        index_key: &str,
    ) -> impl Iterator<Item = K> + use<Self, K>;
    /// Ordered bucket scan for a *sorted* index: the bucket's `<sort‖pk>`
    /// child segments, wrapped in a `SortedScan` that strips the
    /// `S::WIDTH`-char prefix to yield `K` and bounds `up_to`/`range` on the
    /// encoded prefix. `S` is the index's sort field type, so the bound type
    /// and the stored prefix width can't disagree.
    fn by_index_sorted<S: stdlib::SortKey>(
        &self,
        index_name: &str,
        index_key: &str,
    ) -> stdlib::SortedScan<K, S>;
    /// O(1) member count of a `(index_name, index_key)` bucket, the
    /// framework-maintained size of what the scans would walk.
    fn bucket_count(&self, index_name: &str, index_key: &str) -> u64;
    fn where_status(&self, status: u64) -> impl Iterator<Item = K> {
        self.by_index("status", &stdlib::IndexKey::index_key(&status))
    }
    fn count_status(&self, status: u64) -> u64 {
        self.bucket_count("status", &stdlib::IndexKey::index_key(&status))
    }
    fn where_due(&self, status: u64) -> stdlib::SortedScan<K, u64> {
        self.by_index_sorted::<u64>("due", &stdlib::IndexKey::index_key(&status))
    }
    fn count_due(&self, status: u64) -> u64 {
        self.bucket_count("due", &stdlib::IndexKey::index_key(&status))
    }
}
