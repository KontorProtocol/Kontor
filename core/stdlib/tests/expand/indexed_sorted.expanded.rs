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
                sort: Some(stdlib::KeyElement::encode(&self.deadline_height)),
            });
        entries
    }
}
pub trait ChallengeIndex<K>
where
    K: stdlib::KeyElement + Clone,
{
    /// Raw bucket scan — yields the primary keys of an unsorted index
    /// bucket, identified by its segments `<bucket…>` (one per `by` field).
    /// The returned iterator owns its source (`use<Self, K>`, no lifetime
    /// capture), so the typed wrappers can hand it borrows of temporary key
    /// strings.
    fn by_index(
        &self,
        index_name: &str,
        bucket: &[&[u8]],
    ) -> impl Iterator<Item = K> + use<Self, K>;
    /// Ordered bucket scan for a *sorted* index: the bucket's `(sort, pk)`
    /// tuple child members, wrapped in a `SortedScan` that yields `K` in sort
    /// order and bounds `up_to`/`range` on the decoded sort value. `S` is the
    /// index's sort field type, so the wrong bound type is a compile error.
    fn by_index_sorted<S: stdlib::KeyElement + Clone + 'static>(
        &self,
        index_name: &str,
        bucket: &[&[u8]],
    ) -> stdlib::SortedScan<K, S>;
    /// O(1) member count of an `(index_name, bucket…)` bucket, the
    /// framework-maintained size of what the scans would walk.
    fn bucket_count(&self, index_name: &str, bucket: &[&[u8]]) -> u64;
    fn where_status(&self, status: u64) -> impl Iterator<Item = K> {
        let __b0 = stdlib::IndexKey::index_key(&status);
        self.by_index("status", &[__b0.as_slice()])
    }
    fn count_status(&self, status: u64) -> u64 {
        let __b0 = stdlib::IndexKey::index_key(&status);
        self.bucket_count("status", &[__b0.as_slice()])
    }
    fn where_due(&self, status: u64) -> stdlib::SortedScan<K, u64> {
        let __b0 = stdlib::IndexKey::index_key(&status);
        self.by_index_sorted::<u64>("due", &[__b0.as_slice()])
    }
    fn count_due(&self, status: u64) -> u64 {
        let __b0 = stdlib::IndexKey::index_key(&status);
        self.bucket_count("due", &[__b0.as_slice()])
    }
}
