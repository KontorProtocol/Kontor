use stdlib::{Indexed, Model, Storage};

// `Storage` gives the value its model (with the `__index_entries` reader, since
// it has an `#[index]` field); `Indexed` gives the value-level entries used to
// compute new index memberships on `set`.
#[derive(Clone, Storage, Indexed)]
struct Challenge {
    pub prover: u64,
    #[index]
    pub status: u64,
}

#[derive(Model)]
struct ChallengeStorage {
    pub challenges: IndexedMap<u64, Challenge>,
}
