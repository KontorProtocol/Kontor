use stdlib::{Indexed, Model, Storage};

// `Storage` gives the value its model (with the `__index_entries` reader, since
// it has indexed fields); `Indexed` gives the value-level entries used to compute
// new index memberships on `set`. `status` carries a single-field index AND backs
// the sorted `due` index, so `set_status` must reconcile both — and read the
// shared `deadline` (the `due` sort field) only once.
#[derive(Clone, Storage, Indexed)]
#[index(due, by = status, sort = deadline)]
struct Challenge {
    pub prover: u64,
    #[index]
    pub status: u64,
    pub deadline: u64,
}

#[derive(Model)]
struct ChallengeStorage {
    pub challenges: IndexedMap<u64, Challenge>,
}
