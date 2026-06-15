use stdlib::{Model, Storage};

// A composite index over a bool and an `Option` field: `eligible` partitions on
// (active, challenge-presence), so `where_eligible(true, Presence::Absent)` is a
// prefix scan of the `active ∧ unchallenged` bucket — no predicate DSL. `active`
// also carries its own single-field index, so `set_active` must reconcile both,
// and `set_challenge` (an Option field) reconciles `eligible`.
#[derive(Clone, Storage)]
#[index(eligible, by = (active, challenge))]
struct Agreement {
    #[index]
    active: bool,
    challenge: Option<u64>,
}

#[derive(Model)]
struct AgreementStorage {
    agreements: Map<u64, Agreement>,
}
