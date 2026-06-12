use stdlib::Storage;

// `Storage` on an enum emits the storage Model/Store AND the index machinery:
// the payload-free `<E>Kind` mirror, discriminant `From`, and `IndexKey` (keyed
// by the lowercased case name, so `Failed(_)` keys as `"failed"`). No `Display`
// — that would clash with built-in enums that already have one.
#[derive(Storage)]
enum ChallengeStatus {
    Active,
    Proven,
    Failed(u64),
}
