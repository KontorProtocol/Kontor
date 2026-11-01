#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) enum ExecutorVersion {
    LegacyP1,
}

impl ExecutorVersion {
    pub(crate) const fn tag(self) -> u32 {
        match self {
            Self::LegacyP1 => 1,
        }
    }
}

// These fields preserve the node's current freshness marker. They are not a
// persisted protocol identity or a certified migration commitment.
pub(crate) type CanonicalBase = (
    String,
    u64,
    Option<u64>,
    Option<String>,
    u64,
    Option<u64>,
    Option<String>,
);

// Purpose tags: view=0, committee=1, preparation=2, block=3, batch=4,
// simulation=5, maintenance=6, initialization=7, migration=8. Unused fields must be zero/None so equality is unambiguous.
pub(crate) type Position = (u8, u64, Option<[u8; 32]>, u64);
pub(crate) type SelectionEnvelope = (u32, [u8; 4], CanonicalBase, Position);
