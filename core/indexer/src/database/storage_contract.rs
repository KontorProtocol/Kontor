use anyhow::{Result, bail};
use libsql::Connection;
use sha2::{Digest, Sha256};

use super::storage_callbacks_v1::storage_callbacks;
use crate::protocol::identity::DefinitionReference;
use crate::protocol::storage_callbacks::StorageCallbacks;

const V1_PATH: &str = "core/indexer/src/protocol/v1/storage-contract.json";
const V1_REFERENCE: &[u8] = include_bytes!("../protocol/v1/storage-contract.json");

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StorageContract {
    V1,
}

impl StorageContract {
    pub(crate) fn resolve(definition: &DefinitionReference) -> Result<Self> {
        let mut contracts = definition
            .sources
            .iter()
            .filter(|source| source.path.ends_with("/storage-contract.json"));
        let Some(required) = contracts.next() else {
            bail!("execution definition has no required storage contract");
        };
        if contracts.next().is_some() {
            bail!("execution definition has multiple required storage contracts");
        }
        // This is the immutable contract reference, not a digest of today's SQL
        // adapter. A replacement adapter must qualify against the same contract.
        let expected: [u8; 32] = Sha256::digest(V1_REFERENCE).into();
        if required.path != V1_PATH || required.digest != expected {
            bail!("execution definition requires an unsupported storage contract");
        }
        Ok(Self::V1)
    }

    pub(crate) fn callbacks(self, conn: &Connection) -> StorageCallbacks {
        match self {
            Self::V1 => storage_callbacks(conn),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::identity::SourceDigest;

    fn definition() -> DefinitionReference {
        DefinitionReference {
            sources: vec![SourceDigest {
                path: V1_PATH.into(),
                digest: Sha256::digest(V1_REFERENCE).into(),
            }],
            locks: vec![SourceDigest {
                path: "executor/Cargo.lock".into(),
                digest: [1; 32],
            }],
            features: vec![],
            build_policy: [2; 32],
        }
    }

    #[test]
    fn storage_contract_is_shared_by_distinct_execution_definitions() -> Result<()> {
        let first = definition();
        let mut second = first.clone();
        second.locks[0].digest = [3; 32];
        assert_ne!(first.id()?, second.id()?);
        assert_eq!(StorageContract::resolve(&first)?, StorageContract::V1);
        assert_eq!(StorageContract::resolve(&second)?, StorageContract::V1);
        Ok(())
    }

    #[test]
    fn storage_contract_rejects_missing_unknown_changed_and_ambiguous_requirements() {
        let mut missing = definition();
        missing.sources.clear();
        assert!(StorageContract::resolve(&missing).is_err());
        let mut unknown = definition();
        unknown.sources[0].path = "core/indexer/src/protocol/v2/storage-contract.json".into();
        assert!(StorageContract::resolve(&unknown).is_err());
        let mut changed = definition();
        changed.sources[0].digest = [0; 32];
        assert_ne!(changed.id().unwrap(), definition().id().unwrap());
        assert!(StorageContract::resolve(&changed).is_err());
        let mut ambiguous = definition();
        ambiguous.sources.push(unknown.sources.remove(0));
        assert!(StorageContract::resolve(&ambiguous).is_err());
    }
}
