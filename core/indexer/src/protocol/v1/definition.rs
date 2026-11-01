use std::sync::OnceLock;

use crate::protocol::canonical_codec::CodecError;
use crate::protocol::identity::{DefinitionReference, ExecutionDefinitionId};

#[cfg(kontor_retained)]
pub(crate) const REFERENCE: &[u8] =
    include_bytes!(concat!(env!("CARGO_MANIFEST_DIR"), "/definition.bin"));
#[cfg(not(kontor_retained))]
pub(crate) const REFERENCE: &[u8] =
    include_bytes!("../../../../../protocol-bundles/executor-first/definition.bin");

pub(crate) fn execution_definition() -> Result<ExecutionDefinitionId, CodecError> {
    static ID: OnceLock<Result<ExecutionDefinitionId, CodecError>> = OnceLock::new();
    *ID.get_or_init(|| DefinitionReference::decode(REFERENCE)?.id())
}

#[cfg(test)]
mod tests {
    use super::{REFERENCE, execution_definition};
    use crate::protocol::identity::DefinitionReference;

    #[test]
    fn retained_graph_references_have_distinct_valid_identities() {
        let first = DefinitionReference::decode(include_bytes!(
            "../../../../../protocol-bundles/executor-first/definition.bin"
        ))
        .unwrap()
        .id()
        .unwrap();
        let second = DefinitionReference::decode(include_bytes!(
            "../../../../../protocol-bundles/executor-second/definition.bin"
        ))
        .unwrap()
        .id()
        .unwrap();
        assert_eq!(
            execution_definition().unwrap(),
            DefinitionReference::decode(REFERENCE)
                .unwrap()
                .id()
                .unwrap()
        );
        assert_ne!(first, second);
    }
}
