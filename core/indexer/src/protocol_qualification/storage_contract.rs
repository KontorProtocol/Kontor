use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Result, anyhow, bail, ensure};
use serde_json::{Value, json};

use super::fixture::NETWORK;
use crate::protocol::coordinator::linked::{RetainedFactory, retained_session_factory};
use crate::protocol::identity::DefinitionReference;
use crate::protocol::session::HostError;

static CONSTRUCTIONS: AtomicUsize = AtomicUsize::new(0);

fn unexpected_constructor() -> Result<RetainedFactory, HostError> {
    CONSTRUCTIONS.fetch_add(1, Ordering::SeqCst);
    Err((
        0,
        "unsupported storage reached executor construction".into(),
    ))
}

pub(super) fn qualify() -> Result<Value> {
    let before = CONSTRUCTIONS.load(Ordering::SeqCst);
    let mut checked = Vec::new();
    for (name, bytes) in [
        ("first", kontor_executor_first::execution_definition()),
        ("second", kontor_executor_second::execution_definition()),
    ] {
        let original = DefinitionReference::decode(bytes)?;
        for mutation in ["missing", "unknown", "changed", "multiple"] {
            let mut reference = original.clone();
            let position = reference
                .sources
                .iter()
                .position(|source| {
                    source.path == "core/indexer/src/protocol/v1/storage-contract.json"
                })
                .ok_or_else(|| anyhow!("actual executor lacks storage requirement"))?;
            match mutation {
                "missing" => {
                    reference.sources.remove(position);
                }
                "unknown" => {
                    reference.sources[position].path =
                        "core/indexer/src/protocol/v2/storage-contract.json".into()
                }
                "changed" => reference.sources[position].digest = [0; 32],
                "multiple" => {
                    let mut extra = reference.sources[position].clone();
                    extra.path = "core/indexer/src/protocol/v2/storage-contract.json".into();
                    reference.sources.push(extra);
                }
                _ => unreachable!(),
            }
            reference.sources.sort_by(|a, b| a.path.cmp(&b.path));
            let encoded = reference.encode()?;
            let error =
                match retained_session_factory(NETWORK, None, unexpected_constructor, &encoded) {
                    Ok(_) => bail!("unsupported storage contract accepted"),
                    Err(error) => error,
                };
            ensure!(
                error.to_string().contains("storage contract"),
                "unexpected rejection: {error:#}"
            );
            checked.push(format!("{name}:{mutation}"));
        }
    }
    ensure!(
        CONSTRUCTIONS.load(Ordering::SeqCst) == before,
        "unsupported storage contract reached executor construction"
    );
    Ok(json!({"rejected_before_construction": checked}))
}
