use anyhow::{Context, Result, ensure};
use libsql::{Connection, params};

use crate::protocol::coordinator::certified_decision::proof_stream::ProofVerifier;
use crate::protocol::coordinator::certified_decision::{CommitteeRecord, Decision};

const PAGE_BYTES: usize = 1_048_576;

pub(super) async fn verify(
    conn: &Connection,
    decision: &Decision,
    authority: &CommitteeRecord,
    length: usize,
    augmentation: bool,
) -> Result<()> {
    let mut verifier = ProofVerifier::for_decision(decision, length, authority)?;
    let query = if augmentation {
        "SELECT substr(proof_augmentation, ?2, ?3) FROM certified_decisions WHERE height = ?1"
    } else {
        "SELECT substr(original_proof, ?2, ?3) FROM certified_decisions WHERE height = ?1"
    };
    let mut offset = 0usize;
    while offset < length {
        let count = PAGE_BYTES.min(length - offset);
        let row = conn
            .query(
                query,
                params![
                    decision.height.to_be_bytes().to_vec(),
                    i64::try_from(offset)?
                        .checked_add(1)
                        .context("proof offset overflow")?,
                    i64::try_from(count)?
                ],
            )
            .await?
            .next()
            .await?
            .context("retained certificate unavailable")?;
        let bytes: Vec<u8> = row.get(0)?;
        ensure!(bytes.len() == count, "retained certificate length changed");
        verifier.push(&bytes)?;
        offset += count;
    }
    verifier.finish()
}
