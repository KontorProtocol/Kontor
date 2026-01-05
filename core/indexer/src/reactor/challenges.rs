//! Challenge generation and processing for the file storage protocol.
//!
//! This module handles:
//! - Deterministic challenge generation based on block hash
//! - HKDF-based seed derivation for reproducible randomness
//! - Integration with kontor-crypto's Challenge type
//! - Expiration processing for unanswered challenges

use anyhow::Result;
use ff::FromUniformBytes;
use hkdf::Hkdf;
use kontor_crypto::{Challenge as CryptoChallenge, FieldElement, FileMetadata};
use libsql::Connection;
use rand::{Rng, SeedableRng};
use rand_chacha::ChaCha8Rng;
use sha2::Sha256;
use tracing::info;

use crate::database::{
    queries::{expire_challenges_at_height, insert_challenge},
    types::{ChallengeRow, ChallengeStatus},
};

/// Configuration for challenge generation
pub struct ChallengeConfig {
    /// Target number of challenges per file per year (C_target from protocol)
    pub c_target: f64,
    /// Blocks per year (approximately 52560 at 10 min/block)
    pub blocks_per_year: u64,
    /// Number of blocks a node has to respond to a challenge
    pub deadline_blocks: i64,
    /// Number of proof iterations per challenge (s_chal from protocol)
    pub num_challenges: usize,
}

impl Default for ChallengeConfig {
    fn default() -> Self {
        Self {
            c_target: 12.0,         // 12 challenges per file per year (monthly average)
            blocks_per_year: 52560, // ~10 min blocks
            deadline_blocks: 2016,  // ~2 weeks at 10 min/block
            num_challenges: 100,    // Number of proof iterations
        }
    }
}

/// Represents an active agreement with its file metadata for challenge selection
#[derive(Debug, Clone)]
pub struct ActiveAgreement {
    pub agreement_id: String,
    pub file_metadata: FileMetadata,
    pub nodes: Vec<String>,
}

/// Derive a deterministic 32-byte seed via HKDF (extract + expand).
///
/// - Extract: PRK = HMAC-SHA256(salt=domain_separator, IKM=master_seed)
/// - Expand:  HKDF-Expand with SHA256 and info="kontor/hkdf/" + domain
fn derive_seed_32(master_seed: &[u8], domain_separator: &str) -> [u8; 32] {
    let salt = domain_separator.as_bytes();
    let info = format!("kontor/hkdf/{}", domain_separator);

    let hk = Hkdf::<Sha256>::new(Some(salt), master_seed);
    let mut okm = [0u8; 32];
    hk.expand(info.as_bytes(), &mut okm)
        .expect("32 bytes is a valid length for HKDF-SHA256");
    okm
}

/// Derive a deterministic 64-byte seed for hash-to-field conversion.
fn derive_seed_64(master_seed: &[u8], domain_separator: &str) -> [u8; 64] {
    let salt = domain_separator.as_bytes();
    let info = format!("kontor/hkdf/{}", domain_separator);

    let hk = Hkdf::<Sha256>::new(Some(salt), master_seed);
    let mut okm = [0u8; 64];
    hk.expand(info.as_bytes(), &mut okm)
        .expect("64 bytes is a valid length for HKDF-SHA256");
    okm
}

/// Convert a 64-byte seed to a FieldElement using hash-to-field
fn seed_to_field_element(seed: &[u8; 64]) -> FieldElement {
    FieldElement::from_uniform_bytes(seed)
}

/// Create a seeded RNG from a 32-byte seed
fn seeded_rng(seed: &[u8; 32]) -> ChaCha8Rng {
    ChaCha8Rng::from_seed(*seed)
}

/// Generate challenges for a block.
///
/// This implements the challenge generation algorithm from the protocol:
/// - θ(t) = (C_target * |F(t)|) / B files are challenged per block
/// - Each file has probability p_f = C_target / B of being challenged
/// - If a file is challenged, one node is randomly selected from N_f
///
/// All randomness is derived deterministically from the block hash.
/// Challenges are created using kontor-crypto's Challenge type for ID computation.
pub async fn generate_challenges(
    conn: &Connection,
    block_height: i64,
    block_hash: &[u8; 32],
    active_agreements: &[ActiveAgreement],
    active_file_ids_with_challenges: &std::collections::HashSet<String>,
    config: &ChallengeConfig,
) -> Result<Vec<ChallengeRow>> {
    let mut generated = Vec::new();

    // Filter to eligible agreements (files without active challenges)
    let eligible_agreements: Vec<_> = active_agreements
        .iter()
        .filter(|a| !a.nodes.is_empty())
        .filter(|a| !active_file_ids_with_challenges.contains(&a.file_metadata.file_id))
        .collect();

    let total_files = eligible_agreements.len();
    if total_files == 0 {
        return Ok(generated);
    }

    // Calculate expected number of challenges this block: θ(t) = (C_target * |F(t)|) / B
    let expected_challenges =
        (config.c_target * total_files as f64) / config.blocks_per_year as f64;

    // Base number of challenges (integer part)
    let mut num_challenges = expected_challenges as usize;

    // Derive seed for agreement selection
    let agreement_seed = derive_seed_32(block_hash, "agreement_selection");
    let mut agreement_rng = seeded_rng(&agreement_seed);

    // Stochastic component: with probability (expected - floor), add one more
    let stochastic_threshold = expected_challenges - num_challenges as f64;
    if agreement_rng.random::<f64>() < stochastic_threshold {
        num_challenges += 1;
    }

    if num_challenges == 0 {
        return Ok(generated);
    }

    // Ensure we don't try to sample more agreements than exist
    num_challenges = num_challenges.min(total_files);

    // Sample agreements to challenge (Fisher-Yates partial shuffle)
    let mut indices: Vec<usize> = (0..total_files).collect();
    for i in 0..num_challenges {
        let j = agreement_rng.random_range(i..total_files);
        indices.swap(i, j);
    }
    let selected_indices = &indices[..num_challenges];

    // Derive batch seed for challenge data (64 bytes for hash-to-field)
    let batch_seed = derive_seed_64(block_hash, "batch_seed");
    let batch_seed_field = seed_to_field_element(&batch_seed);

    info!(
        "Block {}: Generating {} challenges for {}/{} eligible files (expected: {:.4})",
        block_height,
        num_challenges,
        total_files,
        active_agreements.len(),
        expected_challenges
    );

    // Create challenges for selected agreements
    for &idx in selected_indices {
        let agreement = &eligible_agreements[idx];

        // Derive node selection seed specific to this file
        let node_seed_input = format!(
            "{}:{}",
            hex::encode(block_hash),
            agreement.file_metadata.file_id
        );
        let node_seed = derive_seed_32(node_seed_input.as_bytes(), "node_selection");
        let mut node_rng = seeded_rng(&node_seed);

        // Select a random node
        let node_index = node_rng.random_range(0..agreement.nodes.len());
        let selected_node = &agreement.nodes[node_index];

        // Create the kontor-crypto Challenge to get deterministic ID
        let crypto_challenge = CryptoChallenge::new(
            agreement.file_metadata.clone(),
            block_height as u64,
            config.num_challenges,
            batch_seed_field,
            selected_node.clone(),
        );

        // Get the challenge ID from kontor-crypto
        let challenge_id = crypto_challenge.id();
        let challenge_id_hex = hex::encode(challenge_id.0);

        let challenge = ChallengeRow::builder()
            .challenge_id(challenge_id_hex)
            .agreement_id(agreement.agreement_id.clone())
            .file_id(agreement.file_metadata.file_id.clone())
            .node_id(selected_node.clone())
            .issued_height(block_height)
            .deadline_height(block_height + config.deadline_blocks)
            .status(ChallengeStatus::Pending)
            .build();

        insert_challenge(conn, &challenge).await?;
        generated.push(challenge);
    }

    Ok(generated)
}

/// Process expired challenges at the end of block processing.
///
/// Marks all pending challenges past their deadline as expired.
pub async fn process_expired_challenges(conn: &Connection, current_height: i64) -> Result<u64> {
    let expired_count = expire_challenges_at_height(conn, current_height).await?;

    if expired_count > 0 {
        info!(
            "Expired {} challenges at height {}",
            expired_count, current_height
        );
    }

    Ok(expired_count)
}
