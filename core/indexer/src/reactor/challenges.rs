//! Reactor-native challenge generation and expiry. This is the host-side port
//! of what `filestorage` used to do in-contract: every block it derives a
//! deterministic set of challenges from `(block_hash, active agreements,
//! members)` and writes them to the host challenge ledger. The contract keeps
//! only the economic layer (agreements + memberships), which the reactor reads
//! through its view exports.
//!
//! The seed/selection math is byte-identical to the former in-contract version
//! (HKDF-SHA256 64-byte streams, rejection sampling) — it must be, since the
//! challenge ids it produces are consensus state and are verified by proofs.

use std::collections::{BTreeSet, HashSet};

use anyhow::{Context, Result};
use hkdf::Hkdf;
use sha2::Sha256;

use crate::database::queries::{
    append_challenge_status, get_active_challenge_agreement_ids, get_overdue_active_challenges,
    insert_challenge,
};
use crate::database::types::{ChallengeRow, ChallengeStatus};
use crate::runtime::Runtime;
use crate::runtime::filestorage::api::{get_agreement_nodes, get_all_active_agreements};

/// Number of agreements challenged per file per year (target rate).
const C_TARGET: u64 = 12;
/// Bitcoin blocks per year (~10 min/block).
const BLOCKS_PER_YEAR: u64 = 52560;
/// Blocks a node has to answer a challenge (~2 weeks).
const DEADLINE_BLOCKS: u64 = 2016;
/// Sectors sampled per challenge on production networks.
const S_CHAL: u64 = 100;
/// Smaller sample count on regtest — the Nova prover cost is ~linear in it, so
/// this keeps dev/test proof generation fast. Soundness only matters on real
/// networks (cf. token dev-mint conditioning on `network()`).
const REGTEST_S_CHAL: u64 = 8;
/// On regtest, challenge every eligible file each block (so a single mined block
/// deterministically produces challenges to test against) rather than spreading
/// them across a production-length year.
const REGTEST_BLOCKS_PER_YEAR: u64 = 1;

fn s_chal_for(network: bitcoin::Network) -> u64 {
    if network == bitcoin::Network::Regtest {
        REGTEST_S_CHAL
    } else {
        S_CHAL
    }
}

fn blocks_per_year_for(network: bitcoin::Network) -> u64 {
    if network == bitcoin::Network::Regtest {
        REGTEST_BLOCKS_PER_YEAR
    } else {
        BLOCKS_PER_YEAR
    }
}

// ── Deterministic primitives (identical to the former contract helpers) ──

/// HKDF-SHA256 → 64 bytes. Mirrors the `crypto::hkdf-derive` host function
/// (empty salt ⇒ `None`), so reactor and (former) contract derivations match.
fn hkdf64(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 64] {
    let salt = if salt.is_empty() { None } else { Some(salt) };
    let hk = Hkdf::<Sha256>::new(salt, ikm);
    let mut okm = [0u8; 64];
    hk.expand(info, &mut okm).expect("HKDF expand 64 bytes");
    okm
}

/// Per-block batch seed: `σ_batch = HKDF(block_hash, "KONTOR-CHAL::v1" || height)`.
fn derive_batch_seed(block_hash: &[u8], block_height: u64) -> [u8; 64] {
    let info = [b"KONTOR-CHAL::v1".as_slice(), &block_height.to_le_bytes()].concat();
    hkdf64(block_hash, &[], &info)
}

fn derive_stream_seed(sigma_batch: &[u8; 64], domain: &[u8]) -> [u8; 64] {
    let info = [b"KONTOR-CHAL-STREAM::v1/".as_slice(), domain].concat();
    hkdf64(sigma_batch, &[], &info)
}

fn derive_stream_seed_for_file(sigma_batch: &[u8; 64], domain: &[u8], file_id: &str) -> [u8; 64] {
    let info = [b"KONTOR-CHAL-STREAM::v1/".as_slice(), domain].concat();
    hkdf64(sigma_batch, file_id.as_bytes(), &info)
}

fn derive_challenge_seed_for_file(sigma_batch: &[u8; 64], file_id: &str) -> [u8; 64] {
    hkdf64(sigma_batch, file_id.as_bytes(), b"KONTOR-SEED::v1")
}

/// Deterministic u64 stream from a 64-byte seed; `counter` is the HKDF salt.
fn seeded_u64(seed: &[u8; 64], counter: &mut u64, domain: &[u8]) -> u64 {
    let info = [b"KONTOR-RNG::v1/".as_slice(), domain].concat();
    let derived = hkdf64(seed, &counter.to_le_bytes(), &info);
    *counter = counter.wrapping_add(1);
    u64::from_le_bytes(derived[..8].try_into().expect("8 bytes"))
}

/// Unbiased index in `[0, n)` via rejection sampling.
fn uniform_index(seed: &[u8; 64], counter: &mut u64, info: &[u8], n: usize) -> usize {
    if n == 0 {
        return 0;
    }
    let n_u64 = n as u64;
    let limit = u64::MAX - (u64::MAX % n_u64);
    loop {
        let v = seeded_u64(seed, counter, info);
        if v < limit {
            return (v % n_u64) as usize;
        }
    }
}

/// θ(t) = floor(C_target·|F| / B), plus one with probability equal to the
/// fractional remainder (deterministic via `roll`).
fn compute_num_to_challenge(
    c_target: u64,
    total_files: usize,
    blocks_per_year: u64,
    roll: u64,
) -> usize {
    if total_files == 0 || blocks_per_year == 0 {
        return 0;
    }
    let total = total_files as u64;
    let scaled = c_target * total;
    let base = scaled / blocks_per_year;
    let remainder = scaled % blocks_per_year;
    let num = if (roll % blocks_per_year) < remainder {
        base + 1
    } else {
        base
    };
    core::cmp::min(num, total) as usize
}

/// A challenge the reactor decided to issue this block, resolved enough to write
/// (the file descriptor lookup + id computation happen in a second pass to keep
/// the `&mut Runtime` view reads and the `&Runtime` ledger writes from
/// overlapping).
struct PendingChallenge {
    agreement_id: String,
    file_id: String,
    prover_id: u64,
    seed: Vec<u8>,
}

/// Generate this block's challenges and write them to the ledger. Returns the
/// number issued.
pub async fn generate_challenges_for_block(
    runtime: &mut Runtime,
    block_height: u64,
    block_hash: &[u8],
) -> Result<u64> {
    let s_chal = s_chal_for(runtime.network);
    let blocks_per_year = blocks_per_year_for(runtime.network);

    // Read economic state through the contract's view exports.
    let agreements = get_all_active_agreements(runtime)
        .await
        .context("read active agreements")?;
    if agreements.is_empty() {
        return Ok(0);
    }

    // Eligible = active and not already under a live challenge.
    let challenged: HashSet<String> =
        get_active_challenge_agreement_ids(&runtime.storage.conn)
            .await?
            .into_iter()
            .collect();
    let eligible: Vec<_> = agreements
        .into_iter()
        .filter(|a| !challenged.contains(&a.agreement_id))
        .collect();
    let total_files = eligible.len();
    if total_files == 0 {
        return Ok(0);
    }

    let sigma_batch = derive_batch_seed(block_hash, block_height);
    let agreement_seed = derive_stream_seed(&sigma_batch, b"agreement_selection");
    let mut counter = 0u64;
    let roll = uniform_index(
        &agreement_seed,
        &mut counter,
        b"roll",
        blocks_per_year as usize,
    ) as u64;
    let num_to_challenge = compute_num_to_challenge(C_TARGET, total_files, blocks_per_year, roll);
    if num_to_challenge == 0 {
        return Ok(0);
    }

    // Select unique agreement indices (rejection sampling avoids modulo bias).
    let mut selected = BTreeSet::new();
    if num_to_challenge >= total_files {
        selected.extend(0..total_files);
    } else {
        while selected.len() < num_to_challenge {
            selected.insert(uniform_index(
                &agreement_seed,
                &mut counter,
                b"select",
                total_files,
            ));
        }
    }

    // Pass 1 (view reads): pick one member per selected agreement and derive the
    // per-file challenge seed.
    let mut pending = Vec::new();
    for index in selected {
        let agreement = &eligible[index];
        let nodes = get_agreement_nodes(runtime, &agreement.agreement_id).await?;
        let active_nodes: Vec<&str> = nodes
            .iter()
            .filter(|n| n.active)
            .map(|n| n.node_id.as_str())
            .collect();
        if active_nodes.is_empty() {
            continue;
        }
        let node_seed =
            derive_stream_seed_for_file(&sigma_batch, b"node_selection", &agreement.file_id);
        let mut node_counter = 0u64;
        let node_index = uniform_index(&node_seed, &mut node_counter, b"node", active_nodes.len());
        // Membership is signer-keyed, so node_id is the prover's signer_id.
        let Ok(prover_id) = active_nodes[node_index].parse::<u64>() else {
            continue;
        };
        pending.push(PendingChallenge {
            agreement_id: agreement.agreement_id.clone(),
            file_id: agreement.file_id.clone(),
            prover_id,
            seed: derive_challenge_seed_for_file(&sigma_batch, &agreement.file_id).to_vec(),
        });
    }

    // Pass 2 (ledger writes): compute the challenge id and persist.
    let deadline_height = block_height + DEADLINE_BLOCKS;
    let mut created = 0u64;
    for p in pending {
        let Some(fd) = runtime
            .file_ledger
            .get_file_descriptor(&runtime.storage.conn, &p.file_id)
            .await?
        else {
            continue;
        };
        let challenge_id =
            match fd.compute_challenge_id(block_height, s_chal, &p.seed, p.prover_id) {
                Ok(id) => id,
                Err(_) => continue,
            };
        let row = ChallengeRow::builder()
            .challenge_id(challenge_id.clone())
            .prover_id(p.prover_id)
            .agreement_id(p.agreement_id)
            .num_challenges(s_chal)
            .seed(p.seed)
            .deadline_height(deadline_height)
            .height(block_height)
            .build();
        insert_challenge(&runtime.storage.conn, &row).await?;
        append_challenge_status(
            &runtime.storage.conn,
            &challenge_id,
            ChallengeStatus::Active,
            block_height,
        )
        .await?;
        created += 1;
    }
    Ok(created)
}

/// Expire active challenges whose deadline has passed. Returns the number expired.
pub async fn expire_challenges(runtime: &Runtime, current_height: u64) -> Result<u64> {
    let overdue = get_overdue_active_challenges(&runtime.storage.conn, current_height).await?;
    let count = overdue.len() as u64;
    for c in overdue {
        append_challenge_status(
            &runtime.storage.conn,
            &c.challenge_id,
            ChallengeStatus::Expired,
            current_height,
        )
        .await?;
    }
    Ok(count)
}
