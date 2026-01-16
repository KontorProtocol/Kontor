#![no_std]
contract!(name = "filestorage");

use alloc::collections::BTreeSet;
use stdlib::*;

// ─────────────────────────────────────────────────────────────────
// Protocol Constants
// ─────────────────────────────────────────────────────────────────

/// Minimum number of storage nodes required for an agreement to be active
const DEFAULT_MIN_NODES: u64 = 3;

/// Number of blocks a storage node has to respond to a challenge (~2 weeks at 10 min/block)
const DEFAULT_CHALLENGE_DEADLINE_BLOCKS: u64 = 2016;

/// Target challenges per file per year
const DEFAULT_C_TARGET: u64 = 12;

/// Default Bitcoin blocks per year - ~52560 at 10 min/block
const DEFAULT_BLOCKS_PER_YEAR: u64 = 52560;

/// Number of sectors/symbols sampled per challenge
const DEFAULT_S_CHAL: u64 = 100;

// ─────────────────────────────────────────────────────────────────
// State Types
// ─────────────────────────────────────────────────────────────────

#[derive(Clone, Default, Storage)]
struct AgreementNodes {
    /// node_id -> is_active (true means active, false means left)
    pub nodes: Map<String, bool>,
    pub node_count: u64,
}

#[derive(Clone, Default, StorageRoot)]
struct ProtocolState {
    pub min_nodes: u64,
    pub challenge_deadline_blocks: u64,
    pub c_target: u64,
    pub s_chal: u64,
    pub blocks_per_year: u64,
    pub agreements: Map<String, AgreementData>,
    pub agreement_nodes: Map<String, AgreementNodes>,
    pub agreement_count: u64,
    pub challenges: Map<String, ChallengeData>,
}

// ─────────────────────────────────────────────────────────────────
// Contract Implementation
// ─────────────────────────────────────────────────────────────────

impl Guest for Filestorage {
    fn init(ctx: &ProcContext) {
        ProtocolState {
            min_nodes: DEFAULT_MIN_NODES,
            challenge_deadline_blocks: DEFAULT_CHALLENGE_DEADLINE_BLOCKS,
            c_target: DEFAULT_C_TARGET,
            s_chal: DEFAULT_S_CHAL,
            blocks_per_year: DEFAULT_BLOCKS_PER_YEAR,
            agreements: Map::default(),
            agreement_nodes: Map::default(),
            agreement_count: 0,
            challenges: Map::default(),
        }
        .init(ctx);
    }

    fn create_agreement(
        ctx: &ProcContext,
        descriptor: RawFileDescriptor,
    ) -> Result<CreateAgreementResult, Error> {
        // Validate inputs
        if descriptor.file_id.is_empty() {
            return Err(Error::Message("file_id cannot be empty".to_string()));
        }
        if descriptor.padded_len == 0 || !descriptor.padded_len.is_power_of_two() {
            return Err(Error::Message(
                "padded_len must be a positive power of 2".to_string(),
            ));
        }

        let model = ctx.model();

        // Check for duplicate agreement
        let agreement_id = descriptor.file_id.clone();
        if model.agreements().get(&agreement_id).is_some() {
            return Err(Error::Message(format!(
                "agreement already exists for file_id: {}",
                agreement_id
            )));
        }

        // Validate and register with the FileLedger host function
        let fd: file_registry::FileDescriptor =
            file_registry::FileDescriptor::from_raw(&descriptor)?;
        file_registry::add_file(&fd);

        // Create the agreement (starts inactive until nodes join)
        let agreement = AgreementData {
            agreement_id: agreement_id.clone(),
            file_id: descriptor.file_id.clone(),
            active: false,
        };

        // Store the agreement and initialize node tracking
        model.agreements().set(agreement_id.clone(), agreement);
        model
            .agreement_nodes()
            .set(agreement_id.clone(), AgreementNodes::default());

        // Increment count
        model.update_agreement_count(|c| c + 1);

        Ok(CreateAgreementResult { agreement_id })
    }

    fn get_agreement(ctx: &ViewContext, agreement_id: String) -> Option<AgreementData> {
        ctx.model()
            .agreements()
            .get(&agreement_id)
            .map(|a| a.load())
    }

    fn agreement_count(ctx: &ViewContext) -> u64 {
        ctx.model().agreement_count()
    }

    fn get_all_active_agreements(ctx: &ViewContext) -> Vec<AgreementData> {
        let model = ctx.model();
        model
            .agreements()
            .keys::<String>()
            .filter_map(|agreement_id: String| {
                let agreement = model.agreements().get(&agreement_id)?;
                if !agreement.active() {
                    return None;
                }
                Some(agreement.load())
            })
            .collect()
    }

    fn join_agreement(
        ctx: &ProcContext,
        agreement_id: String,
        node_id: String,
    ) -> Result<JoinAgreementResult, Error> {
        let model = ctx.model();

        // Validate agreement exists
        let agreement = model
            .agreements()
            .get(&agreement_id)
            .ok_or(Error::Message(format!(
                "agreement not found: {}",
                agreement_id
            )))?;
        let nodes_state = model
            .agreement_nodes()
            .get(&agreement_id)
            .ok_or(Error::Message(format!(
                "agreement nodes not found: {}",
                agreement_id
            )))?;

        // Check if node is already active in agreement
        if nodes_state.nodes().get(&node_id).unwrap_or(false) {
            return Err(Error::Message(format!(
                "node {} already in agreement {}",
                node_id, agreement_id
            )));
        }

        // Add node to agreement (or reactivate if previously left)
        nodes_state.nodes().set(node_id.clone(), true);

        // Increment node count
        nodes_state.update_node_count(|c| c + 1);
        let node_count = nodes_state.node_count();

        // Check if we should activate (only if not already active)
        let min_nodes = model.min_nodes();
        let activated = !agreement.active() && node_count >= min_nodes;

        if activated {
            agreement.set_active(true);
        }

        Ok(JoinAgreementResult {
            agreement_id,
            node_id,
            activated,
        })
    }

    fn leave_agreement(
        ctx: &ProcContext,
        agreement_id: String,
        node_id: String,
    ) -> Result<LeaveAgreementResult, Error> {
        let model = ctx.model();

        // Validate agreement exists
        let _agreement = model
            .agreements()
            .get(&agreement_id)
            .ok_or(Error::Message(format!(
                "agreement not found: {}",
                agreement_id
            )))?;
        let nodes_state = model
            .agreement_nodes()
            .get(&agreement_id)
            .ok_or(Error::Message(format!(
                "agreement nodes not found: {}",
                agreement_id
            )))?;

        // Validate node is active in agreement
        if !nodes_state.nodes().get(&node_id).unwrap_or(false) {
            return Err(Error::Message(format!(
                "node {} not in agreement {}",
                node_id, agreement_id
            )));
        }

        // Mark node as inactive (don't delete, just set to false)
        nodes_state.nodes().set(node_id.clone(), false);

        // Decrement node count
        nodes_state.update_node_count(|c| c.saturating_sub(1));

        Ok(LeaveAgreementResult {
            agreement_id,
            node_id,
        })
    }

    fn get_agreement_nodes(ctx: &ViewContext, agreement_id: String) -> Vec<NodeInfo> {
        ctx.model()
            .agreement_nodes()
            .get(&agreement_id)
            .map(|s| {
                // Return all nodes we’ve seen, including inactive ones
                s.nodes()
                    .keys()
                    .map(|node_id: String| NodeInfo {
                        node_id: node_id.clone(),
                        active: s.nodes().get(&node_id).unwrap_or(false),
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn is_node_in_agreement(ctx: &ViewContext, agreement_id: String, node_id: String) -> bool {
        ctx.model()
            .agreement_nodes()
            .get(&agreement_id)
            .map(|s| s.nodes().get(&node_id).unwrap_or(false))
            .unwrap_or(false)
    }

    fn get_min_nodes(ctx: &ViewContext) -> u64 {
        ctx.model().min_nodes()
    }

    // ─────────────────────────────────────────────────────────────────
    // Challenge Management
    // ─────────────────────────────────────────────────────────────────

    fn get_challenge(ctx: &ViewContext, challenge_id: String) -> Option<ChallengeData> {
        ctx.model()
            .challenges()
            .get(&challenge_id)
            .map(|c| c.load())
    }

    fn get_active_challenges(ctx: &ViewContext) -> Vec<ChallengeData> {
        let model = ctx.model();
        model
            .challenges()
            .keys()
            .filter_map(|challenge_id: String| {
                let c = model.challenges().get(&challenge_id)?;
                if c.status().load() != ChallengeStatus::Active {
                    return None;
                }
                Some(c.load())
            })
            .collect()
    }

    fn expire_challenges(ctx: &ProcContext, current_height: u64) {
        let model = ctx.model();

        // Iterate through all challenges and expire those past deadline
        for challenge_id in model.challenges().keys::<String>() {
            if let Some(challenge) = model.challenges().get(&challenge_id)
                && challenge.status().load() == ChallengeStatus::Active
                && challenge.deadline_height() <= current_height
            {
                challenge.set_status(ChallengeStatus::Expired);
            }
        }
    }

    // ─────────────────────────────────────────────────────────────────
    // Challenge Generation
    // ─────────────────────────────────────────────────────────────────

    fn generate_challenges_for_block(
        ctx: &ProcContext,
        block_height: u64,
        prev_block_hash: Vec<u8>,
    ) -> Vec<ChallengeData> {
        let model = ctx.model();
        let mut new_challenges = Vec::new();

        // Exclude any agreement_id that already has an active challenge.
        let challenged_agreement_ids: Vec<String> = model
            .challenges()
            .keys()
            .filter_map(|cid: String| {
                let c = model.challenges().get(&cid)?;
                (c.status().load() == ChallengeStatus::Active).then(|| c.agreement_id())
            })
            .collect();

        // Get eligible agreements: active and agreement not already challenged
        let eligible_agreement_ids: Vec<String> = model
            .agreements()
            .keys::<String>()
            .filter(|aid: &String| {
                model
                    .agreements()
                    .get(aid)
                    .is_some_and(|a| a.active() && !challenged_agreement_ids.contains(aid))
            })
            .collect();

        let total_files = eligible_agreement_ids.len();
        if total_files == 0 {
            return new_challenges;
        }

        // Derive deterministic seed from block hash for agreement selection
        let agreement_seed = derive_seed(&prev_block_hash, b"agreement_selection");
        let mut rng_counter: u64 = 0;

        // Calculate expected number of challenges: θ(t) = (C_target * |F|) / B
        let c_target = model.c_target();
        let blocks_per_year = model.blocks_per_year();

        // Stochastic component: add one more challenge with probability (expected - base)
        let roll = uniform_index(
            &agreement_seed,
            &mut rng_counter,
            b"roll",
            blocks_per_year as usize,
        ) as u64;
        let num_to_challenge =
            compute_num_to_challenge(c_target, total_files, blocks_per_year, roll);

        if num_to_challenge == 0 {
            return new_challenges;
        }

        // Don't try to challenge more agreements than exist
        let num_to_challenge = core::cmp::min(num_to_challenge, total_files);

        // Select random unique agreement indices (rejection sampling avoids modulo bias)
        let mut selected_indices = BTreeSet::new();
        let eligible_len = eligible_agreement_ids.len();
        if num_to_challenge == eligible_len {
            for i in 0..eligible_len {
                selected_indices.insert(i);
            }
        } else {
            while selected_indices.len() < num_to_challenge {
                let index =
                    uniform_index(&agreement_seed, &mut rng_counter, b"select", eligible_len);
                selected_indices.insert(index);
            }
        }

        // Derive batch seed for all challenges in this block
        let batch_seed = derive_seed(&prev_block_hash, b"batch_seed");
        let seed: Vec<u8> = batch_seed.to_vec();

        let s_chal = model.s_chal();
        let deadline_height = block_height + model.challenge_deadline_blocks();

        // Create challenges for selected agreements
        for index in selected_indices {
            let agreement_id = &eligible_agreement_ids[index];
            let agreement = match model.agreements().get(agreement_id) {
                Some(a) => a,
                None => continue,
            };

            // Get active nodes for this agreement
            let nodes_state = match model.agreement_nodes().get(agreement_id) {
                Some(s) => s,
                None => continue,
            };
            let active_nodes: Vec<String> = nodes_state
                .nodes()
                .keys::<String>()
                .filter(|nid: &String| nodes_state.nodes().get(nid).unwrap_or(false))
                .collect();

            if active_nodes.is_empty() {
                continue;
            }

            // Deterministically select one node (agreement-level exclusion ensures we create
            // at most 1 active challenge per agreement total).
            let file_id = agreement.file_id();
            let node_seed_input = [prev_block_hash.as_slice(), b":", file_id.as_bytes()].concat();
            let node_seed = derive_seed(&node_seed_input, b"node_selection");
            let mut node_counter: u64 = 0;
            let node_index =
                uniform_index(&node_seed, &mut node_counter, b"node", active_nodes.len());
            let prover_id = active_nodes[node_index].clone();

            let descriptor = match file_registry::get_file_descriptor(&file_id) {
                Some(d) => d,
                None => continue,
            };

            // Compute challenge ID via file descriptor method
            let challenge_id =
                match descriptor.compute_challenge_id(block_height, s_chal, &seed, &prover_id) {
                    Ok(id) => id,
                    Err(_) => continue,
                };

            let challenge = ChallengeData {
                challenge_id,
                agreement_id: agreement_id.clone(),
                block_height,
                num_challenges: s_chal,
                seed: seed.clone(),
                prover_id,
                deadline_height,
                status: ChallengeStatus::Active,
            };
            model
                .challenges()
                .set(challenge.challenge_id.clone(), challenge.clone());

            new_challenges.push(challenge);
        }

        new_challenges
    }

    /// Create a challenge for a specific agreement and node.
    /// This is primarily for testing to avoid probabilistic challenge generation.
    fn create_challenge_for_agreement(
        ctx: &ProcContext,
        agreement_id: String,
        node_id: String,
        block_height: u64,
        seed: Vec<u8>,
    ) -> Result<ChallengeData, Error> {
        let model = ctx.model();

        // Validate agreement exists and is active
        let agreement = model
            .agreements()
            .get(&agreement_id)
            .ok_or(Error::Message(format!(
                "Agreement not found: {}",
                agreement_id
            )))?;

        if !agreement.active() {
            return Err(Error::Message(format!(
                "Agreement {} is not active",
                agreement_id
            )));
        }

        // Validate node is in agreement
        let nodes_state = model
            .agreement_nodes()
            .get(&agreement_id)
            .ok_or(Error::Message("No nodes for agreement".to_string()))?;

        let is_active = nodes_state.nodes().get(&node_id).unwrap_or(false);
        if !is_active {
            return Err(Error::Message(format!(
                "Node {} is not active in agreement {}",
                node_id, agreement_id
            )));
        }

        // Check no active challenge already exists for this agreement
        let has_active = model.challenges().keys().any(|cid: String| {
            model.challenges().get(&cid).is_some_and(|c| {
                c.status().load() == ChallengeStatus::Active && c.agreement_id() == agreement_id
            })
        });
        if has_active {
            return Err(Error::Message(format!(
                "Agreement {} already has an active challenge",
                agreement_id
            )));
        }

        // Validate seed length
        if seed.len() != 32 {
            return Err(Error::Message(format!(
                "Seed must be 32 bytes, got {}",
                seed.len()
            )));
        }

        let file_id = agreement.file_id();
        let s_chal = model.s_chal();
        let deadline_height = block_height + model.challenge_deadline_blocks();

        let descriptor = file_registry::get_file_descriptor(&file_id).ok_or(Error::Message(
            format!("File descriptor not found for {}", file_id),
        ))?;

        let challenge_id =
            descriptor.compute_challenge_id(block_height, s_chal, &seed, &node_id)?;

        let challenge = ChallengeData {
            challenge_id,
            agreement_id,
            block_height,
            num_challenges: s_chal,
            seed,
            prover_id: node_id,
            deadline_height,
            status: ChallengeStatus::Active,
        };

        model
            .challenges()
            .set(challenge.challenge_id.clone(), challenge.clone());

        Ok(challenge)
    }

    fn get_c_target(ctx: &ViewContext) -> u64 {
        ctx.model().c_target()
    }

    fn get_blocks_per_year(ctx: &ViewContext) -> u64 {
        ctx.model().blocks_per_year()
    }

    fn get_s_chal(ctx: &ViewContext) -> u64 {
        ctx.model().s_chal()
    }

    // ─────────────────────────────────────────────────────────────────
    // Proof Verification
    // ─────────────────────────────────────────────────────────────────

    fn verify_proof(ctx: &ProcContext, proof_bytes: Vec<u8>) -> Result<VerifyProofResult, Error> {
        let model = ctx.model();

        // 1. Deserialize proof (single deserialization via host resource)
        let proof = file_registry::Proof::from_bytes(&proof_bytes)?;

        // 2. Get challenge IDs from proof
        let challenge_ids = proof.challenge_ids();
        if challenge_ids.is_empty() {
            return Err(Error::Message("Proof contains no challenges".to_string()));
        }

        // 3. Build challenge inputs from contract storage
        let mut challenge_inputs = Vec::new();
        for cid in &challenge_ids {
            let challenge = model
                .challenges()
                .get(cid)
                .ok_or(Error::Message(format!("Challenge not found: {}", cid)))?;

            // Only accept proofs for active challenges
            if challenge.status().load() != ChallengeStatus::Active {
                return Err(Error::Message(format!(
                    "Challenge {} is not active (status: {:?})",
                    cid,
                    challenge.status().load()
                )));
            }

            // Get file_id from agreement
            let agreement =
                model
                    .agreements()
                    .get(challenge.agreement_id())
                    .ok_or(Error::Message(format!(
                        "Agreement not found: {}",
                        challenge.agreement_id()
                    )))?;

            challenge_inputs.push(file_registry::ChallengeInput {
                challenge_id: cid.clone(),
                file_id: agreement.file_id(),
                block_height: challenge.block_height(),
                num_challenges: challenge.num_challenges(),
                seed: challenge.seed(),
                prover_id: challenge.prover_id(),
            });
        }

        // 4. Verify the proof
        let result = proof.verify(&challenge_inputs)?;

        // 5. Update challenge statuses based on result
        let new_status = match result {
            file_registry::VerifyResult::Verified => ChallengeStatus::Proven,
            file_registry::VerifyResult::Rejected => ChallengeStatus::Failed,
            file_registry::VerifyResult::Invalid => ChallengeStatus::Invalid,
        };

        for cid in &challenge_ids {
            if let Some(c) = model.challenges().get(cid) {
                c.set_status(new_status);
            }
        }

        Ok(VerifyProofResult {
            verified_count: challenge_ids.len() as u64,
        })
    }
}

// ─────────────────────────────────────────────────────────────────
// Helper Functions
// ─────────────────────────────────────────────────────────────────

/// Compute the number of agreements to challenge for this block using:
///   θ(t) = (C_target * |F|) / B
///
/// We compute `base = floor((C_target * |F|)/B)` and then add 1 with probability equal to
/// the fractional remainder, using `roll_mod_1000` (0..999) as the deterministic RNG roll.
pub fn compute_num_to_challenge(
    c_target: u64,
    total_files: usize,
    blocks_per_year: u64,
    roll: u64,
) -> usize {
    if total_files == 0 || blocks_per_year == 0 {
        return 0;
    }

    let total_files_u64 = total_files as u64;
    let expected_challenges_scaled = c_target * total_files_u64;
    let num_challenges_base = expected_challenges_scaled / blocks_per_year;

    let remainder = expected_challenges_scaled % blocks_per_year;
    // Match simulation behavior: add one more with probability remainder / blocks_per_year.
    // We do this deterministically by drawing a roll in [0, blocks_per_year) and checking roll < remainder.
    let roll = roll % blocks_per_year;
    let num = if roll < remainder {
        num_challenges_base + 1
    } else {
        num_challenges_base
    };

    core::cmp::min(num, total_files_u64) as usize
}

/// Derive a 32-byte seed using HKDF-SHA256 via host function
pub fn derive_seed(ikm: &[u8], info: &[u8]) -> [u8; 32] {
    // Use HKDF host function
    // info is used as the "info" parameter (application-specific context)
    // We use "kontor/hkdf/" prefix for domain separation
    let full_info = [b"kontor/hkdf/".as_slice(), info].concat();
    let derived = crypto::hkdf_derive(ikm, &[], &full_info);

    // Convert to fixed-size array
    let mut result = [0u8; 32];
    let len = core::cmp::min(derived.len(), 32);
    result[..len].copy_from_slice(&derived[..len]);
    result
}

/// Deterministically derive a u64 from a 32-byte seed using HKDF-SHA256 via host function.
/// `counter` is used as the HKDF salt to produce a stable stream of outputs.
pub fn seeded_u64(seed: &[u8; 32], counter: &mut u64, info: &[u8]) -> u64 {
    let full_info = [b"kontor/rng/".as_slice(), info].concat();
    let salt = counter.to_le_bytes();
    let bs = crypto::hkdf_derive(seed, &salt, &full_info);
    let mut b8 = [0u8; 8];
    b8.copy_from_slice(&bs[..8]);
    *counter = counter.wrapping_add(1);
    u64::from_le_bytes(b8)
}

/// Generate unbiased random index in range [0, n) using rejection sampling
pub fn uniform_index(seed: &[u8; 32], counter: &mut u64, info: &[u8], n: usize) -> usize {
    uniform_index_from_u64(n, &mut || seeded_u64(seed, counter, info))
}

/// Generate unbiased random index in range [0, n) using rejection sampling.
///
/// This is a pure helper that can be unit-tested without host functions.
pub fn uniform_index_from_u64(n: usize, next_u64: &mut impl FnMut() -> u64) -> usize {
    if n == 0 {
        return 0;
    }

    let n_u64 = n as u64;

    // Find the largest multiple of n that fits in u64.
    // This is the threshold below which all values are unbiased.
    let limit = u64::MAX - (u64::MAX % n_u64);

    loop {
        let rand_val = next_u64();
        if rand_val < limit {
            return (rand_val % n_u64) as usize;
        }
        // Otherwise reject and generate a new value
    }
}

#[cfg(test)]
mod tests {
    use super::{compute_num_to_challenge, uniform_index_from_u64};

    #[test]
    fn theta_total_files_zero() {
        assert_eq!(compute_num_to_challenge(12, 0, 52560, 0), 0);
    }

    #[test]
    fn theta_blocks_per_year_zero() {
        assert_eq!(compute_num_to_challenge(12, 10, 0, 0), 0);
    }

    #[test]
    fn theta_threshold_zero_always_zero_with_defaults_for_small_f() {
        // With defaults, total_files=4 => expected_scaled=48,
        // base=0, remainder=48 => +1 with probability 48/52560.
        assert_eq!(compute_num_to_challenge(12, 4, 52560, 0), 1); // roll < remainder
        assert_eq!(compute_num_to_challenge(12, 4, 52560, 47), 1);
        assert_eq!(compute_num_to_challenge(12, 4, 52560, 48), 0); // roll >= remainder
        assert_eq!(compute_num_to_challenge(12, 4, 52560, 52559), 0);
    }

    #[test]
    fn theta_threshold_positive_branches() {
        // total_files=100 => expected_scaled=1200
        // base=0, remainder=1200
        assert_eq!(compute_num_to_challenge(12, 100, 52560, 0), 1);
        assert_eq!(compute_num_to_challenge(12, 100, 52560, 1199), 1);
        assert_eq!(compute_num_to_challenge(12, 100, 52560, 1200), 0);
        assert_eq!(compute_num_to_challenge(12, 100, 52560, 52559), 0);
    }

    #[test]
    fn theta_base_and_remainder_cases_with_small_blocks_per_year() {
        // Use a small blocks_per_year to exercise base>0 without requiring huge |F|.
        // expected_scaled = 3*10=30, base=3, remainder=0 => always 3
        for roll in [0u64, 999] {
            assert_eq!(compute_num_to_challenge(3, 10, 10, roll), 3);
        }

        // expected_scaled = 3*12=36, base=3, remainder=6 => +1 when roll%10 < 6
        assert_eq!(compute_num_to_challenge(3, 12, 10, 0), 4);
        assert_eq!(compute_num_to_challenge(3, 12, 10, 5), 4);
        assert_eq!(compute_num_to_challenge(3, 12, 10, 6), 3);
        assert_eq!(compute_num_to_challenge(3, 12, 10, 9), 3);
    }

    #[test]
    fn theta_caps_to_total_files() {
        // expected_scaled = 12*10=120, base=12, remainder=0 => 12 but cap to total_files=10
        assert_eq!(compute_num_to_challenge(12, 10, 10, 0), 10);
    }

    #[test]
    fn uniform_index_n_zero_returns_zero() {
        let mut next = || 123u64;
        assert_eq!(uniform_index_from_u64(0, &mut next), 0);
    }

    #[test]
    fn uniform_index_returns_in_range() {
        let mut next = || 123u64;
        let idx = uniform_index_from_u64(10, &mut next);
        assert!(idx < 10);
    }

    #[test]
    fn uniform_index_rejects_values_at_or_above_limit() {
        // For n=10: any value >= limit should be rejected.
        let n = 10usize;
        let n_u64 = n as u64;
        let limit = u64::MAX - (u64::MAX % n_u64);

        // First draw is rejected, second draw should be accepted.
        let mut calls = 0u64;
        let mut next = || {
            calls += 1;
            if calls == 1 {
                limit // rejected (rand_val < limit must hold)
            } else {
                7 // accepted => 7 % 10 = 7
            }
        };

        assert_eq!(uniform_index_from_u64(n, &mut next), 7);
        assert_eq!(calls, 2);
    }
}
