#![no_std]
contract!(name = "filestorage");

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
struct FileMetadata {
    pub file_id: String,
    pub root: Vec<u8>,
    pub padded_len: u64,
    pub original_size: u64,
    pub filename: String,
}

/// A storage agreement for a file
/// nodes: Map<node_id, is_active> - true means active, false means left
#[derive(Clone, Default, Storage)]
struct Agreement {
    pub agreement_id: String,
    pub file_metadata: FileMetadata,
    pub active: bool,
    pub nodes: Map<String, bool>,
    pub node_count: u64,
}

#[derive(Clone, Copy, Default, PartialEq, Eq, Storage)]
enum ChallengeStatusStorage {
    #[default]
    Active,
    Proven,
    Expired,
    Failed,
}

impl From<ChallengeStatusStorage> for ChallengeStatus {
    fn from(s: ChallengeStatusStorage) -> Self {
        match s {
            ChallengeStatusStorage::Active => ChallengeStatus::Active,
            ChallengeStatusStorage::Proven => ChallengeStatus::Proven,
            ChallengeStatusStorage::Expired => ChallengeStatus::Expired,
            ChallengeStatusStorage::Failed => ChallengeStatus::Failed,
        }
    }
}

/// A storage challenge - mirrors WIT challenge-data exactly
#[derive(Clone, Default, Storage)]
struct Challenge {
    pub challenge_id: String,
    pub agreement_id: String,
    pub file_metadata: FileMetadata,
    pub block_height: u64,
    pub num_challenges: u64,
    pub seed: Vec<u8>,
    pub prover_id: String,
    pub deadline_height: u64,
    pub status: ChallengeStatusStorage,
}

#[derive(Clone, Default, StorageRoot)]
struct ProtocolState {
    pub min_nodes: u64,
    pub challenge_deadline_blocks: u64,
    pub c_target: u64,
    pub s_chal: u64,
    pub blocks_per_year: u64,
    pub agreements: Map<String, Agreement>,
    pub agreement_count: u64,
    pub challenges: Map<String, Challenge>,
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
        let fd = file_ledger::FileDescriptor::from_raw(&descriptor)?;
        file_ledger::add_file(&fd);

        let file_metadata = FileMetadata {
            file_id: descriptor.file_id,
            root: descriptor.root,
            padded_len: descriptor.padded_len,
            original_size: descriptor.original_size,
            filename: descriptor.filename,
        };

        // Create the agreement (starts inactive until nodes join)
        let agreement = Agreement {
            agreement_id: agreement_id.clone(),
            file_metadata,
            active: false,
            nodes: Map::default(),
            node_count: 0,
        };

        // Store the agreement
        model.agreements().set(agreement_id.clone(), agreement);

        // Increment count
        model.update_agreement_count(|c| c + 1);

        Ok(CreateAgreementResult { agreement_id })
    }

    fn get_agreement(ctx: &ViewContext, agreement_id: String) -> Option<AgreementData> {
        ctx.model().agreements().get(&agreement_id).map(|a| {
            let fm = a.file_metadata();
            AgreementData {
                agreement_id: a.agreement_id(),
                file_metadata: FileMetadataData {
                    file_id: fm.file_id(),
                    root: fm.root(),
                    padded_len: fm.padded_len(),
                    original_size: fm.original_size(),
                    filename: fm.filename(),
                },
                active: a.active(),
            }
        })
    }

    fn agreement_count(ctx: &ViewContext) -> u64 {
        ctx.model().agreement_count()
    }

    fn get_all_active_agreements(ctx: &ViewContext) -> Vec<AgreementData> {
        let model = ctx.model();
        model
            .agreements()
            .keys()
            .filter_map(|agreement_id| {
                let agreement = model.agreements().get(&agreement_id)?;
                if !agreement.active() {
                    return None;
                }

                let fm = agreement.file_metadata();

                Some(AgreementData {
                    agreement_id,
                    file_metadata: FileMetadataData {
                        file_id: fm.file_id(),
                        root: fm.root(),
                        padded_len: fm.padded_len(),
                        original_size: fm.original_size(),
                        filename: fm.filename(),
                    },
                    active: agreement.active(),
                })
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

        // Check if node is already active in agreement
        if agreement.nodes().get(&node_id).unwrap_or(false) {
            return Err(Error::Message(format!(
                "node {} already in agreement {}",
                node_id, agreement_id
            )));
        }

        // Add node to agreement (or reactivate if previously left)
        agreement.nodes().set(node_id.clone(), true);

        // Increment node count
        agreement.update_node_count(|c| c + 1);
        let node_count = agreement.node_count();

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
        let agreement = model
            .agreements()
            .get(&agreement_id)
            .ok_or(Error::Message(format!(
                "agreement not found: {}",
                agreement_id
            )))?;

        // Validate node is active in agreement
        if !agreement.nodes().get(&node_id).unwrap_or(false) {
            return Err(Error::Message(format!(
                "node {} not in agreement {}",
                node_id, agreement_id
            )));
        }

        // Mark node as inactive (don't delete, just set to false)
        agreement.nodes().set(node_id.clone(), false);

        // Decrement node count
        agreement.update_node_count(|c| c.saturating_sub(1));

        Ok(LeaveAgreementResult {
            agreement_id,
            node_id,
        })
    }

    fn get_agreement_nodes(ctx: &ViewContext, agreement_id: String) -> Option<Vec<String>> {
        ctx.model().agreements().get(&agreement_id).map(|a| {
            // Collect only active nodes (value = true)
            a.nodes()
                .keys()
                .filter(|k: &String| a.nodes().get(k).unwrap_or(false))
                .collect()
        })
    }

    fn is_node_in_agreement(ctx: &ViewContext, agreement_id: String, node_id: String) -> bool {
        ctx.model()
            .agreements()
            .get(&agreement_id)
            .map(|a| a.nodes().get(&node_id).unwrap_or(false))
            .unwrap_or(false)
    }

    fn get_min_nodes(ctx: &ViewContext) -> u64 {
        ctx.model().min_nodes()
    }

    // ─────────────────────────────────────────────────────────────────
    // Challenge Management
    // ─────────────────────────────────────────────────────────────────

    fn get_challenge(ctx: &ViewContext, challenge_id: String) -> Option<ChallengeData> {
        ctx.model().challenges().get(&challenge_id).map(|c| {
            let fm = c.file_metadata();
            ChallengeData {
                challenge_id: c.challenge_id(),
                agreement_id: c.agreement_id(),
                file_metadata: FileMetadataData {
                    file_id: fm.file_id(),
                    root: fm.root(),
                    padded_len: fm.padded_len(),
                    original_size: fm.original_size(),
                    filename: fm.filename(),
                },
                block_height: c.block_height(),
                num_challenges: c.num_challenges(),
                seed: c.seed(),
                prover_id: c.prover_id(),
                deadline_height: c.deadline_height(),
                status: c.status().load().into(),
            }
        })
    }

    fn get_active_challenges(ctx: &ViewContext) -> Vec<ChallengeData> {
        let model = ctx.model();
        model
            .challenges()
            .keys()
            .filter_map(|challenge_id: String| {
                let c = model.challenges().get(&challenge_id)?;
                if c.status().load() != ChallengeStatusStorage::Active {
                    return None;
                }
                let fm = c.file_metadata();
                Some(ChallengeData {
                    challenge_id: c.challenge_id(),
                    agreement_id: c.agreement_id(),
                    file_metadata: FileMetadataData {
                        file_id: fm.file_id(),
                        root: fm.root(),
                        padded_len: fm.padded_len(),
                        original_size: fm.original_size(),
                        filename: fm.filename(),
                    },
                    block_height: c.block_height(),
                    num_challenges: c.num_challenges(),
                    seed: c.seed(),
                    prover_id: c.prover_id(),
                    deadline_height: c.deadline_height(),
                    status: c.status().load().into(),
                })
            })
            .collect()
    }

    fn get_challenges_for_node(ctx: &ViewContext, node_id: String) -> Vec<ChallengeData> {
        let model = ctx.model();
        model
            .challenges()
            .keys()
            .filter_map(|challenge_id: String| {
                let c = model.challenges().get(&challenge_id)?;
                if c.prover_id() != node_id || c.status().load() != ChallengeStatusStorage::Active {
                    return None;
                }
                let fm = c.file_metadata();
                Some(ChallengeData {
                    challenge_id: c.challenge_id(),
                    agreement_id: c.agreement_id(),
                    file_metadata: FileMetadataData {
                        file_id: fm.file_id(),
                        root: fm.root(),
                        padded_len: fm.padded_len(),
                        original_size: fm.original_size(),
                        filename: fm.filename(),
                    },
                    block_height: c.block_height(),
                    num_challenges: c.num_challenges(),
                    seed: c.seed(),
                    prover_id: c.prover_id(),
                    deadline_height: c.deadline_height(),
                    status: c.status().load().into(),
                })
            })
            .collect()
    }

    fn expire_challenges(ctx: &ProcContext, current_height: u64) {
        let model = ctx.model();

        // Iterate through all challenges and expire those past deadline
        for challenge_id in model.challenges().keys::<String>() {
            if let Some(challenge) = model.challenges().get(&challenge_id)
                && challenge.status().load() == ChallengeStatusStorage::Active
                && challenge.deadline_height() <= current_height
            {
                challenge.set_status(ChallengeStatusStorage::Expired);
            }
        }
    }

    fn submit_proof(
        _ctx: &ProcContext,
        _challenge_ids: Vec<String>,
        _proof: Vec<u8>,
    ) -> Result<SubmitProofResult, Error> {
        // TODO: Implement proof verification
        // 1. Call host function to verify proof
        // 2. Update challenge statuses to Proven if verified
        todo!("Proof verification not yet implemented")
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

        // Build set of file IDs that already have active challenges
        let challenged_file_ids: Vec<String> = model
            .challenges()
            .keys()
            .filter_map(|cid: String| {
                let c = model.challenges().get(&cid)?;
                (c.status().load() == ChallengeStatusStorage::Active)
                    .then(|| c.file_metadata().file_id())
            })
            .collect();

        // Get eligible agreements: active and file not already challenged
        let eligible_agreement_ids: Vec<String> = model
            .agreements()
            .keys()
            .filter(|aid: &String| {
                model.agreements().get(aid).is_some_and(|a| {
                    a.active() && !challenged_file_ids.contains(&a.file_metadata().file_id())
                })
            })
            .collect();

        let total_files = eligible_agreement_ids.len() as u64;
        if total_files == 0 {
            return new_challenges;
        }

        // Calculate expected number of challenges: θ(t) = (C_target * |F|) / B
        let c_target = model.c_target();
        let blocks_per_year = model.blocks_per_year();
        let expected_challenges_scaled = c_target * total_files;
        let num_challenges_base = expected_challenges_scaled / blocks_per_year;

        // Derive deterministic seed from block hash for agreement selection
        let agreement_seed = derive_seed(&prev_block_hash, b"agreement_selection");
        let mut rng_counter: u64 = 0;

        // Stochastic component: add one more challenge with probability (expected - base)
        let remainder = expected_challenges_scaled % blocks_per_year;
        let threshold = (remainder * 1000) / blocks_per_year;
        let roll = seeded_u64(&agreement_seed, &mut rng_counter, b"roll");
        let roll = roll % 1000;
        let num_to_challenge = if roll < threshold {
            num_challenges_base + 1
        } else {
            num_challenges_base
        };

        if num_to_challenge == 0 {
            return new_challenges;
        }

        // Don't try to challenge more agreements than exist
        let num_to_challenge = core::cmp::min(num_to_challenge, total_files);

        // Randomly select agreements using Fisher-Yates partial shuffle
        let mut shuffled_agreement_ids = eligible_agreement_ids;
        for i in 0..num_to_challenge as usize {
            let rand_val = seeded_u64(&agreement_seed, &mut rng_counter, b"shuffle");
            let j = i + (rand_val as usize % (shuffled_agreement_ids.len() - i));
            shuffled_agreement_ids.swap(i, j);
        }
        let selected_agreement_ids: Vec<String> = shuffled_agreement_ids
            .into_iter()
            .take(num_to_challenge as usize)
            .collect();

        // Derive batch seed for all challenges in this block
        let batch_seed = derive_seed(&prev_block_hash, b"batch_seed");
        let seed: Vec<u8> = batch_seed.to_vec();

        let s_chal = model.s_chal();
        let deadline_height = block_height + model.challenge_deadline_blocks();

        // Create challenges for selected agreements
        for agreement_id in selected_agreement_ids.iter() {
            let agreement = match model.agreements().get(agreement_id) {
                Some(a) => a,
                None => continue,
            };

            // Get active nodes for this agreement
            let active_nodes: Vec<String> = agreement
                .nodes()
                .keys()
                .filter(|nid: &String| agreement.nodes().get(nid).unwrap_or(false))
                .collect();

            if active_nodes.is_empty() {
                continue;
            }

            // Deterministically select one node
            let fm = agreement.file_metadata();
            let file_id = fm.file_id();
            let node_seed_input = [prev_block_hash.as_slice(), b":", file_id.as_bytes()].concat();
            let node_seed = derive_seed(&node_seed_input, b"node_selection");
            let mut node_counter: u64 = 0;
            let node_u64 = seeded_u64(&node_seed, &mut node_counter, b"node");
            let node_index = node_u64 as usize % active_nodes.len();
            let prover_id = active_nodes[node_index].clone();

            // Compute challenge ID via host function
            let raw_descriptor = RawFileDescriptor {
                file_id: file_id.clone(),
                root: fm.root(),
                padded_len: fm.padded_len(),
                original_size: fm.original_size(),
                filename: fm.filename(),
            };
            let challenge_id = match challenges::compute_challenge_id(
                &raw_descriptor,
                block_height,
                s_chal,
                &seed,
                &prover_id,
            ) {
                Ok(id) => id,
                Err(_) => continue,
            };

            // Create file metadata for storage
            let file_metadata = FileMetadata {
                file_id: file_id.clone(),
                root: fm.root(),
                padded_len: fm.padded_len(),
                original_size: fm.original_size(),
                filename: fm.filename(),
            };

            // Create and store challenge
            let challenge = Challenge {
                challenge_id: challenge_id.clone(),
                agreement_id: agreement_id.clone(),
                file_metadata,
                block_height,
                num_challenges: s_chal,
                seed: seed.clone(),
                prover_id: prover_id.clone(),
                deadline_height,
                status: ChallengeStatusStorage::Active,
            };
            model.challenges().set(challenge_id.clone(), challenge);

            new_challenges.push(ChallengeData {
                challenge_id,
                agreement_id: agreement_id.clone(),
                file_metadata: FileMetadataData {
                    file_id,
                    root: fm.root(),
                    padded_len: fm.padded_len(),
                    original_size: fm.original_size(),
                    filename: fm.filename(),
                },
                block_height,
                num_challenges: s_chal,
                seed: seed.clone(),
                prover_id,
                deadline_height,
                status: ChallengeStatus::Active,
            });
        }

        new_challenges
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
}

// ─────────────────────────────────────────────────────────────────
// Helper Functions
// ─────────────────────────────────────────────────────────────────

/// Derive a 32-byte seed using HKDF-SHA256 via host function
fn derive_seed(ikm: &[u8], info: &[u8]) -> [u8; 32] {
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
fn seeded_u64(seed: &[u8; 32], counter: &mut u64, info: &[u8]) -> u64 {
    let full_info = [b"kontor/rng/".as_slice(), info].concat();
    let salt = counter.to_le_bytes();
    let bs = crypto::hkdf_derive(seed, &salt, &full_info);
    let mut b8 = [0u8; 8];
    b8.copy_from_slice(&bs[..8]);
    *counter = counter.wrapping_add(1);
    u64::from_le_bytes(b8)
}
