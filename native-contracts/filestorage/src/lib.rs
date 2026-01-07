#![no_std]
contract!(name = "filestorage");

use stdlib::*;

use ChallengeStatus as ChallengeStatusWit;

// ─────────────────────────────────────────────────────────────────
// Protocol Constants
// ─────────────────────────────────────────────────────────────────

/// Minimum number of storage nodes required for an agreement to be active
const DEFAULT_MIN_NODES: u64 = 3;

/// Number of blocks a storage node has to respond to a challenge (~2 weeks at 10 min/block)
const DEFAULT_CHALLENGE_DEADLINE_BLOCKS: u64 = 2016;

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

/// Challenge status for storage - uses path-based variant encoding via Storage derive
#[derive(Clone, Copy, Default, PartialEq, Eq, Storage)]
enum ChallengeStatusStorage {
    #[default]
    Active,
    Proven,
    Expired,
    BadProof,
}

impl ChallengeStatusStorage {
    fn to_wit(self) -> ChallengeStatusWit {
        match self {
            Self::Active => ChallengeStatusWit::Active,
            Self::Proven => ChallengeStatusWit::Proven,
            Self::Expired => ChallengeStatusWit::Expired,
            Self::BadProof => ChallengeStatusWit::BadProof,
        }
    }
}

/// A storage challenge issued to a node
#[derive(Clone, Default, Storage)]
struct Challenge {
    pub challenge_id: String,
    pub agreement_id: String,
    pub file_id: String,
    pub node_id: String,
    pub issued_height: u64,
    pub deadline_height: u64,
    pub seed: Vec<u8>,
    pub num_challenges: u64,
    pub status: ChallengeStatusStorage,
}

#[derive(Clone, Default, StorageRoot)]
struct ProtocolState {
    pub min_nodes: u64,
    pub challenge_deadline_blocks: u64,
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

    fn create_challenge(
        ctx: &ProcContext,
        challenge_id: String,
        agreement_id: String,
        node_id: String,
        issued_height: u64,
        seed: Vec<u8>,
        num_challenges: u64,
    ) -> Result<ChallengeData, Error> {
        let model = ctx.model();

        // Validate challenge doesn't already exist
        if model.challenges().get(&challenge_id).is_some() {
            return Err(Error::Message(format!(
                "challenge already exists: {}",
                challenge_id
            )));
        }

        // Validate agreement exists and is active
        let agreement = model
            .agreements()
            .get(&agreement_id)
            .ok_or(Error::Message(format!(
                "agreement not found: {}",
                agreement_id
            )))?;

        if !agreement.active() {
            return Err(Error::Message(format!(
                "agreement not active: {}",
                agreement_id
            )));
        }

        // Validate node is in the agreement
        if !agreement.nodes().get(&node_id).unwrap_or(false) {
            return Err(Error::Message(format!(
                "node {} not in agreement {}",
                node_id, agreement_id
            )));
        }

        let file_id = agreement.file_metadata().file_id();
        let deadline_height = issued_height + model.challenge_deadline_blocks();

        let challenge = Challenge {
            challenge_id: challenge_id.clone(),
            agreement_id: agreement_id.clone(),
            file_id: file_id.clone(),
            node_id: node_id.clone(),
            issued_height,
            deadline_height,
            seed: seed.clone(),
            num_challenges,
            status: ChallengeStatusStorage::Active,
        };

        model.challenges().set(challenge_id.clone(), challenge);

        Ok(ChallengeData {
            challenge_id,
            agreement_id,
            file_id,
            node_id,
            issued_height,
            deadline_height,
            seed,
            num_challenges,
            status: ChallengeStatus::Active,
        })
    }

    fn get_challenge(ctx: &ViewContext, challenge_id: String) -> Option<ChallengeData> {
        ctx.model()
            .challenges()
            .get(&challenge_id)
            .map(|c| ChallengeData {
                challenge_id: c.challenge_id(),
                agreement_id: c.agreement_id(),
                file_id: c.file_id(),
                node_id: c.node_id(),
                issued_height: c.issued_height(),
                deadline_height: c.deadline_height(),
                seed: c.seed(),
                num_challenges: c.num_challenges(),
                status: c.status().load().to_wit(),
            })
    }

    fn get_active_challenges(ctx: &ViewContext) -> Vec<ChallengeData> {
        let model = ctx.model();
        model
            .challenges()
            .keys()
            .filter_map(|challenge_id| {
                let challenge = model.challenges().get(&challenge_id)?;
                if challenge.status().load() != ChallengeStatusStorage::Active {
                    return None;
                }
                Some(ChallengeData {
                    challenge_id,
                    agreement_id: challenge.agreement_id(),
                    file_id: challenge.file_id(),
                    node_id: challenge.node_id(),
                    issued_height: challenge.issued_height(),
                    deadline_height: challenge.deadline_height(),
                    seed: challenge.seed(),
                    num_challenges: challenge.num_challenges(),
                    status: challenge.status().load().to_wit(),
                })
            })
            .collect()
    }

    fn get_challenges_for_node(ctx: &ViewContext, node_id: String) -> Vec<ChallengeData> {
        let model = ctx.model();
        model
            .challenges()
            .keys()
            .filter_map(|challenge_id| {
                let challenge = model.challenges().get(&challenge_id)?;
                if challenge.node_id() != node_id {
                    return None;
                }
                if challenge.status().load() != ChallengeStatusStorage::Active {
                    return None;
                }
                Some(ChallengeData {
                    challenge_id,
                    agreement_id: challenge.agreement_id(),
                    file_id: challenge.file_id(),
                    node_id: challenge.node_id(),
                    issued_height: challenge.issued_height(),
                    deadline_height: challenge.deadline_height(),
                    seed: challenge.seed(),
                    num_challenges: challenge.num_challenges(),
                    status: challenge.status().load().to_wit(),
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
}
