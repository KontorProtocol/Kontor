#![no_std]
contract!(name = "filestorage");

use stdlib::*;

// ─────────────────────────────────────────────────────────────────
// Protocol Constants
// ─────────────────────────────────────────────────────────────────

/// Minimum number of storage nodes required for an agreement to be active.
/// The challenge-generation params (target rate, deadline, sample count) now
/// live host-side in the reactor — generation is no longer a contract concern.
const DEFAULT_MIN_NODES: u64 = 3;

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
    pub agreements: Map<String, AgreementData>,
    pub agreement_nodes: Map<String, AgreementNodes>,
    pub agreement_count: u64,
}

// ─────────────────────────────────────────────────────────────────
// Contract Implementation
// ─────────────────────────────────────────────────────────────────

impl Guest for Filestorage {
    fn init(ctx: &ProcContext) -> Contract {
        ProtocolState {
            min_nodes: DEFAULT_MIN_NODES,
            agreements: Map::default(),
            agreement_nodes: Map::default(),
            agreement_count: 0,
        }
        .init(ctx);
        ctx.contract()
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
        register_file_descriptor(&descriptor)?;

        // Create the agreement (starts inactive until nodes join)
        let agreement = AgreementData {
            agreement_id: agreement_id.clone(),
            file_id: descriptor.file_id.clone(),
            active: false,
        };

        // Store the agreement and initialize node tracking
        model.agreements().set(&agreement_id, agreement);
        model
            .agreement_nodes()
            .set(&agreement_id, AgreementNodes::default());

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
            .keys()
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
    ) -> Result<JoinAgreementResult, Error> {
        let model = ctx.model();

        // Membership is keyed on the joining signer — one slot per signer per
        // agreement. The identity is the signer's key (its signer_id, under the
        // hood), never a caller parameter, so auth is structural and a failed
        // challenge's prover resolves to a slashable stake.
        let node_id = ctx.signer().key();

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
        nodes_state.nodes().set(&node_id, true);

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
    ) -> Result<LeaveAgreementResult, Error> {
        let model = ctx.model();

        // Only the signer that joined can leave its own slot — structural auth,
        // since the membership key is the signer's identity.
        let node_id = ctx.signer().key();

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

        // TODO: the storage protocol spec does not allow
        // voluntary departure when the agreement would be at/below the minimum replication
        // threshold (|N_f| <= n_min). We do not enforce that rule yet.

        // Mark node as inactive (don't delete, just set to false)
        nodes_state.nodes().set(&node_id, false);

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


    // ─────────────────────────────────────────────────────────────────
    // Proof Verification
    // ─────────────────────────────────────────────────────────────────

    fn verify_proof(ctx: &ProcContext, proof_bytes: Vec<u8>) -> Result<VerifyProofResult, Error> {
        // 1. Deserialize proof (single deserialization via host resource)
        let proof = file_registry::Proof::from_bytes(&proof_bytes)?;

        // 2. Get challenge IDs from proof
        let challenge_ids = proof.challenge_ids();
        if challenge_ids.is_empty() {
            return Err(Error::Message("Proof contains no challenges".to_string()));
        }

        // 3. Reconstruct challenge inputs from the host ledger. Challenges live
        //    host-side now; the contract still owns agreements, so it resolves
        //    each challenge's file_id from its agreement locally.
        let model = ctx.model();
        let mut challenge_inputs = Vec::new();
        for cid in &challenge_ids {
            let challenge = challenge_registry::get_challenge(cid)
                .ok_or(Error::Message(format!("Challenge not found: {}", cid)))?;

            // Only accept proofs for active challenges
            if challenge.status != challenge_registry::ChallengeStatus::Active {
                return Err(Error::Message(format!(
                    "Challenge {} is not active (status: {:?})",
                    cid, challenge.status
                )));
            }

            let agreement = model.agreements().get(&challenge.agreement_id).ok_or(
                Error::Message(format!("Agreement not found: {}", challenge.agreement_id)),
            )?;

            challenge_inputs.push(file_registry::ChallengeInput {
                challenge_id: cid.clone(),
                file_id: agreement.file_id(),
                block_height: challenge.height,
                num_challenges: challenge.num_challenges,
                seed: challenge.seed,
                prover_id: challenge.prover_id,
            });
        }

        // 4. Verify the proof
        let result = proof.verify(&challenge_inputs)?;

        // 5. Record the outcome in the ledger (native-only write).
        let new_status = match result {
            file_registry::VerifyResult::Verified => challenge_registry::ChallengeStatus::Proven,
            file_registry::VerifyResult::Rejected => challenge_registry::ChallengeStatus::Failed,
            file_registry::VerifyResult::Invalid => challenge_registry::ChallengeStatus::Invalid,
        };

        for cid in &challenge_ids {
            challenge_registry::record_status(cid, new_status);
        }

        Ok(VerifyProofResult {
            verified_count: challenge_ids.len() as u64,
        })
    }
}

/// Validate and register a file descriptor with the file registry host.
fn register_file_descriptor(descriptor: &RawFileDescriptor) -> Result<(), Error> {
    let fd: file_registry::FileDescriptor = file_registry::FileDescriptor::from_raw(descriptor)?;
    file_registry::add_file(&fd);
    Ok(())
}

