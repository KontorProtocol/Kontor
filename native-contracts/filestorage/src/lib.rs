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

// ─────────────────────────────────────────────────────────────────
// State Types
// ─────────────────────────────────────────────────────────────────

/// A storage agreement for a file
/// nodes: Map<node_id, is_active> - true means active, false means left
#[derive(Clone, Default, Storage)]
struct Agreement {
    pub agreement_id: String,
    pub file_id: String,
    pub root: Vec<u8>,
    pub depth: u64,
    pub active: bool,
    pub nodes: Map<String, bool>,
    pub node_count: u64,
}

#[derive(Clone, Default, StorageRoot)]
struct ProtocolState {
    pub min_nodes: u64,
    pub challenge_deadline_blocks: u64,
    pub agreements: Map<String, Agreement>,
    pub agreement_count: u64,
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
        if descriptor.depth == 0 {
            return Err(Error::Message("depth must be positive".to_string()));
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

        // Create the agreement (starts inactive until nodes join)
        let agreement = Agreement {
            agreement_id: agreement_id.clone(),
            file_id: descriptor.file_id,
            root: descriptor.root,
            depth: descriptor.depth,
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
        ctx.model()
            .agreements()
            .get(&agreement_id)
            .map(|a| AgreementData {
                agreement_id: a.agreement_id(),
                file_id: a.file_id(),
                root: a.root(),
                depth: a.depth(),
                active: a.active(),
            })
    }

    fn agreement_count(ctx: &ViewContext) -> u64 {
        ctx.model().agreement_count()
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
}
