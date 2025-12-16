#![no_std]
contract!(name = "storage");

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

#[derive(Clone, Default, Storage)]
struct Agreement {
    pub file_id: String,
    /// Merkle tree root as hex string (64 chars)
    pub root: String,
    pub tree_depth: i64,
    pub owner: String,
    pub created_height: u64,
    pub active: bool,
}

#[derive(Clone, Default, StorageRoot)]
struct StorageProtocolState {
    pub min_nodes: u64,
    pub challenge_deadline_blocks: u64,
    pub agreements: Map<String, Agreement>,
    pub agreement_count: u64,
}

// ─────────────────────────────────────────────────────────────────
// Helper Functions
// ─────────────────────────────────────────────────────────────────

fn to_agreement_data(agreement_id: String, model: &AgreementModel) -> AgreementData {
    AgreementData {
        agreement_id,
        file_id: model.file_id(),
        root: model.root(),
        tree_depth: model.tree_depth(),
        owner: model.owner(),
        created_height: model.created_height(),
        active: model.active(),
    }
}

/// Decode hex string to bytes and validate it's exactly 32 bytes.
fn decode_root(root: &str) -> Result<Vec<u8>, Error> {
    let bytes =
        hex::decode(root).map_err(|_| Error::Message("root must be valid hex".to_string()))?;
    if bytes.len() != 32 {
        return Err(Error::Message(format!(
            "root must be 32 bytes, got {}",
            bytes.len()
        )));
    }
    Ok(bytes)
}

// ─────────────────────────────────────────────────────────────────
// Contract Implementation
// ─────────────────────────────────────────────────────────────────

impl Guest for Storage {
    fn init(ctx: &ProcContext) {
        StorageProtocolState {
            min_nodes: DEFAULT_MIN_NODES,
            challenge_deadline_blocks: DEFAULT_CHALLENGE_DEADLINE_BLOCKS,
            agreements: Map::default(),
            agreement_count: 0,
        }
        .init(ctx);
    }

    fn create_agreement(
        ctx: &ProcContext,
        metadata: FileMetadata,
    ) -> Result<CreateAgreementResult, Error> {
        // Validate inputs
        if metadata.file_id.is_empty() {
            return Err(Error::Message("file_id cannot be empty".to_string()));
        }
        let root_bytes = decode_root(&metadata.root)?;
        if metadata.tree_depth <= 0 {
            return Err(Error::Message("tree_depth must be positive".to_string()));
        }

        let model = ctx.model();

        // Check for duplicate agreement
        let agreement_id = metadata.file_id.clone();
        if model.agreements().get(&agreement_id).is_some() {
            return Err(Error::Message(format!(
                "agreement already exists for file_id: {}",
                agreement_id
            )));
        }

        // Register with the FileLedger host function
        file_ledger::register_file(&metadata.file_id, &root_bytes, metadata.tree_depth as u64)
            .map_err(|e| Error::Message(format!("failed to register file: {}", e)))?;

        // Create the agreement (starts inactive until nodes join)
        let agreement = Agreement {
            file_id: metadata.file_id,
            root: metadata.root,
            tree_depth: metadata.tree_depth,
            owner: ctx.signer().to_string(),
            created_height: 0, // TODO: Get actual block height when available
            active: false,
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
            .map(|a| to_agreement_data(agreement_id, &a))
    }

    fn agreement_count(ctx: &ViewContext) -> u64 {
        ctx.model().agreement_count()
    }
}
