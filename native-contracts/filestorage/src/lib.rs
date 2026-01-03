#![no_std]
contract!(name = "storage_agreement");

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
    pub root: Vec<u8>,
    pub depth: u64,
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
        depth: model.depth(),
        active: model.active(),
    }
}

// ─────────────────────────────────────────────────────────────────
// Contract Implementation
// ─────────────────────────────────────────────────────────────────

impl Guest for StorageAgreement {
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
            file_id: descriptor.file_id,
            root: descriptor.root,
            depth: descriptor.depth,
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
