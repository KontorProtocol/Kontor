#![no_std]
contract!(
    name = "filestorage",
    indexed = "
        agreement-data: active;
        challenge-data: status;
        challenge-data: due by status sort deadline-height;
    "
);

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

/// Challenge count on regtest. The PoR prover (a Nova recursive SNARK) costs
/// roughly linearly in this count; a small value keeps proof generation fast on
/// the dev network and in tests. Soundness only matters on real networks, so
/// signet/testnet/mainnet keep `DEFAULT_S_CHAL`.
const REGTEST_S_CHAL: u64 = 8;

/// Bound on retained aggregated roots (mirrors kontor-crypto's
/// `DEFAULT_MAX_HISTORICAL_ROOTS`). A submitted proof's `ledger_root` must fall
/// within this many recent roots, else verification rejects it.
const MAX_VALID_ROOTS: u64 = 4096;

// ─────────────────────────────────────────────────────────────────
// STORAGE INDEX MODEL
//
// A `Map<K, V>` whose value declares `#[index]` fields gains framework-maintained
// secondary indexes (sibling `<map>#idx/...` rows — ordinary contract_state, so
// versioned, reorg-safe, checkpoint-covered); a value with none is a plain map at
// zero cost (the index path const-folds out). One `Map` type, no separate
// `IndexedMap`. The bookkeeping lives in stdlib (audited once), not hand-rolled here.
//
//   agreements            indexed by `active` → where_active(true)
//   challenges            indexed by `status` → where_status(ChallengeStatus::Active)
//   challenges            `due`: by `status`, sorted by `deadline_height`
//                                → where_due(Active).up_to(height) (ordered, early-break)
//   memberships           keyed by the compound `(agreement_id, node_id)` tuple;
//                         `by_agreement_active`: by (`agreement_id`, `active`)
//                                → where_by_agreement_active(aid, true) (flat, no
//                                  nested map; count_by_agreement_active for size)
//
// This collapses every former scan — expire's full challenge scan, generation's
// nested challenge×agreement scan, get_active_challenges' full scan, and the
// per-agreement active-node scan-and-filter — to indexed prefix reads over just
// the live subset. `where_<index>(bucket…)` lookups are typed: the method name is
// the index and the arguments are the bucket fields' real types (no stringly-typed
// name or key), generated from the value's `#[index]` fields by its `Storage`
// derive. A *composite* index takes one argument per bucket field — an `Option`
// field by its presence (`Presence::Absent`/`Present`), so "active ∧ unchallenged"
// is one prefix scan, not a scan-and-filter. A *sorted* index's `where_` returns a
// `SortedScan` with `.up_to(bound)` / `.range(lo..=hi)`, so `expire` walks only the
// due prefix of the active bucket instead of every active challenge. For the WIT
// records (`agreement-data`/`challenge-data`) the `#[index(...)]` declarations are
// injected by the `indexed = "..."` arg on `contract!` (forked wit-bindgen);
// internal structs (`NodeState`) carry `#[index]` directly.
//
// `set`/`remove` maintain the index, AND an in-place indexed-field setter does
// too (`get(&k).set_status(...)` / `set_active(...)` reconcile the bucket) — so
// no load→mutate→set dance. Departed/terminal rows move to the off bucket
// (`active/false`, `status/expired`…), out of the live scan but kept for history.
//
// Bucket sizes are framework-maintained: `count_active(true)` is the live-member
// count (no hand-kept `node_count`), and the agreement total is the sum of its
// `active` buckets (no hand-kept `agreement_count`) — neither can drift.
//
// Deferred: partial/`filter` indexes and covering indexes (avoid the where_*→get
// N reads), and order-statistics on indexes (the i-th member in O(log n)). See the
// upgrade backlog. Challenge selection needs uniform random ordinal access into the
// eligible set, which a key-ordered index can't give sublinearly — so it uses the
// dense append-only `active_ids` array instead (see ProtocolState), not an index.
// (The `due` sorted index covers the composite `(status, deadline_height)` sweep
// `expire` needed; the flat compound-keyed `memberships` map replaced the nested
// per-agreement node map.)
// ─────────────────────────────────────────────────────────────────

// ─────────────────────────────────────────────────────────────────
// State Types
// ─────────────────────────────────────────────────────────────────

/// A node's membership in an agreement, stored in the flat `memberships` map
/// keyed by the compound `(agreement_id, node_id)` tuple. The composite
/// `by_agreement_active` index — bucketed by `(agreement_id, active)` — makes an
/// agreement's live members a single prefix scan
/// (`where_by_agreement_active(aid, true)`) and its count framework-maintained
/// (`count_by_agreement_active(aid, true)`), so there's no nested map and no
/// hand-kept counter. `agreement_id` is co-located in the value (it's the bucket
/// field; the key also carries it) so the index is computable from the value
/// alone. Departed nodes keep a row with `active = false`, in the
/// `(aid, false)` bucket, out of the live scan but still listable.
#[derive(Clone, Default, Storage)]
#[index(by_agreement_active, by = (agreement_id, active))]
struct NodeState {
    pub agreement_id: String,
    pub active: bool,
}

/// A file registered this block, queued for the per-block frontier fold. Carries
/// exactly what `frontier-append` needs per file — `(root, padded_len, ledger_index)`
/// — drained FIFO (ascending `ledger_index`, the order slots were assigned) by
/// `record_block_root`.
#[derive(Clone, Default, Storage)]
struct PendingFile {
    pub root: Vec<u8>,
    pub padded_len: u64,
    pub ledger_index: u64,
}

#[derive(Clone, Default, StorageRoot)]
struct ProtocolState {
    pub min_nodes: u64,
    pub challenge_deadline_blocks: u64,
    pub c_target: u64,
    pub s_chal: u64,
    pub blocks_per_year: u64,
    pub agreements: Map<String, AgreementData>,
    pub memberships: Map<(String, u64), NodeState>,
    pub challenges: Map<String, ChallengeData>,
    /// Dense, append-only array of ACTIVE agreements' ids (position 0..len). An
    /// agreement is pushed here exactly when it activates (reaches `min_nodes`);
    /// `active` is monotonic (never turned off) and agreements never terminate, so
    /// this only grows — no holes, no removal. It exists for one reason: challenge
    /// selection needs uniform-random ORDINAL access ("the i-th active agreement"),
    /// which the key-ordered `active` index can't answer sublinearly (you'd walk the
    /// bucket, O(n)). `active_ids.get(i)` is O(1), so generate_challenges samples in
    /// O(challenges-this-block) instead of materializing the whole eligible set.
    /// Eligibility (not currently challenged) is applied by rejection at sample time.
    pub active_ids: Deque<String>,
    // The accepted aggregated-root window ({current} ∪ recent history): a new root
    // is one O(1) push per file add (not a rewrite of the whole window). `verify`
    // is given this set; a proof's ledger_root must be a member. Bounded by
    // `MAX_VALID_ROOTS` via push_back + pop_front (FIFO eviction of the oldest).
    pub valid_roots: Deque<Vec<u8>>,
    /// Files registered this block, not yet folded into the aggregated root.
    /// `create_agreement` pushes one per new file; the per-block `record_block_root`
    /// core hook drains them (FIFO) into the incremental frontier and clears the
    /// queue. A non-empty queue is the "file set changed this block" signal (it
    /// replaces the old `roots_dirty` flag) — empty ⇒ the hook is a no-op. Keeps
    /// `create_agreement` O(1) and the per-block fold O(files added this block).
    pub pending_appends: Deque<PendingFile>,
    /// Persisted append-only ledger frontier (kontor-crypto `LedgerFrontier`): the
    /// O(log n) Merkle "mountain peaks" of every file folded so far. `frontier_count`
    /// is the number folded (== the next slot to fold); `frontier_peaks` is the
    /// concatenated 32-byte field reprs of the peaks (one per set bit of the count).
    /// `record_block_root` advances these incrementally each block instead of
    /// rebuilding the whole tree — the resulting root is byte-identical to a full
    /// `aggregate_root` over the same contiguous slots.
    ///
    /// INVARIANT: `frontier_count + pending_appends.len() == next_ledger_index`,
    /// maintained by construction (`create_agreement` bumps `next_ledger_index` AND
    /// pushes one `pending_appends` entry; `record_block_root` drains those AND
    /// advances `frontier_count` by the same count) and true from genesis (`init`
    /// seeds all three at 0). So the first pending slot is always exactly
    /// `frontier_count` and `frontier-append`'s contiguity check never fires on a
    /// genesis-initialized chain. The one way to break it is to deploy this code over
    /// a PRE-EXISTING registry (agreements with `ledger_index > 0` but a fresh
    /// `frontier_count = 0`) — such a migration MUST first backfill the frontier with
    /// every existing file before the first `record_block_root`. N/A pre-launch; the
    /// contiguity check is the intended loud fail-stop that would catch a missed
    /// backfill rather than silently record a wrong root.
    pub frontier_count: u64,
    pub frontier_peaks: Vec<u8>,
    /// Monotonic, append-only counter for the next file's stable ledger slot
    /// (kontor-crypto 0.3.0). Assigned at `create_agreement` and only ever
    /// incremented — a slot is never reused, even if its file is later removed —
    /// so a file's leaf position in the aggregated ledger tree is stable for life.
    /// Replaces the old lexicographic-`file_id` ordering.
    pub next_ledger_index: u64,
}

// `agreement-data`/`challenge-data` are indexed (agreement by `active`; challenge
// by `status` and by the sorted `due` index) via the `indexed = "..."` arg on
// `contract!`, which injects the struct-level `#[index(...)]` declarations onto the
// WIT records (forked wit-bindgen). The index machinery itself is folded into
// `#[derive(Storage)]` (applied to every record), so their `Indexed` impls and
// index-aware setters are generated, not hand-written.
// `challenge-status` (like every enum the contract defines) automatically gets
// the `StorageEnum` machinery generated by `contract!` — its `IndexKey` (the
// discriminant is the index-bucket key), `Display`, and the `ChallengeStatusKind`
// marker. So the bucket a `where_status(..)` lookup scans and the bucket a write
// lands in both come from one generated source and can't drift.

// ─────────────────────────────────────────────────────────────────
// Contract Implementation
// ─────────────────────────────────────────────────────────────────

/// The caller's `u64` signer_id, which is the storage-node identity. Members
/// must be registered signers (a failed challenge has to resolve to a slashable
/// stake), so a non-signer holder — core, raw pubkey, utxo — is bad input here
/// rather than a silently skipped join.
fn require_signer_id(signer: &context::Signer) -> Result<u64, Error> {
    match signer.into() {
        HolderRef::SignerId(id) => Ok(id),
        _ => Err(Error::Message(
            "caller must be a registered signer identity".to_string(),
        )),
    }
}

impl Guest for Filestorage {
    fn init(ctx: &ProcContext) -> Contract {
        // Smaller challenge count on regtest so the Nova prover stays fast for
        // the dev network and tests; production networks use the full count.
        // Self-conditioning via the `network()` built-in (cf. token dev-mint).
        let s_chal = if ctx.network().is_regtest() {
            REGTEST_S_CHAL
        } else {
            DEFAULT_S_CHAL
        };
        ProtocolState {
            min_nodes: DEFAULT_MIN_NODES,
            challenge_deadline_blocks: DEFAULT_CHALLENGE_DEADLINE_BLOCKS,
            c_target: DEFAULT_C_TARGET,
            s_chal,
            blocks_per_year: DEFAULT_BLOCKS_PER_YEAR,
            agreements: Map::default(),
            memberships: Map::default(),
            challenges: Map::default(),
            active_ids: Deque::default(),
            valid_roots: Deque::default(),
            pending_appends: Deque::default(),
            frontier_count: 0,
            frontier_peaks: Vec::new(),
            next_ledger_index: 0,
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

        // Assign this file's stable, append-only ledger slot from the monotonic
        // counter. Done before the validation call below — but the counter is only
        // bumped AFTER validation succeeds, so a rejected descriptor never burns a
        // slot (which would leave a permanent gap and erode the sparsity budget).
        let ledger_index = model.next_ledger_index();

        // Validate the descriptor's `root` field element up front via a throwaway
        // single-file aggregate — O(1). The per-block `record_block_root` recompute
        // also validates, but it's a core op that can't surface errors to a user, so
        // we reject a malformed descriptor here (never stored) before it ever reaches
        // that hook. Aggregate by (root, padded_len, ledger_index) — the file lives
        // at its assigned slot, not a sort position.
        file_registry::aggregate_root(&[(
            descriptor.root.clone(),
            descriptor.padded_len,
            ledger_index,
        )])?;

        // Validation passed — claim the slot by advancing the append-only counter.
        model.set_next_ledger_index(ledger_index + 1);

        // Create the agreement (starts inactive until nodes join). The file
        // descriptor is folded in — the contract owns this metadata now.
        let agreement = AgreementData {
            agreement_id: agreement_id.clone(),
            file_id: descriptor.file_id.clone(),
            object_id: descriptor.object_id.clone(),
            nonce: descriptor.nonce.clone(),
            root: descriptor.root.clone(),
            padded_len: descriptor.padded_len,
            original_size: descriptor.original_size,
            filename: descriptor.filename.clone(),
            ledger_index,
            active: false,
            active_challenge: None,
        };

        // Store the agreement, `active: false`, so it lands in the `active/false`
        // index bucket; the framework bucket counts are the agreement total, so
        // there's no separate counter to bump. Memberships are flat rows in their
        // own map, written by `join` — nothing to initialize here.
        model.agreements().set(&agreement_id, agreement);

        // Queue this file for the per-block frontier fold; `record_block_root` drains
        // the queue (unbilled system work) once per block. create_agreement stays
        // O(1) — one push, not a root recompute — and the per-block fold is O(files
        // added this block), not O(all files).
        model.pending_appends().push_back(PendingFile {
            root: descriptor.root.clone(),
            padded_len: descriptor.padded_len,
            ledger_index,
        });

        Ok(CreateAgreementResult { agreement_id })
    }

    fn get_agreement(ctx: &ViewContext, agreement_id: String) -> Option<AgreementData> {
        ctx.model()
            .agreements()
            .get(&agreement_id)
            .map(|a| a.load())
    }

    fn agreement_count(ctx: &ViewContext) -> u64 {
        // Every agreement is in exactly one `active` bucket (`true` once enough
        // nodes join, `false` before that), and agreements are never removed —
        // so the total is the sum of the two framework-maintained bucket counts.
        let agreements = ctx.model().agreements();
        agreements.count_active(true) + agreements.count_active(false)
    }

    fn get_all_active_agreements(ctx: &ViewContext) -> Vec<AgreementData> {
        let model = ctx.model();
        model
            .agreements()
            .where_active(true)
            .filter_map(|agreement_id: String| {
                model.agreements().get(&agreement_id).map(|a| a.load())
            })
            .collect()
    }

    fn join_agreement(
        ctx: &ProcContext,
        agreement_id: String,
    ) -> Result<JoinAgreementResult, Error> {
        let model = ctx.model();

        // Membership is keyed on the joining signer's u64 signer_id, so one
        // signer holds at most one slot per agreement (enforced by the dup-check
        // below). This is a legitimacy guardrail — not a replication guarantee:
        // replication is economic, and an operator behind multiple keys is
        // undetectable by design. Keying on the signer also makes a failed
        // challenge's `prover_id` resolve to a slashable stake.
        let node_id = require_signer_id(&ctx.signer())?;

        // Validate agreement exists
        let agreement = model
            .agreements()
            .get(&agreement_id)
            .ok_or(Error::Message(format!(
                "agreement not found: {}",
                agreement_id
            )))?;
        // Membership is a single flat entry keyed by `(agreement_id, node_id)` — a
        // missing entry just means "never joined".
        let membership_key = (agreement_id.clone(), node_id);

        // Check if node is already active in agreement
        if model
            .memberships()
            .get(&membership_key)
            .map(|n| n.active())
            .unwrap_or(false)
        {
            return Err(Error::Message(format!(
                "node {} already in agreement {}",
                node_id, agreement_id
            )));
        }

        // Add (or reactivate) the node — `set` lands it in the `(agreement, true)`
        // bucket and bumps that bucket's framework-maintained count. No nested
        // node-set to lazily create.
        model.memberships().set(
            &membership_key,
            NodeState {
                agreement_id: agreement_id.clone(),
                active: true,
            },
        );

        // Active-node count is the `(agreement, true)` bucket size — read straight
        // from the index, no hand-kept counter.
        let node_count = model
            .memberships()
            .count_by_agreement_active(agreement_id.clone(), true);

        // Check if we should activate (only if not already active)
        let min_nodes = model.min_nodes();
        let activated = !agreement.active() && node_count >= min_nodes;

        if activated {
            // In-place set: the `active` index is maintained automatically
            // because `agreements().get()` binds the value model to the index.
            agreement.set_active(true);
            // Append to the dense active array (activation is one-way, so this is the
            // only place it grows). Gives generate_challenges O(1) ordinal access.
            model.active_ids().push_back(agreement_id.clone());
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

        // Only the signer that joined can leave its own membership — auth is
        // structural now that the key is the signer's identity.
        let node_id = require_signer_id(&ctx.signer())?;

        // Validate agreement exists
        let _agreement = model
            .agreements()
            .get(&agreement_id)
            .ok_or(Error::Message(format!(
                "agreement not found: {}",
                agreement_id
            )))?;
        let membership_key = (agreement_id.clone(), node_id);
        let membership = model
            .memberships()
            .get(&membership_key)
            .ok_or(Error::Message(format!(
                "node {} not in agreement {}",
                node_id, agreement_id
            )))?;

        // Validate node is active in agreement
        if !membership.active() {
            return Err(Error::Message(format!(
                "node {} not in agreement {}",
                node_id, agreement_id
            )));
        }

        // TODO: the storage protocol spec does not allow
        // voluntary departure when the agreement would be at/below the minimum replication
        // threshold (|N_f| <= n_min). We do not enforce that rule yet.

        // Mark node as inactive in place (kept as a row; the framework moves it to
        // the `(agreement, false)` bucket, out of the live-member scan, and
        // decrements the `(agreement, true)` count automatically).
        membership.set_active(false);

        Ok(LeaveAgreementResult {
            agreement_id,
            node_id,
        })
    }

    fn get_agreement_nodes(ctx: &ViewContext, agreement_id: String) -> Vec<NodeInfo> {
        let memberships = ctx.model().memberships();
        // All nodes we've seen, including inactive ones: scan both `active` buckets
        // of the agreement. `active` is known from which bucket, so no per-node
        // read, and the node_id is the second half of the compound key.
        [true, false]
            .into_iter()
            .flat_map(|active| {
                memberships
                    .where_by_agreement_active(agreement_id.clone(), active)
                    .map(move |key: (String, u64)| NodeInfo {
                        node_id: key.1,
                        active,
                    })
            })
            .collect()
    }

    fn is_node_in_agreement(ctx: &ViewContext, agreement_id: String, node_id: u64) -> bool {
        ctx.model()
            .memberships()
            .get(&(agreement_id, node_id))
            .map(|n| n.active())
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
            .where_status(ChallengeStatus::Active)
            .filter_map(|challenge_id: String| {
                model.challenges().get(&challenge_id).map(|c| c.load())
            })
            .collect()
    }

    fn expire_challenges(ctx: &CoreContext, current_height: u64) -> u64 {
        let model = ctx.proc_context().model();

        // Ordered scan of the active bucket by deadline; `up_to` early-breaks at
        // the first not-yet-due challenge (the bound is the encoded deadline, a
        // string compare). Snapshot before mutating — `set_status` moves ids out
        // of the `due` and `status` buckets, and mutating an index mid-scan would
        // corrupt the lazy iteration.
        let due: Vec<String> = model
            .challenges()
            .where_due(ChallengeStatus::Active)
            .up_to(current_height)
            .collect();

        for challenge_id in &due {
            terminate_challenge(&model, challenge_id, ChallengeStatus::Expired);
        }
        due.len() as u64
    }

    /// Fold this block's newly-registered files into the aggregated ledger root — a
    /// per-block CORE op, so `create_agreement` stays O(1) (it only queues the file).
    /// No-op on blocks that added no files. Runs after the block's transactions (in
    /// `run_block_lifecycle`), so the recorded root reflects the complete block-end
    /// set. Safe to defer: the only consumer of `valid_roots` is proof verification,
    /// and a proof against a root that includes a file first added this block cannot
    /// exist yet (the prover needs the block-end root first; single-file proofs use
    /// the file's own root).
    ///
    /// Cost is O(files added this block), not O(all files): `frontier_append`
    /// advances the persisted append-only `LedgerFrontier` incrementally (O(log n)
    /// per file) instead of rebuilding the whole Merkle tree. The frontier's root is
    /// byte-identical to a full `aggregate_root` over the same slots. All descriptors
    /// were validated at create time, so `frontier_append` here cannot fail on a bad
    /// descriptor.
    fn record_block_root(ctx: &CoreContext) -> Result<(), Error> {
        let model = ctx.proc_context().model();

        // Drain the per-block queue FIFO (== ascending ledger slot, the order
        // `create_agreement` assigned them). Empty ⇒ no files added this block ⇒ the
        // root is unchanged, nothing to do.
        let pending = model.pending_appends();
        let mut new_files = Vec::with_capacity(pending.len() as usize);
        while let Some(p) = pending.pop_front() {
            new_files.push((p.root, p.padded_len, p.ledger_index));
        }
        if new_files.is_empty() {
            return Ok(());
        }

        // Fold them into the persisted frontier; `frontier_append` asserts each slot
        // is contiguous with `frontier_count` and returns the advanced state + the new
        // aggregated root.
        let (new_count, new_peaks, root) = file_registry::frontier_append(
            model.frontier_count(),
            &model.frontier_peaks(),
            &new_files,
        )?;
        model.set_frontier_count(new_count);
        model.set_frontier_peaks(new_peaks);

        // Append the new root; evict the oldest once over the cap (FIFO window).
        let roots = model.valid_roots();
        roots.push_back(root);
        if roots.len() > MAX_VALID_ROOTS {
            roots.pop_front();
        }
        Ok(())
    }

    // ─────────────────────────────────────────────────────────────────
    // Challenge Generation
    // ─────────────────────────────────────────────────────────────────

    fn generate_challenges_for_block(
        ctx: &CoreContext,
        block_height: u64,
        block_hash: Vec<u8>,
    ) -> Vec<ChallengeData> {
        let model = ctx.proc_context().model();
        let mut new_challenges = Vec::new();

        // Per-block batch seed: σ_batch = HKDF_SHA256(block_hash, "KONTOR-CHAL::v1" || block_height)
        let sigma_batch = derive_batch_seed(&block_hash, block_height);

        // Eligible agreements = active AND not currently challenged. Both inputs are
        // O(1): `active_ids` is the dense append-only array of active agreements (its
        // length is the active count), and the challenged count is the Active-challenge
        // bucket count (≤1 active challenge per agreement). This replaces the old O(n)
        // `where_eligible(...).collect()` that materialized the whole eligible set every
        // block just to index into it.
        let active_ids = model.active_ids();
        let active_count = active_ids.len();
        let challenged = model.challenges().count_status(ChallengeStatus::Active);
        let total_files = active_count.saturating_sub(challenged) as usize;
        if total_files == 0 {
            return new_challenges;
        }

        // Derive deterministic seed from the per-block batch seed for agreement selection
        let agreement_seed = derive_stream_seed(&sigma_batch, b"agreement_selection");
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

        // Don't try to challenge more agreements than are eligible
        let num_to_challenge = core::cmp::min(num_to_challenge, total_files);

        // Select `num_to_challenge` distinct eligible agreements by REJECTION SAMPLING
        // over the dense active array: draw a random ordinal, skip it if that agreement
        // is currently challenged (ineligible) or already chosen. Expected draws are
        // O(num_to_challenge) — the challenged fraction is ≈ c_target·deadline /
        // blocks_per_year (a protocol constant well below 1, independent of the total
        // file count), so this stays bounded as state grows rather than degrading to an
        // O(n) scan. (`num_to_challenge ≤ total_files` guarantees the loop terminates.)
        let mut selected: BTreeSet<String> = BTreeSet::new();
        while selected.len() < num_to_challenge {
            let ordinal = uniform_index(
                &agreement_seed,
                &mut rng_counter,
                b"select",
                active_count as usize,
            ) as u64;
            let agreement_id = match active_ids.get(ordinal) {
                Some(id) => id,
                None => continue,
            };
            if selected.contains(&agreement_id) {
                continue;
            }
            // Eligible = not currently under challenge (every `active_ids` entry is
            // active by construction).
            if model
                .agreements()
                .get(&agreement_id)
                .map(|a| a.active_challenge().is_none())
                .unwrap_or(false)
            {
                selected.insert(agreement_id);
            }
        }

        let s_chal = model.s_chal();
        let deadline_height = block_height + model.challenge_deadline_blocks();

        // Create challenges for selected agreements
        for agreement_id in &selected {
            let agreement = match model.agreements().get(agreement_id) {
                Some(a) => a,
                None => continue,
            };

            // Live members of this agreement — an indexed prefix scan of the
            // `(agreement, true)` bucket, recovering each node_id from the compound
            // key's second half.
            let active_nodes: Vec<u64> = model
                .memberships()
                .where_by_agreement_active(agreement_id.clone(), true)
                .map(|key: (String, u64)| key.1)
                .collect();

            if active_nodes.is_empty() {
                continue;
            }

            // Get file_id early since we need it for multiple derivations
            let file_id = agreement.file_id();

            // Deterministically select one node (agreement-level exclusion ensures we create
            // at most 1 active challenge per agreement total).
            let node_seed = derive_stream_seed_for_file(&sigma_batch, b"node_selection", &file_id);
            let mut node_counter: u64 = 0;
            let node_index =
                uniform_index(&node_seed, &mut node_counter, b"node", active_nodes.len());
            let prover_id = active_nodes[node_index];

            // Per-challenge seed used by kontor-crypto as the Challenge.seed field.
            // Derived deterministically from the per-block batch seed and the file_id.
            let challenge_seed = derive_challenge_seed_for_file(&sigma_batch, &file_id);
            let seed: Vec<u8> = challenge_seed.to_vec();

            let descriptor = raw_descriptor(&agreement.load());

            // Compute challenge ID from the file metadata.
            let challenge_id = match file_registry::compute_challenge_id(
                &descriptor,
                block_height,
                s_chal,
                &seed,
                prover_id,
            ) {
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
                .set(&challenge.challenge_id, challenge.clone());
            agreement.set_active_challenge(Some(challenge.challenge_id.clone()));

            new_challenges.push(challenge);
        }

        new_challenges
    }

    /// Create a challenge for a specific agreement and node.
    /// This is primarily for testing to avoid probabilistic challenge generation.
    fn create_challenge_for_agreement(
        ctx: &ProcContext,
        agreement_id: String,
        prover_id: u64,
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

        // Validate node is active in agreement (point read of the flat membership).
        let is_active = model
            .memberships()
            .get(&(agreement_id.clone(), prover_id))
            .map(|n| n.active())
            .unwrap_or(false);
        if !is_active {
            return Err(Error::Message(format!(
                "Node {} is not active in agreement {}",
                prover_id, agreement_id
            )));
        }

        // No active challenge already exists for this agreement — a point read
        // of the co-located `active_challenge`, not a scan.
        if agreement.active_challenge().is_some() {
            return Err(Error::Message(format!(
                "Agreement {} already has an active challenge",
                agreement_id
            )));
        }

        // Validate seed length (64 bytes required for unbiased field element conversion)
        if seed.len() != 64 {
            return Err(Error::Message(format!(
                "Seed must be 64 bytes, got {}",
                seed.len()
            )));
        }

        let s_chal = model.s_chal();
        let deadline_height = block_height + model.challenge_deadline_blocks();

        let descriptor = raw_descriptor(&agreement.load());

        let challenge_id = file_registry::compute_challenge_id(
            &descriptor,
            block_height,
            s_chal,
            &seed,
            prover_id,
        )?;

        let challenge = ChallengeData {
            challenge_id,
            agreement_id,
            block_height,
            num_challenges: s_chal,
            seed,
            prover_id,
            deadline_height,
            status: ChallengeStatus::Active,
        };

        model
            .challenges()
            .set(&challenge.challenge_id, challenge.clone());
        agreement.set_active_challenge(Some(challenge.challenge_id.clone()));

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

    fn verify_proof(
        ctx: &ProcContext,
        proof_bytes: Vec<u8>,
        challenge_ids: Vec<String>,
    ) -> Result<VerifyProofResult, Error> {
        let model = ctx.model();

        // 1. Deserialize proof (single deserialization via host resource)
        let proof = file_registry::Proof::from_bytes(&proof_bytes)?;

        // 2. The kontor-crypto 0.3.0 constant-size proof no longer enumerates the
        // challenges it answers, so the submitter declares them. The SNARK binds
        // the challenge set + each file's resolved slot to the proof, so a wrong,
        // extra, or missing id makes verification fail — no credit is given for
        // challenges the proof doesn't actually answer.
        if challenge_ids.is_empty() {
            return Err(Error::Message("No challenge ids supplied".to_string()));
        }

        // 3. Build challenge inputs + the file-registry snapshot (`file_id ->
        // (root, padded_len, ledger_index)`) the stateless verifier resolves each
        // challenged file's stable slot and root-commitment from.
        let mut challenge_inputs = Vec::new();
        let mut files: Vec<(String, Vec<u8>, u64, u64)> = Vec::new();
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
                    .get(&challenge.agreement_id())
                    .ok_or(Error::Message(format!(
                        "Agreement not found: {}",
                        challenge.agreement_id()
                    )))?;
            let agreement = agreement.load();

            files.push((
                agreement.file_id.clone(),
                agreement.root.clone(),
                agreement.padded_len,
                agreement.ledger_index,
            ));

            challenge_inputs.push(file_registry_types::ChallengeInput {
                challenge_id: cid.clone(),
                file: raw_descriptor(&agreement),
                block_height: challenge.block_height(),
                num_challenges: challenge.num_challenges(),
                seed: challenge.seed(),
                prover_id: challenge.prover_id(),
            });
        }

        // 4. Verify the proof against the contract's valid-root window + the file
        // registry snapshot (for stable-slot resolution).
        let valid_roots: Vec<Vec<u8>> = model.valid_roots().iter().collect();
        let result = proof.verify(&challenge_inputs, &valid_roots, &files)?;

        // 5. Update challenge statuses based on result
        let new_status = match result {
            file_registry_types::VerifyResult::Verified => ChallengeStatus::Proven,
            file_registry_types::VerifyResult::Rejected => ChallengeStatus::Failed,
            file_registry_types::VerifyResult::Invalid => ChallengeStatus::Invalid,
        };

        for cid in &challenge_ids {
            terminate_challenge(&model, cid, new_status);
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

/// Derive the per-block batch seed:
///   σ_batch = HKDF_SHA256(block_hash, info = "KONTOR-CHAL::v1" || block_height)
///
/// 64 bytes are suitable for unbiased field element conversion via from_uniform_bytes.
pub fn derive_batch_seed(block_hash: &[u8], block_height: u64) -> [u8; 64] {
    let full_info = [
        b"KONTOR-CHAL::v1".as_slice(),
        block_height.to_le_bytes().as_slice(),
    ]
    .concat();
    // Spec does not require a salt here; use empty salt for determinism.
    hkdf64(block_hash, &[], &full_info)
}

/// Derive a deterministic stream seed from σ_batch for a particular purpose.
pub fn derive_stream_seed(sigma_batch: &[u8; 64], domain: &[u8]) -> [u8; 64] {
    // Identical to the per-file variant with an empty file_id (= empty HKDF salt).
    derive_stream_seed_for_file(sigma_batch, domain, "")
}

/// Domain-separated stream seed for a specific file.
pub fn derive_stream_seed_for_file(
    sigma_batch: &[u8; 64],
    domain: &[u8],
    file_id: &str,
) -> [u8; 64] {
    let full_info = [b"KONTOR-CHAL-STREAM::v1/".as_slice(), domain].concat();
    hkdf64(sigma_batch, file_id.as_bytes(), &full_info)
}

/// Derive the per-file challenge seed (64 bytes) from σ_batch and file_id.
pub fn derive_challenge_seed_for_file(sigma_batch: &[u8; 64], file_id: &str) -> [u8; 64] {
    hkdf64(sigma_batch, file_id.as_bytes(), b"KONTOR-SEED::v1")
}

/// Host HKDF-SHA256, unwrapped to the fixed 64-byte output every seed derivation
/// relies on — centralizes the "always 64 bytes" length invariant.
fn hkdf64(ikm: &[u8], salt: &[u8], info: &[u8]) -> [u8; 64] {
    crypto::hkdf_derive(ikm, salt, info)
        .try_into()
        .expect("hkdf_derive must return 64 bytes")
}

/// Deterministically derive a u64 from a 64-byte seed using HKDF-SHA256 via host function.
/// `counter` is used as the HKDF salt to produce a stable stream of outputs.
pub fn seeded_u64(seed: &[u8; 64], counter: &mut u64, domain_separator: &[u8]) -> u64 {
    let full_info = [b"KONTOR-RNG::v1/".as_slice(), domain_separator].concat();
    let salt = counter.to_le_bytes();
    let derived = hkdf64(seed, &salt, &full_info);
    *counter = counter.wrapping_add(1);
    u64::from_le_bytes(derived[..8].try_into().expect("slice is 8 bytes"))
}

/// Generate unbiased random index in range [0, n) using rejection sampling
pub fn uniform_index(seed: &[u8; 64], counter: &mut u64, info: &[u8], n: usize) -> usize {
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

/// Validate and register a file descriptor with the file registry host.
/// Rebuild the `raw-file-descriptor` the host crypto fns consume from a stored
/// agreement (the file metadata is folded into `agreement-data`).
/// Move a challenge to a terminal status (proven/failed/invalid/expired) and free
/// its agreement's challenge slot so the agreement can be challenged again. The two
/// are a unit — a terminal status must always clear the slot — so every caller goes
/// through here. No-op if the challenge or its agreement is already gone.
fn terminate_challenge(
    model: &ProtocolStateWriteModel,
    challenge_id: &str,
    status: ChallengeStatus,
) {
    if let Some(challenge) = model.challenges().get(&challenge_id.to_string()) {
        // In-place; the `status`/`due` indexes follow via the get() binding.
        challenge.set_status(status);
        if let Some(agreement) = model.agreements().get(&challenge.agreement_id()) {
            agreement.set_active_challenge(None);
        }
    }
}

fn raw_descriptor(a: &AgreementData) -> RawFileDescriptor {
    RawFileDescriptor {
        file_id: a.file_id.clone(),
        object_id: a.object_id.clone(),
        nonce: a.nonce.clone(),
        root: a.root.clone(),
        padded_len: a.padded_len,
        original_size: a.original_size,
        filename: a.filename.clone(),
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
