# Timed workload amendment

This refines the timed-arrival portion of the existing S2 sequence plan in the
same S2 PR. It changes test fixtures and measurement, not production behavior.
Schemas 1 and 2 remain supported for the bounded correctness evidence already
collected. Those diagnostics do not establish the timed workload gates.

## Workload and immutable inputs

Interpret the existing 50/500 two-operation Bitcoin transactions per block as
fresh transactions, additional to transactions already executed in batches.
Representative arrivals are 20 operations every 30 seconds, stress arrivals
40 operations every 15 seconds. Each 600-second interval therefore contains
20/40 batches, 400/1,600 operations and 200/800 two-operation transactions.
The following confirming block contains these transactions plus its 50/500
fresh transactions: 250/1,300 transactions in steady state. Never silently
lower these rates, recycle canonical transactions or omit confirmations.

Use a separately versioned finite event envelope, reusing the existing funding,
identity, raw-input and complete-checkpoint helpers. Archive globally unique
canonical transaction identities, confirmed funding outpoints, commit/reveal
bytes, signers, ordered operations, raw blocks, batch decisions, independent
simulation inputs and the full event list. Bind event ordinal, type, input,
intended arrival and dependencies. Bind canonical anchor, consensus order and
complete predecessor/successor checkpoints. Each block explicitly partitions
fresh transactions from earlier batch confirmations; existing database rows
alone do not define the expected partition.

Generalize the bounded funding generator beyond 50/500 transactions and 2/6/7
steps for this envelope. Confirm a bounded parent/split funding tree before the
initial snapshot. Verify individual transaction admission and actual complete
block acceptance with Bitcoin Core, including measured weights and unique
spent inputs. If the exact requested workload does not fit, report that
concrete conflict instead of changing policy, limits or workload counts.

## Ordering and canonical obligations

Order events by intended arrival, then blocks in height order, batches, and
simulations, with explicit ordinals resolving remaining ties. Anchors and
dependencies are frozen before execution and never derived from host speed.
In the steady trace, batches at times 0 through less than 600 anchor to 101;
block 102 at 600 confirms that interval before the batch at 600 anchors to 102.
In the fresh backlog diagnostic, six blocks are available at time zero before
the first batch and simulation; subsequent batches anchor to 107 and block 108
arrives at 600. Queued earlier batches execute before their confirming block
even on a slow host. Reject stale-anchor RecordedOnly results, never reanchor.

This is a trace of already decided execution, not evidence of live proposal
admission, certificate validation or Malachite throughput. Preserve that limit
because validate_batch may reject while a Bitcoin block is pending.

Maintain a transaction-keyed pending-confirmation model across blocks. Record
original execution identity, receipts and usage. Confirm exactly the declared
subset, preserving execution and charges while checking raw Bitcoin and filtered
transaction positions. All nonselected pending entries remain unchanged.
Reject unknown, duplicate, early or omitted confirmations. Every pending
transaction must confirm by its anchor plus the production finality window
(currently six blocks). The steady workload confirms the entire preceding
interval rather than hiding growth in an ever-expanding pending set.

Block service includes the normal post-block advance/finality and maintenance
path, not only handle_block. The existing bounded helper stops at handle_block,
so its historical evidence remains explicitly limited. Check finality pruning
and in-memory reactor/consensus state alongside full database projections.
Unexpected rollback, excluded transactions or stale tracked obligations fail
the positive workload. Dedicated negatives establish the deadline failure path.

## State and observation

Advance independent semantic models when execution actually occurs: batch
effects and fees at the anchor, fresh effects at the block, confirmation metadata
only for prior batches. Lifecycle expectations use the accumulated prestate.
Use unique canonical file IDs derived from stream, event and operation ordinal.
Require all canonical checkpoints to agree over two independent initial restores
before sealing the archive, and verify them again in a fresh consumer process.
Retain the existing explicit producer/consumer identity mechanism.

Give simulation requests their own archived namespace, especially file IDs.
Each arrival represents one explicit request with an occurrence and mix ordinal,
not every request executed twice or a modulo selection of canonical inputs.
Reuse requires proof of validity across every eligible canonical state. A
late request that exceeds that range fails the fixture. Accidental registration
or balance failures do not count as the promised successful workload; deliberate
errors have exact expectations. Check complete rollback and restored height,
tip, simulation mode and caches after every request. Use disk-backed full-state
comparison rather than retaining unbounded duplicate JSON projections.
Eight view clients run continuously over the whole sequence.

## Clock and measurement

Preflight the finite horizon, unique inputs, all events and confirmations,
expected arrival counts and legal deadlines. Enqueue from an independent
monotonic schedule, not completion-paced generation. Record enqueue lateness,
dependency wait, dispatch, execution service, oracle cost and completion.
Input preparation is setup. Oracle work is excluded from active execution
service but included in end-to-end and drain delay. Do not compress the clock
for acceptance evidence. Report scheduler delay rather than hiding it.

Drain completion includes every event intended strictly before its observation;
at exactly 600 seconds observe before all arrivals at that timestamp. Predefine
enough future inputs and fail explicitly on exhaustion. A transaction waiting
for its frozen future confirmation is a persistent obligation, not another
unprocessed execution event. Report such obligations and validate their future
confirmation in the full correctness trace.

Historical replay has a separate complete canonical schedule: include the full
20/40 batches in each represented 600-second interval. Keep historical time
distinct from current delivery/backlog offsets. Replay canonical work as fast
as possible with the required real-clock external API load; simulation requests
never enlarge the historical denominator. Six fresh blocks plus batches arriving
afterward are a fresh-backlog diagnostic, not six mixed historical intervals.

## Acceptance and review

Before implementation, obtain explicit integration-reviewer agreement on this
amendment's exact revision. Required controls cover stale anchors, duplicate or
missing events, wrong confirmation subsets and positions, pending transactions
across an intervening block, missed finality deadlines, canonical/API file-ID
collisions, tie ordering, the exact 600-second boundary, finite-horizon exhaustion
and modified intermediate checkpoints. Lead and both independent reviewers
review source and raw evidence before the existing PR/CI/merge gates.

No new operator policy decision is introduced by the additive interpretation.
Existing representative/stress population and threshold decisions, resource
profiles, paired real S1/S2 builds, cold cases and full six-cell qualification
remain required. Passing this harness does not close those separate gates.
