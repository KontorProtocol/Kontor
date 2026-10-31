# Consecutive workload sequence implementation

This extends the existing S2 workload harness inside the agreed S2 PR. It is
not a separate prerequisite project or a replacement for full W_op acceptance.
The inspected baseline is `e8590cef53d0f4195bb09a6f9f143f4e3cd1974c`.
No production execution behavior changes are proposed.

## Result and boundaries

Generate distinct signed consecutive Bitcoin blocks, then apply their canonical
work to one evolving reactor and SQLite database. Start from the populated
height-101 snapshot. Include height 102, its validator transitions and its first
storage reward/challenge lifecycle inside the sequence. Subsequent steps retain
all preceding effects. Never restore the initial snapshot between steps.

Keep existing single-block entrypoints, configuration and schema-1 saved fixtures
working unchanged. Use shared setup and execution helpers, with a sequence
envelope and evolving-state oracle. Initially support bounded sequences of two,
six and seven blocks, each with the existing 50 or 500 two-operation transactions.
The six-block case supplies the initial backlog, and the seventh supplies one
subsequent block. These bounds do not imply adequate input for every timed run.

The first deliverable is sequence correctness and portable saved inputs. Timed
open-loop arrivals follow using those inputs. Neither deliverable alone proves
the entire workload envelope, resource limits or six-cell S2 qualification.

## Confirmed funding and immutable inputs

Prepare all funding before the initial snapshot and measured sequence. Use a
bounded parent/split transaction tree: the mature funding coin funds one output
per sequence block, and each child splits its output into 50 or 500 distinct
transaction fundings. Confirm the parent and children together at height 101.
Check signatures, values, fees, unique outpoints, standard transaction weight,
and exact generated transaction order. Submit the small parent to the mempool,
then check each child individually with `testmempoolaccept` while only the parent
is retained there. Do not broadcast the children during these checks. Mine the
ordered parent and raw child transaction bytes with `generateblock`, and verify
Bitcoin accepted the complete block and all funding outputs are confirmed.
Record this as individual child admission plus block acceptance, not simultaneous
tree mempool admission. This also avoids the default connected-cluster size
limit without changing node policy. Do not enlarge one fanout to 3,500 P2TR
outputs, which exceeds standard transaction weight. Do not call the existing
mining fanout helper inside the measured block loop.

Generate each workload block with its own confirmed outpoints. Preserve the
ordered commit/reveal pairs and decode the resulting raw block through the real
decoder. Bind height, previous hash, block hash, raw transaction positions,
transaction IDs, signers and ordered operations. Validate the whole predecessor
chain and distinct spent inputs before execution. Generation time is setup time.

Reuse application contracts and initial live-key populations across steps.
Derive new file identities from a sequence ordinal and file ordinal. File ledger
state includes all previous registrations, including inactive files. Do not
assume registered count equals active count after the first step.

## Evolving semantic oracle

Preserve the existing independent first-block checks at 102 as an additional
check. Initialize a cumulative model from the actual initial snapshot, then
advance its expectations using ordered inputs and arithmetic, not by accepting
post-execution state as the expected value.

- Mixed calls: validate each receipt and nested receipt, transaction fuel,
  counter increments, recipient transfers, stake accumulation and failed-write
  rollback relative to the step's prestate. Intermediate stake return values
  include prior blocks' stake. Exact paid operation order remains checked.
- Accounting: check payer debits, burn, supply and escrow changes per step.
  Compute ordering emission and shares using the pre-transition active validator
  records with literal `ValidatorStatus::Active`, in the production holder-string
  order with rounding residue assigned to the last recipient. Do not substitute
  the consensus committee or `get_active_set`, which also includes pending exits.
  Apply only transitions due at that height, retaining already inactive validators
  and their balances on later blocks.
- Storage rewards: retain the cumulative reward index, per-host fractional
  earnings and global fractional liability. With index scale Q, previous
  liability remainder r and new liability L, funded atoms are
  `floor((L+r)/Q) + ((L+r)%Q > 0) - (r > 0)`. Carry the new remainder. Do not
  sum independently rounded per-block host balances or funding amounts.
- Storage registry: independently append each new descriptor to the expected
  full ledger, compare frontier count/peaks/root, pending-append drain and the
  retained valid-root window. Preserve prior active agreements and memberships.
- Challenges: retain previous active entries, check new entries' height,
  deadline, seed and status, and verify agreement references. Derive the exact
  expected new count and selected set from the prestate and block seed, so an
  omitted generation call cannot pass by creating no rows to inspect. Do not
  reset expected challenges each block. The short ordinary sequence does not
  reach expiry and does not replace the separately required expiry/cleanup backlog.
- Pruning: check the moving watermark/cutoff, retained versions and obsolete
  versions across steps, including the configured historical-key population.

For batch delivery, each step uses its current anchor and next confirmation
height. Preserve the earlier execution identity and usage when the block
confirms the transactions. Select paid receipts by exact transaction IDs;
receipts at the anchor can also contain the previous block's paid/lifecycle
rows. Check each canonical batch checkpoint as well as block completion.

Simulation requests remain noncanonical, bound to their designated step and
checked for full rollback. Keep eight view clients running across the complete
writer sequence, with initial/final counter bounds and nondecreasing observed
values. Do not recreate cold view pools at each block boundary.

## Saved sequence and replay

Use a strict schema-2 sequence envelope, leaving the schema-1 reader intact.
Bind the initial snapshot and full initial projection, Bitcoin setup chain,
ordered block inputs, associated batch/simulation inputs and complete projection
after every canonical batch and block. All file inventories and byte digests
are explicit. Reject unknown/duplicate fields, missing/extra files, reordered
steps, inconsistent heights/hashes/associations and reused transaction inputs.

Generate expected projections only after semantic checks. Execute the full
sequence on two independent initial-snapshot restores and require every
checkpoint to agree before writing the final manifest completion marker.
Observations must leave each checkpoint's complete projection unchanged.

Fresh-process replay validates identities through the existing replay-run seam,
checks each predecessor projection, applies the next step, and compares all
tables and state at its expected checkpoint. No additional projection exclusions
or normalization are allowed. Preserve initial snapshot bytes and producer
inputs. Test tampered/reordered steps, omitted or duplicate work, bad predecessor
links and changed intermediate expected state, not only final-state equality.

## Timed arrivals after correctness

The [agreed timed-workload amendment](native-stack-s2-timed-workload-plan.md)
refines this outline with additive fresh/confirmation budgets, fixed event
ordering, finality processing and a complete historical replay schedule.

Use a deterministic trace with fixed event tie ordering and canonical anchor
dependencies. Record intended enqueue time, actual dispatch, full service through
pruning and completion separately. Input preparation and oracle reads are not
execution service; report their cost separately without hiding delay from end to
end latency. Do not execute canonical operations twice to increase load.

The original six stress blocks are available at time zero. Batches and
simulations arrive at their declared intervals while views continue. The next
block arrives at 600 seconds. Successful draining must clear all work enqueued
strictly before the completion observation, with the agreed exact-deadline rule.
Do not compress the clock and claim the real 600-second gate passed. Freeze
enough future input for the declared horizon and fail explicitly if it runs out.

Replay speed uses canonical historical duration only. Simulation/API load never
enlarges its denominator. Keep fresh-block and batch-confirmation paths separate,
and warm/cold measurements distinct. Enforced resource profiles, paired real
S1/S2 builds, representative/stress populations and remaining legal diagnostics
remain separate required acceptance evidence.

## Review and validation

Before implementation, the integration reviewer must agree this concrete plan.
Source, evidence and eventual PR still need lead review plus both independent
review perspectives. Preserve the single Cargo/runtime slot and max two jobs.

Validate a two-block case first, then six-block and seventh-block continuity,
fresh and batched delivery, accumulated files/rewards/history, rollback and
continuous views. Recheck legacy single-block generation and saved replay.
Record actual source, binary, artifact and input hashes, negative controls,
process exits and limitations. Do not mark performance gates passed merely
because correctness replays pass.
