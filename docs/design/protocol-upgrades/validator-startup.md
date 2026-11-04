# Validator startup and verified catch-up

This describes the single-runtime startup implementation merged in
[PR623](https://github.com/KontorProtocol/Kontor/pull/623), with live promotion,
transition and crash recovery qualification.
Protocol activation changes the selected executor and per-height signing
authorization while keeping the same Malachite runtime running. Joining as a
validator is a separate lifecycle transition.

Both ordinary `cargo build` nodes and independently linked production nodes use
this coordinator and the same pinned Malachite fork. The build distinction is
executor assembly: ordinary builds run the current in-tree executor, while
`tools/kontor` preserves independently linked historical executors and verifies
their build provenance. Their protocol identities and supported histories can
therefore differ even though their startup protections are shared.

Ordinary development nodes now use an owner-managed network key and the protected
files described below, replacing their former validator-derived network identity
and `consensus.wal`. Old development directories may fail admission and need an
intentional fresh regtest setup. Startup does not convert or delete old state.

## Starting a validator

Use `--consensus-mode validator` with the configured validator key and genesis.
Choose the startup policy deliberately:

- `--bootstrap-consensus`: start the initial genesis committee. The database must
  have no completed consensus decisions and the key must have no retained signer
  state. This is not a way to join an already running chain or discard history.
- No additional flag: resume retained validator state. Complete any persisted
  unfinished application closure, then resume the next consensus height and its
  retained WAL rounds. Validators restarting together do not need to certify
  that unfinished height before they can resume it.
- `--join-min-height C`: join through verified history, with a positive minimum
  completed **Kontor consensus height**, not a Bitcoin height. The effective
  floor is the maximum of C, the highest locally signed consensus height, and the last authorized height
  minus one.
  Remain a non-signing follower until completed history reaches that floor and
  the key belongs to the next committee. Already verified local history may
  satisfy the floor without another network synchronization pass.

The minimum is an operator-selected lower bound. An unsigned peer tip is not a
freshness proof, and unreachable peers do not mean catch-up succeeded. Supplying
an unnecessarily high minimum can leave a joining validator waiting for history
that the available quorum has not yet produced. For ordinary restarts, use
resume rather than keeping the one-time join flag.

Read-only `--consensus-mode follower` never promotes and accepts neither bootstrap
nor join flags.

## Preserved state

`consensus-authority/` contains exclusive node ownership and durable signing
history. `consensus-validator.wal` retains the validator's consensus state.
`consensus-catchup.wal` is separate because follower startup may reset its WAL.
Do not delete protected validator files to clear a startup error.

If the completed consensus height is 6, ordinary resume starts height 7.
Malachite opens and replays its own WAL, including unfinished rounds. Kontor
checks signer history and whether the validator WAL file exists, but never opens,
copies, decodes, or validates its contents. Signing state or authorization ahead
of the recoverable application boundary requires verified reconstruction. Missing
the WAL after signing at 7 requires joining through closure 7 before signing at a
new height. An interruption after authorizing 7 but before creating its WAL, with
no signature at 7, does not require an additional decision.

Kontor commits accepted proposal bodies and normal round choices to its database
before replying to Malachite or publishing a local proposal. Sync bodies are
stored by exact value ID separately from normal round choices. The engine checks
a sync body's ID against its certificate after the application reply, so staged
sync bodies are not themselves certified history. Decided verifies the proof,
loads the exact input, and commits certified history and proposal retirement in
one transaction before acknowledging the decision. Restart uses these durable
application records instead of extracting application data from Malachite's WAL.

Signer inspection does not create a signing capability or reserve a generation.
WAL integrity, incomplete-tail repair, and replay belong to Malachite. Kontor does
not add a corruption preflight or support arbitrary combinations of database and
validator backups. Restore the database, signing state, and engine WAL together.

Promotion first stops and fully joins the catch-up runtime while retaining the
exclusive node owner. Startup then reinspects protected state and the completed
boundary, authorizes the next height, and starts the validator on the same
listener. Old transport callbacks are discarded; application state, mempool and
Bitcoin ingestion remain in the node. A failed join never starts a competing
validator runtime.

## Observing startup and catch-up

`GET /api/status` keeps the configured `consensus_mode` separate from `runtime`,
the last observation published by the reactor. Runtime `authority` describes
whether the running engine has validator authority or is a follower.
`committee_member` separately reports membership at the observed consensus
height. A joining validator may therefore be a committee member while its
engine remains a follower. `required_join_height` is the verified closure floor
required before promotion, or null if no promotion is pending. Heights are
decimal strings. None of these diagnostics grant signing permission.

Runtime observations are null before startup, during role promotion, when the
publisher is gone, or when the node is shutting down or has failed. They are
observations rather than synchronous proofs of a live signer. The existing
readiness and failure fields remain necessary when interpreting them.

`GET /api/protocol` provides a separate consistent database snapshot of canonical
protocol selection and retained certified progress. Its `ready` availability
does not certify network freshness or validator participation. A recovery state,
unsupported protocol, unavailable history or missing runtime observation must
not be interpreted as permission to bootstrap or discard protected state.
