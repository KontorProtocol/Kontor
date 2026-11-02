# Validator startup and verified catch-up

This describes the single-runtime startup implementation. Local live promotion,
transition and crash recovery qualification passed. Review and merge remain pending.
Protocol activation changes the selected executor and per-height signing
authorization while keeping the same Malachite runtime running. Joining as a
validator is a separate lifecycle transition.

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
  floor is the maximum of C, the highest locally signed consensus height, the
  protected validator WAL height, and the last authorized height minus one.
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

If the completed consensus height is 6, ordinary resume starts height 7. A valid
WAL at 7 preserves its unfinished round state. A WAL below 7 can reset forward
because certified closure covers that older height. A WAL or signing state ahead
of 7 requires verified reconstruction instead of a backward reset. Missing the
WAL after signing at 7 requires joining through closure 7 before signing at a new
height. An interruption after authorizing 7 but before creating its WAL, with no
signature at 7, does not require an additional decision.

Inspection reads signer history without creating a signing capability or reserving
a generation. WAL validation uses a private copy because the pinned WAL library
repairs incomplete tails when opening a file. Corruption is reported without
modifying the protected original. Entries with heights must match the WAL header.
When resuming that height, proposal/value descriptors must also match its verified
chain, protocol and era. These checks reject inconsistent restored files; they do
not repair or support arbitrary combinations of database and validator backups.

Promotion first stops and fully joins the catch-up runtime while retaining the
exclusive node owner. Startup then reinspects protected state and the completed
boundary, authorizes the next height, and starts the validator on the same
listener. Old transport callbacks are discarded; application state, mempool and
Bitcoin ingestion remain in the node. A failed join never starts a competing
validator runtime.
