CREATE TABLE IF NOT EXISTS blocks (
  height INTEGER PRIMARY KEY,
  hash TEXT NOT NULL UNIQUE,
  relevant BOOLEAN NOT NULL
);

CREATE TABLE IF NOT EXISTS checkpoints (
  height INTEGER PRIMARY KEY,
  hash TEXT NOT NULL UNIQUE,
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS batches (
  consensus_height INTEGER PRIMARY KEY,
  anchor_height INTEGER NOT NULL,
  anchor_hash TEXT NOT NULL,
  certificate BLOB NOT NULL,
  is_block BOOLEAN NOT NULL DEFAULT 0
);

-- The batch_height FK (here and on unconfirmed_batch_txs) deliberately has NO
-- cascade: batches are the decided consensus record and are never deleted while
-- children exist. Rollbacks delete transactions via the height->blocks cascade;
-- the one path that deletes batches (startup cleanup of decided-but-unexecuted
-- rows, ConsensusState::new) deletes children explicitly first, and FK
-- enforcement failing LOUD there is the guard against any future deletion path
-- forgetting to.
CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY,
  txid TEXT NOT NULL UNIQUE,
  height INTEGER NOT NULL,
  confirmed_height INTEGER,
  tx_index INTEGER,
  batch_height INTEGER,
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE,
  FOREIGN KEY (batch_height) REFERENCES batches (consensus_height)
);

CREATE TABLE IF NOT EXISTS contracts (
  id INTEGER PRIMARY KEY,
  name TEXT NOT NULL,
  height INTEGER NOT NULL,
  tx_index INTEGER NOT NULL,
  size INTEGER NOT NULL,
  bytes BLOB NOT NULL,
  signer_id INTEGER,
  UNIQUE (name, height, tx_index),
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE,
  FOREIGN KEY (signer_id) REFERENCES signers (id)
);

-- Append-only build-provenance log per contract. The publish seeds the first
-- row; an UpdateProvenance op appends another. Latest = highest id per
-- contract_id. `provenance` is a postcard-encoded indexer_types::BuildProvenance.
-- `author_signer_id` is the publisher's signer (the op's signer, NOT the
-- contract's own signer_id). The author of the FIRST row is the publisher and
-- is the UpdateProvenance authz anchor; every row records its author.
CREATE TABLE IF NOT EXISTS contract_provenance (
  id INTEGER PRIMARY KEY,
  contract_id INTEGER NOT NULL,
  author_signer_id INTEGER NOT NULL,
  height INTEGER NOT NULL,
  tx_index INTEGER NOT NULL,
  provenance BLOB NOT NULL,
  FOREIGN KEY (contract_id) REFERENCES contracts (id) ON DELETE CASCADE,
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_contract_provenance_contract ON contract_provenance (contract_id, id);

CREATE TABLE IF NOT EXISTS contract_state (
  contract_id INTEGER NOT NULL,
  height INTEGER NOT NULL,
  tx_id INTEGER,
  size INTEGER NOT NULL,
  -- Order-preserving tuple-codec bytes (see stdlib::keycodec); BLOB so it can
  -- hold any bytes and so bytewise comparison == logical key order.
  path BLOB NOT NULL,
  value BLOB NOT NULL,
  deleted BOOLEAN NOT NULL DEFAULT 0,
  -- The signer who wrote (deposited for) this version — whose storage-deposit
  -- FLOOR this row counts toward (summed live across contracts). NULL for
  -- tombstones, and for exempt writes (the token ledger + core-signed/non-settling
  -- ops), which carry no deposit. A deterministic rowid like contract_id, so safe
  -- in the checkpoint hash.
  depositor INTEGER,
  -- The deposit this row represents = (path + value bytes) × D, in integer GAS
  -- (the unit deposits are metered in; D is gas/byte). NULL when there's no
  -- depositor. At D=1 this equals path+value bytes. The token value is this × the
  -- gas→token rate, computed at read. Consensus state, so hashed in the checkpoint.
  deposited_gas INTEGER,
  UNIQUE (contract_id, height, path),
  -- depositor and deposited_gas are always set together or not at all (a row
  -- either carries a deposit or it doesn't). Enforced in SQL so a future writer
  -- can't desync them and corrupt the footprint accounting.
  CHECK ((depositor IS NULL) = (deposited_gas IS NULL)),
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE,
  FOREIGN KEY (tx_id) REFERENCES transactions (id),
  FOREIGN KEY (depositor) REFERENCES signers (id)
);

CREATE INDEX IF NOT EXISTS idx_contract_state_lookup ON contract_state (contract_id, path, height DESC);

CREATE INDEX IF NOT EXISTS idx_contract_state_contract_tx ON contract_state (contract_id, height DESC, tx_id DESC);

-- Height-leading index for incremental band pruning (see project_state_pruning):
-- lets a prune find the newly-finalized band by a height range-seek instead of a
-- full table scan, and is COVERING for the band-discovery subquery.
CREATE INDEX IF NOT EXISTS idx_contract_state_height ON contract_state (height, contract_id, path);

-- Selective entry point for the per-signer storage-deposit footprint query
-- (find_footprint_by_depositor): a depositor holds a small fraction of all rows,
-- so this narrows the outer scan; the NOT EXISTS liveness check is served by
-- idx_contract_state_lookup. Partial (depositor IS NOT NULL) since most rows have
-- no depositor (Core/system/token-ledger writes).
CREATE INDEX IF NOT EXISTS idx_contract_state_depositor ON contract_state (depositor) WHERE depositor IS NOT NULL;

-- Eager cache of each depositor's storage-deposit FLOOR = Σ of the live
-- `deposited_gas` they collateralize across all contracts (the token value is this
-- × the gas→token rate, applied at read). The token's per-debit floor check
-- (context::storage-floor) reads this as an O(1) point lookup instead of re-scanning
-- contract_state every transfer (NEAR's account.storage_usage, keyed by depositor).
-- Maintained incrementally in the storage write path INSIDE the op savepoint (so it
-- rolls back with the op) via an atomic `total_gas = total_gas + :delta` upsert.
-- DERIVED + reconstructible from the depositor/deposited_gas columns, so it is
-- deliberately NOT in the checkpoint and has NO blocks FK — a reorg recomputes the
-- affected depositors (see Storage::rollback_with_footprint), and startup
-- reconstructs it. A depositor whose floor returns to zero is removed (absence ⇔
-- zero floor).
CREATE TABLE IF NOT EXISTS depositor_footprint (
  depositor INTEGER PRIMARY KEY,
  total_gas INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS contract_results (
  id INTEGER PRIMARY KEY,
  contract_id INTEGER NOT NULL,
  func TEXT NOT NULL,
  height INTEGER NOT NULL,
  tx_id INTEGER,
  input_index INTEGER,
  op_index INTEGER,
  result_index INTEGER NOT NULL,
  gas INTEGER NOT NULL,
  size INTEGER NOT NULL,
  value TEXT,
  signer_id INTEGER NOT NULL,
  -- Who funded gas for this op. Differs from signer_id only when the op was
  -- sponsored by the Bitcoin publisher in a BLS aggregate; otherwise equals
  -- signer_id. NULL for ops that don't go through gas accounting at all
  -- (e.g. Issuance, RegisterBlsKey via Core-paid path).
  payer_signer_id INTEGER,
  -- Outcome category for the op. Stored as the OpStatus enum's variant
  -- name (Ok / ContractErr / OutOfFuel / Trap / Other). Always present —
  -- successful rows carry "Ok", failure rows carry the failure category
  -- (frontend uses this to distinguish OOG from trap from contract Err).
  status TEXT NOT NULL DEFAULT 'Ok',
  UNIQUE (
    tx_id,
    input_index,
    op_index,
    result_index
  ),
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE,
  FOREIGN KEY (tx_id) REFERENCES transactions (id),
  FOREIGN KEY (signer_id) REFERENCES signers (id),
  FOREIGN KEY (payer_signer_id) REFERENCES signers (id)
);

CREATE TABLE IF NOT EXISTS signers (
  id INTEGER PRIMARY KEY,
  height INTEGER NOT NULL,
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS x_only_pubkeys (
  signer_id INTEGER NOT NULL,
  x_only_pubkey TEXT NOT NULL UNIQUE,
  height INTEGER NOT NULL,
  PRIMARY KEY (signer_id, height),
  FOREIGN KEY (signer_id) REFERENCES signers (id),
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS bls_keys (
  signer_id INTEGER NOT NULL,
  bls_pubkey BLOB NOT NULL,
  height INTEGER NOT NULL,
  PRIMARY KEY (signer_id, height),
  FOREIGN KEY (signer_id) REFERENCES signers (id),
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS nonces (
  signer_id INTEGER NOT NULL,
  next_nonce INTEGER NOT NULL,
  height INTEGER NOT NULL,
  PRIMARY KEY (signer_id, height),
  FOREIGN KEY (signer_id) REFERENCES signers (id),
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS unconfirmed_batch_txs (
  txid TEXT NOT NULL PRIMARY KEY,
  batch_height INTEGER NOT NULL,
  raw_tx BLOB NOT NULL,
  FOREIGN KEY (batch_height) REFERENCES batches (consensus_height)
);

-- Node-local operational state (NOT consensus state): a singleton key/value store.
-- Deliberately has NO foreign key to blocks (a reorg must not cascade-delete or roll
-- back local cursors) and is never touched by the checkpoint trigger (which fires
-- only on contract_state INSERT). The `value` column has no declared type, so SQLite
-- stores each value in its native storage class (e.g. the prune watermark as a real
-- INTEGER). First tenant: the prune watermark `W_prev` (see project_state_pruning).
CREATE TABLE IF NOT EXISTS node_meta (
  key TEXT PRIMARY KEY,
  value
) WITHOUT ROWID;
