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
CREATE TABLE IF NOT EXISTS contract_provenance (
  id INTEGER PRIMARY KEY,
  contract_id INTEGER NOT NULL,
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
  UNIQUE (contract_id, height, path),
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE,
  FOREIGN KEY (tx_id) REFERENCES transactions (id)
);

CREATE INDEX IF NOT EXISTS idx_contract_state_lookup ON contract_state (contract_id, path, height DESC);

CREATE INDEX IF NOT EXISTS idx_contract_state_contract_tx ON contract_state (contract_id, height DESC, tx_id DESC);

-- Height-leading index for incremental band pruning (see project_state_pruning):
-- lets a prune find the newly-finalized band by a height range-seek instead of a
-- full table scan, and is COVERING for the band-discovery subquery.
CREATE INDEX IF NOT EXISTS idx_contract_state_height ON contract_state (height, contract_id, path);

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
