CREATE TABLE IF NOT EXISTS blocks (
  height INTEGER PRIMARY KEY,
  hash TEXT NOT NULL UNIQUE,
  relevant BOOLEAN NOT NULL,
  processed BOOLEAN NOT NULL DEFAULT 0
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
  certificate BLOB NOT NULL
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
  UNIQUE (name, height, tx_index),
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS contract_state (
  contract_id INTEGER NOT NULL,
  height INTEGER NOT NULL,
  tx_id INTEGER,
  size INTEGER NOT NULL,
  path TEXT NOT NULL,
  value BLOB NOT NULL,
  deleted BOOLEAN NOT NULL DEFAULT 0,
  UNIQUE (contract_id, height, path),
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE,
  FOREIGN KEY (tx_id) REFERENCES transactions (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_contract_state_lookup ON contract_state (contract_id, path, height DESC);

CREATE INDEX IF NOT EXISTS idx_contract_state_contract_tx ON contract_state (contract_id, height DESC, tx_id DESC);

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
  UNIQUE (
    tx_id,
    input_index,
    op_index,
    result_index
  ),
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE,
  FOREIGN KEY (tx_id) REFERENCES transactions (id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS file_metadata (
  id INTEGER PRIMARY KEY,
  file_id TEXT NOT NULL UNIQUE,
  object_id TEXT NOT NULL,
  nonce BLOB NOT NULL,
  root BLOB NOT NULL,
  padded_len INTEGER NOT NULL,
  original_size INTEGER NOT NULL,
  filename TEXT NOT NULL,
  height INTEGER NOT NULL,
  historical_root BLOB,
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_file_metadata_file_id ON file_metadata (file_id);
