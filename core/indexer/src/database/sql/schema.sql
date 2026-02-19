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

CREATE TABLE IF NOT EXISTS transactions (
  id INTEGER PRIMARY KEY,
  txid TEXT NOT NULL UNIQUE,
  height INTEGER NOT NULL,
  tx_index INTEGER NOT NULL,
  UNIQUE (height, tx_index),
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE
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
  tx_index INTEGER,
  size INTEGER NOT NULL,
  path TEXT NOT NULL,
  value BLOB NOT NULL,
  deleted BOOLEAN NOT NULL DEFAULT 0,
  UNIQUE (contract_id, height, path),
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_contract_state_lookup ON contract_state (contract_id, path, height DESC);

CREATE INDEX IF NOT EXISTS idx_contract_state_contract_tx ON contract_state (contract_id, height DESC, tx_index DESC);

CREATE TABLE IF NOT EXISTS contract_results (
  id INTEGER PRIMARY KEY,
  contract_id INTEGER NOT NULL,
  func TEXT NOT NULL,
  height INTEGER NOT NULL,
  tx_index INTEGER,
  input_index INTEGER,
  op_index INTEGER,
  result_index INTEGER NOT NULL,
  gas INTEGER NOT NULL,
  size INTEGER NOT NULL,
  value TEXT,
  UNIQUE (
    height,
    tx_index,
    input_index,
    op_index,
    result_index
  ),
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE
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

CREATE TABLE IF NOT EXISTS signer_nonces (
  signer_id BLOB NOT NULL,
  nonce BLOB NOT NULL,
  height INTEGER NOT NULL,
  tx_index INTEGER,
  input_index INTEGER,
  op_index INTEGER,
  UNIQUE (signer_id, nonce),
  CHECK (length(signer_id) = 8),
  CHECK (length(nonce) = 8),
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE
);
