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
  tx_index INTEGER NOT NULL,
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
  tx_index INTEGER NOT NULL,
  input_index INTEGER NOT NULL,
  op_index INTEGER NOT NULL,
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

-- File ledger for Proof-of-Retrievability verification.
-- Each CreateAgreement creates a new leaf in the Merkle tree.
-- Root is stored as 32 bytes (FieldElement canonical serialization via to_repr()).
-- These values come from kontor-crypto's prepare_file() -> metadata.root.to_repr()
CREATE TABLE IF NOT EXISTS file_ledger_entries (
  id INTEGER PRIMARY KEY,
  txid TEXT NOT NULL,  -- txid of the CreateAgreement transaction
  file_id TEXT NOT NULL,
  root BLOB NOT NULL,
  tree_depth INTEGER NOT NULL,
  height INTEGER NOT NULL,
  tx_index INTEGER NOT NULL,
  UNIQUE (txid, file_id),  -- agreement identified by txid + file_id
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_file_ledger_txid_file ON file_ledger_entries (txid, file_id);
CREATE INDEX IF NOT EXISTS idx_file_ledger_file_id ON file_ledger_entries (file_id);
CREATE INDEX IF NOT EXISTS idx_file_ledger_height ON file_ledger_entries (height, tx_index);

-- Nodes participating in storage agreements.
-- References the specific ledger entry (leaf position).
CREATE TABLE IF NOT EXISTS agreement_nodes (
  id INTEGER PRIMARY KEY,
  ledger_entry_id INTEGER NOT NULL,  -- references file_ledger_entries.id (leaf position)
  node_id TEXT NOT NULL,
  joined_at_height INTEGER NOT NULL,
  UNIQUE (ledger_entry_id, node_id),
  FOREIGN KEY (ledger_entry_id) REFERENCES file_ledger_entries (id) ON DELETE CASCADE,
  FOREIGN KEY (joined_at_height) REFERENCES blocks (height) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_agreement_nodes_ledger_entry ON agreement_nodes (ledger_entry_id);
CREATE INDEX IF NOT EXISTS idx_agreement_nodes_node_id ON agreement_nodes (node_id);
