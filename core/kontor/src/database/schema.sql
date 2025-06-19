CREATE TABLE IF NOT EXISTS blocks (
  height INTEGER PRIMARY KEY,
  hash TEXT NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS checkpoints (
  id INTEGER PRIMARY KEY,
  height INTEGER UNIQUE,
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

CREATE INDEX IF NOT EXISTS idx_transactions_height_tx_index ON transactions (height DESC, tx_index DESC);

CREATE INDEX IF NOT EXISTS idx_transactions_txid ON transactions (txid);

CREATE TABLE IF NOT EXISTS contract_state (
  id INTEGER PRIMARY KEY,
  contract_id TEXT NOT NULL,
  tx_id INTEGER NOT NULL,
  height INTEGER NOT NULL,
  path TEXT NOT NULL,
  value BLOB,
  deleted BOOLEAN NOT NULL DEFAULT 0,
  UNIQUE (contract_id, height, path),
  FOREIGN KEY (height) REFERENCES blocks (height) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_contract_state_lookup ON contract_state (contract_id, height, path);
