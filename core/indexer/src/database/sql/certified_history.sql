CREATE TABLE IF NOT EXISTS certified_history_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    status TEXT NOT NULL CHECK (status IN ('pending', 'initializing', 'ready', 'unavailable')),
    context BLOB,
    genesis_id BLOB CHECK (genesis_id IS NULL OR length(genesis_id) = 32),
    authenticated_height BLOB NOT NULL CHECK (length(authenticated_height) = 8),
    authenticated_id BLOB CHECK (authenticated_id IS NULL OR length(authenticated_id) = 32),
    closed_height BLOB NOT NULL CHECK (length(closed_height) = 8),
    closure_id BLOB CHECK (closure_id IS NULL OR length(closure_id) = 32),
    CHECK ((status IN ('initializing', 'ready') AND context IS NOT NULL
        AND genesis_id IS NOT NULL AND authenticated_id IS NOT NULL)
        OR (status IN ('pending', 'unavailable') AND context IS NULL
        AND genesis_id IS NULL AND authenticated_id IS NULL AND closure_id IS NULL)),
    CHECK (closed_height <= authenticated_height)
);

CREATE TABLE IF NOT EXISTS certified_inputs (
    body_digest BLOB PRIMARY KEY CHECK (length(body_digest) = 32),
    body BLOB NOT NULL CHECK (length(body) <= 4186112)
);

CREATE TABLE IF NOT EXISTS historical_committees (
    height BLOB PRIMARY KEY CHECK (length(height) = 8),
    committee_id BLOB NOT NULL UNIQUE CHECK (length(committee_id) = 32),
    record BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS certified_decisions (
    height BLOB PRIMARY KEY CHECK (length(height) = 8),
    decision_id BLOB NOT NULL UNIQUE CHECK (length(decision_id) = 32),
    record BLOB NOT NULL,
    body_digest BLOB NOT NULL REFERENCES certified_inputs(body_digest),
    committee_id BLOB NOT NULL REFERENCES historical_committees(committee_id),
    original_proof BLOB NOT NULL,
    proof_augmentation BLOB
);

INSERT OR IGNORE INTO certified_history_state
    (singleton, status, authenticated_height, closed_height)
SELECT 1, CASE WHEN EXISTS(SELECT 1 FROM blocks)
    OR EXISTS(SELECT 1 FROM contracts) OR EXISTS(SELECT 1 FROM contract_state)
    OR EXISTS(SELECT 1 FROM transactions) OR EXISTS(SELECT 1 FROM signers)
    OR EXISTS(SELECT 1 FROM checkpoints) OR EXISTS(SELECT 1 FROM batches)
    OR EXISTS(SELECT 1 FROM canonical_applications)
    THEN 'unavailable' ELSE 'pending' END, zeroblob(8), zeroblob(8);

UPDATE certified_history_state SET status = 'unavailable'
WHERE status = 'pending' AND (EXISTS(SELECT 1 FROM blocks)
    OR EXISTS(SELECT 1 FROM contracts) OR EXISTS(SELECT 1 FROM contract_state)
    OR EXISTS(SELECT 1 FROM transactions) OR EXISTS(SELECT 1 FROM signers)
    OR EXISTS(SELECT 1 FROM checkpoints) OR EXISTS(SELECT 1 FROM batches)
    OR EXISTS(SELECT 1 FROM canonical_applications));
