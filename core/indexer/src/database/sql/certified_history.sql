CREATE TABLE IF NOT EXISTS certified_protocols (
    protocol_id BLOB PRIMARY KEY CHECK (length(protocol_id) = 32),
    manifest BLOB NOT NULL CHECK (length(manifest) <= 65536)
);

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
    bitcoin_height BLOB NOT NULL CHECK (length(bitcoin_height) = 8),
    bitcoin_hash BLOB NOT NULL CHECK (length(bitcoin_hash) = 32),
    is_block INTEGER NOT NULL CHECK (is_block IN (0, 1)),
    proof_augmentation BLOB
);

CREATE INDEX IF NOT EXISTS certified_decision_execution_order
ON certified_decisions (bitcoin_height, height);

CREATE TABLE IF NOT EXISTS certified_bitcoin_boundary (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    context BLOB NOT NULL,
    first_height BLOB NOT NULL CHECK (length(first_height) = 8),
    parent BLOB CHECK (parent IS NULL OR length(parent) = 32)
);

CREATE TABLE IF NOT EXISTS certified_bitcoin_branch (
    bitcoin_height BLOB NOT NULL CHECK (length(bitcoin_height) = 8),
    since_decision BLOB NOT NULL REFERENCES certified_decisions(height),
    until_decision BLOB REFERENCES certified_decisions(height),
    block_hash BLOB NOT NULL CHECK (length(block_hash) = 32),
    PRIMARY KEY (bitcoin_height, since_decision),
    CHECK (until_decision IS NULL OR until_decision > since_decision)
);

CREATE UNIQUE INDEX IF NOT EXISTS certified_bitcoin_current
ON certified_bitcoin_branch (bitcoin_height) WHERE until_decision IS NULL;

CREATE TABLE IF NOT EXISTS registration_observations (
    height BLOB NOT NULL CHECK (length(height) = 8),
    stage BLOB NOT NULL CHECK (length(stage) = 8),
    observation_id BLOB NOT NULL UNIQUE CHECK (length(observation_id) = 32),
    record BLOB NOT NULL,
    PRIMARY KEY (height, stage)
);

CREATE TABLE IF NOT EXISTS closure_plans (
    height BLOB PRIMARY KEY REFERENCES certified_decisions(height),
    plan_id BLOB NOT NULL UNIQUE CHECK (length(plan_id) = 32),
    record BLOB NOT NULL
);

CREATE TABLE IF NOT EXISTS closure_work_plans (
    plan_key BLOB PRIMARY KEY CHECK (length(plan_key) = 32),
    height BLOB NOT NULL REFERENCES closure_plans(height),
    origin BLOB NOT NULL,
    item_count BLOB NOT NULL CHECK (length(item_count) = 8),
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    plan_id BLOB UNIQUE CHECK (plan_id IS NULL OR length(plan_id) = 32),
    verdict BLOB CHECK (verdict IS NULL OR length(verdict) = 32)
);

CREATE TABLE IF NOT EXISTS closure_work_items (
    plan_key BLOB NOT NULL REFERENCES closure_work_plans(plan_key),
    ordinal BLOB NOT NULL CHECK (length(ordinal) = 8),
    item BLOB NOT NULL CHECK (length(item) <= 41),
    previous BLOB NOT NULL CHECK (length(previous) = 32),
    digest BLOB NOT NULL CHECK (length(digest) = 32),
    PRIMARY KEY (plan_key, ordinal)
);

CREATE TABLE IF NOT EXISTS closure_replay_inputs (
    input_id BLOB PRIMARY KEY CHECK (length(input_id) = 32),
    plan_key BLOB NOT NULL REFERENCES closure_work_plans(plan_key),
    decision BLOB NOT NULL REFERENCES certified_decisions(height),
    record BLOB NOT NULL,
    UNIQUE (plan_key, decision)
);

CREATE TABLE IF NOT EXISTS closure_finality_plans (
    plan_key BLOB PRIMARY KEY REFERENCES closure_work_plans(plan_key),
    phase INTEGER NOT NULL CHECK (phase BETWEEN 0 AND 3),
    probe_after INTEGER NOT NULL DEFAULT 0 CHECK (probe_after >= 0),
    seed_after_decision BLOB CHECK (seed_after_decision IS NULL OR length(seed_after_decision) = 8),
    seed_after_txid TEXT,
    replay_height BLOB CHECK (replay_height IS NULL OR length(replay_height) = 8),
    replay_decision BLOB CHECK (replay_decision IS NULL OR length(replay_decision) = 8),
    from_height BLOB CHECK (from_height IS NULL OR length(from_height) = 8),
    record BLOB,
    CHECK ((seed_after_decision IS NULL) = (seed_after_txid IS NULL)),
    CHECK ((replay_height IS NULL) = (replay_decision IS NULL)),
    CHECK ((phase = 3) = (record IS NOT NULL))
);

CREATE TABLE IF NOT EXISTS closure_finality_seeds (
    plan_key BLOB NOT NULL REFERENCES closure_finality_plans(plan_key),
    decision BLOB NOT NULL REFERENCES certified_decisions(height),
    txid BLOB NOT NULL CHECK (length(txid) = 32),
    deadline BLOB NOT NULL CHECK (length(deadline) = 8),
    PRIMARY KEY (plan_key, decision, txid)
);

CREATE TABLE IF NOT EXISTS closure_replay_unavailable (
    plan_key BLOB NOT NULL REFERENCES closure_finality_plans(plan_key),
    txid BLOB NOT NULL CHECK (length(txid) = 32),
    PRIMARY KEY (plan_key, txid)
);

CREATE TABLE IF NOT EXISTS closure_stages (
    height BLOB NOT NULL REFERENCES closure_plans(height),
    stage BLOB NOT NULL CHECK (length(stage) = 8),
    stage_id BLOB NOT NULL UNIQUE CHECK (length(stage_id) = 32),
    observation_id BLOB NOT NULL UNIQUE REFERENCES registration_observations(observation_id),
    record BLOB NOT NULL,
    PRIMARY KEY (height, stage)
);

CREATE TABLE IF NOT EXISTS decision_closures (
    height BLOB PRIMARY KEY REFERENCES certified_decisions(height),
    closure_id BLOB NOT NULL UNIQUE CHECK (length(closure_id) = 32),
    record BLOB NOT NULL,
    next_committee BLOB NOT NULL REFERENCES historical_committees(committee_id)
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
