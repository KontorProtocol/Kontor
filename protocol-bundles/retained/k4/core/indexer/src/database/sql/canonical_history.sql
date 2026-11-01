CREATE TABLE IF NOT EXISTS canonical_history_state (
    singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
    status TEXT NOT NULL CHECK (status IN ('pending', 'ready', 'unavailable')),
    chain_id BLOB CHECK (chain_id IS NULL OR length(chain_id) = 32),
    ordinal INTEGER NOT NULL CHECK (ordinal >= 0),
    lineage BLOB CHECK (lineage IS NULL OR length(lineage) = 32),
    storage_height INTEGER NOT NULL CHECK (storage_height >= 0),
    authentic INTEGER NOT NULL CHECK (authentic IN (0, 1)),
    CHECK ((status = 'ready' AND chain_id IS NOT NULL AND lineage IS NOT NULL)
        OR (status != 'ready' AND chain_id IS NULL AND lineage IS NULL
            AND ordinal = 0 AND storage_height = 0 AND authentic = 0))
);

CREATE TABLE IF NOT EXISTS canonical_applications (
    ordinal INTEGER PRIMARY KEY CHECK (ordinal > 0),
    storage_height INTEGER NOT NULL CHECK (storage_height >= 0),
    record BLOB NOT NULL,
    lineage BLOB NOT NULL CHECK (length(lineage) = 32),
    authentic INTEGER NOT NULL CHECK (authentic IN (0, 1))
);

CREATE INDEX IF NOT EXISTS idx_canonical_applications_height
    ON canonical_applications(storage_height, ordinal);

CREATE TABLE IF NOT EXISTS migration_applications (
    application_key BLOB PRIMARY KEY CHECK (length(application_key) = 32),
    work BLOB NOT NULL CHECK (length(work) = 40),
    ordinal INTEGER NOT NULL UNIQUE REFERENCES canonical_applications(ordinal) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS genesis_applications (
    stage INTEGER PRIMARY KEY CHECK (stage >= 0),
    ordinal INTEGER NOT NULL UNIQUE REFERENCES canonical_applications(ordinal) ON DELETE CASCADE
);

-- Existing effects do not establish authentic input lineage. Initialization may
-- only bind a new chain when this database had no execution state at installation.
INSERT OR IGNORE INTO canonical_history_state
    (singleton, status, chain_id, ordinal, lineage, storage_height, authentic)
SELECT 1, CASE WHEN EXISTS(SELECT 1 FROM blocks)
    OR EXISTS(SELECT 1 FROM contracts) OR EXISTS(SELECT 1 FROM contract_state)
    OR EXISTS(SELECT 1 FROM transactions) OR EXISTS(SELECT 1 FROM signers)
    OR EXISTS(SELECT 1 FROM checkpoints) OR EXISTS(SELECT 1 FROM batches)
    THEN 'unavailable' ELSE 'pending' END, NULL, 0, NULL, 0, 0;

-- A process may have stopped after installing this schema but before binding
-- genesis. Untracked writes since installation cannot acquire a new lineage.
UPDATE canonical_history_state SET status = 'unavailable'
WHERE status = 'pending' AND (EXISTS(SELECT 1 FROM blocks)
    OR EXISTS(SELECT 1 FROM contracts) OR EXISTS(SELECT 1 FROM contract_state)
    OR EXISTS(SELECT 1 FROM transactions) OR EXISTS(SELECT 1 FROM signers)
    OR EXISTS(SELECT 1 FROM checkpoints) OR EXISTS(SELECT 1 FROM batches));
