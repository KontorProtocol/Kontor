CREATE TABLE IF NOT EXISTS canonical_upgrade_controls (
    ordinal INTEGER PRIMARY KEY REFERENCES canonical_applications(ordinal) ON DELETE CASCADE,
    lineage BLOB NOT NULL UNIQUE CHECK (length(lineage) = 32),
    decision BLOB NOT NULL CHECK (length(decision) = 8),
    action BLOB NOT NULL UNIQUE CHECK (length(action) = 32),
    control BLOB NOT NULL CHECK (length(control) = 32),
    state BLOB NOT NULL
);

-- Removing the migration application restores the preceding protocol/control
-- state. Immutable manifests and certified decisions remain available separately.
CREATE TABLE IF NOT EXISTS canonical_protocol_activations (
    ordinal INTEGER PRIMARY KEY REFERENCES canonical_applications(ordinal) ON DELETE CASCADE,
    lineage BLOB NOT NULL UNIQUE CHECK (length(lineage) = 32),
    protocol_id BLOB NOT NULL CHECK (length(protocol_id) = 32),
    control_ordinal INTEGER NOT NULL REFERENCES canonical_upgrade_controls(ordinal) ON DELETE CASCADE,
    CHECK (control_ordinal < ordinal)
);

-- These are derived rollback dispositions, not surviving upgrade effects.
CREATE TABLE IF NOT EXISTS upgrade_control_retractions (
    action BLOB PRIMARY KEY CHECK (length(action) = 32),
    original_ordinal INTEGER NOT NULL CHECK (original_ordinal > 0),
    original_lineage BLOB NOT NULL CHECK (length(original_lineage) = 32),
    original_decision BLOB NOT NULL CHECK (length(original_decision) = 8),
    rollback_decision BLOB NOT NULL CHECK (length(rollback_decision) = 8),
    rollback_stage BLOB NOT NULL CHECK (length(rollback_stage) = 8),
    rollback_origin BLOB NOT NULL,
    rollback_height BLOB NOT NULL CHECK (length(rollback_height) = 8)
);

CREATE INDEX IF NOT EXISTS upgrade_control_retraction_position
ON upgrade_control_retractions (rollback_decision, rollback_stage);

-- Canonical-history cascade deletion must not bypass the rollback disposition.
CREATE TRIGGER IF NOT EXISTS require_upgrade_control_retraction
BEFORE DELETE ON canonical_upgrade_controls
WHEN NOT EXISTS (
    SELECT 1 FROM upgrade_control_retractions r
    WHERE r.action = OLD.action AND r.original_ordinal = OLD.ordinal
      AND r.original_lineage = OLD.lineage AND r.original_decision = OLD.decision
)
BEGIN
    SELECT RAISE(ABORT, 'upgrade control undo lacks retraction');
END;
