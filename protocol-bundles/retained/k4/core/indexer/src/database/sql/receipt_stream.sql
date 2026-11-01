CREATE TABLE IF NOT EXISTS receipt_stream_state (
  singleton INTEGER PRIMARY KEY CHECK (singleton = 1),
  epoch TEXT NOT NULL CHECK (length(epoch) = 64),
  generation INTEGER NOT NULL CHECK (typeof(generation) = 'integer' AND generation >= 0),
  unsupported INTEGER NOT NULL CHECK (unsupported IN (0, 1))
);

INSERT OR IGNORE INTO receipt_stream_state
  (singleton, epoch, generation, unsupported)
VALUES (1, lower(hex(randomblob(32))), 0, 0);

CREATE TABLE IF NOT EXISTS receipt_stream_rollbacks (
  generation INTEGER PRIMARY KEY CHECK (generation > 0),
  surviving_height INTEGER NOT NULL CHECK (surviving_height >= 0),
  surviving_max_id INTEGER NOT NULL CHECK (surviving_max_id >= 0)
);

-- This operational marker survives canonical cascades without changing the
-- retained executor's allocation behavior or its receipt projection.
CREATE TRIGGER IF NOT EXISTS receipt_stream_unsupported_id
AFTER INSERT ON contract_results
WHEN NEW.id < 1 OR NEW.id > 9007199254740991
BEGIN
  UPDATE receipt_stream_state SET unsupported = 1 WHERE singleton = 1;
END;

UPDATE receipt_stream_state SET unsupported = 1
WHERE singleton = 1 AND (
  EXISTS (SELECT 1 FROM contract_results WHERE id < 1)
  OR EXISTS (SELECT 1 FROM contract_results WHERE id > 9007199254740991)
);
