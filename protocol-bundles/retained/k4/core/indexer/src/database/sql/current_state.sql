-- A derived index of live versions. Logical references survive VACUUM; values
-- remain in contract_state and are fetched only after checking the byte budget.
CREATE TABLE current_contract_state (
  contract_id INTEGER NOT NULL,
  path BLOB NOT NULL,
  height INTEGER NOT NULL REFERENCES blocks(height) ON DELETE CASCADE,
  size INTEGER NOT NULL CHECK (size >= 0),
  PRIMARY KEY (contract_id, path)
) WITHOUT ROWID;

CREATE INDEX idx_current_contract_state_height ON current_contract_state(height);

INSERT INTO current_contract_state (contract_id, path, height, size)
SELECT s.contract_id, s.path, s.height, s.size FROM contract_state s
WHERE s.deleted = 0 AND NOT EXISTS (
  SELECT 1 FROM contract_state n
  WHERE n.contract_id = s.contract_id AND n.path = s.path AND n.height > s.height
);

-- Same-height replacements must refresh size as well as height. An older import
-- must not displace a newer value OR resurrect a key hidden by a newer tombstone.
CREATE TRIGGER maintain_current_contract_state AFTER INSERT ON contract_state
WHEN NOT EXISTS (
  SELECT 1 FROM contract_state n
  WHERE n.contract_id = NEW.contract_id AND n.path = NEW.path AND n.height > NEW.height
)
BEGIN
  DELETE FROM current_contract_state
  WHERE NEW.deleted != 0 AND contract_id = NEW.contract_id AND path = NEW.path;
  INSERT INTO current_contract_state (contract_id, path, height, size)
  SELECT NEW.contract_id, NEW.path, NEW.height, NEW.size WHERE NEW.deleted = 0
  ON CONFLICT (contract_id, path) DO UPDATE SET height = excluded.height, size = excluded.size;
END;
