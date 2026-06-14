CREATE TRIGGER IF NOT EXISTS trigger_checkpoint_on_contract_state_insert AFTER INSERT ON contract_state BEGIN
-- Insert a new checkpoint with the calculated hash
INSERT INTO
  checkpoints (height, hash)
VALUES
  (
    NEW.height,
    (
      WITH
        row_hash AS (
          SELECT
            hex(
              crypto_sha256 (
                concat (
                  NEW.contract_id,
                  -- path is a BLOB (codec bytes); hex it so the digest is over a
                  -- deterministic text form, like value below.
                  hex(NEW.path),
                  hex(NEW.value),
                  NEW.deleted
                )
              )
            ) AS hash
        )
      SELECT
        CASE
          WHEN EXISTS (
            SELECT
              1
            FROM
              checkpoints
          ) THEN hex(
            crypto_sha256 (
              concat (
                (
                  SELECT
                    hash
                  FROM
                    row_hash
                ),
                (
                  SELECT
                    hash
                  FROM
                    checkpoints
                  ORDER BY
                    height DESC
                  LIMIT
                    1
                )
              )
            )
          )
          ELSE (
            SELECT
              hash
            FROM
              row_hash
          )
        END
    )
  )
ON CONFLICT (height) DO UPDATE
SET
  hash = excluded.hash;

END;
