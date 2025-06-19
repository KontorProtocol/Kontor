CREATE TRIGGER IF NOT EXISTS trigger_checkpoint_on_contract_state_insert AFTER INSERT ON contract_state BEGIN
-- Insert a new checkpoint with the calculated hash
INSERT INTO
  checkpoints (id, height, hash)
VALUES
  (
    -- Determine the ID
    CASE
    -- If no checkpoints exist, use ID 1
      WHEN NOT EXISTS (
        SELECT
          1
        FROM
          checkpoints
      ) THEN 1
      -- If we've reached a new interval, increment the ID
      WHEN (NEW.height / 50) > (
        (
          SELECT
            height
          FROM
            checkpoints
          WHERE
            id = (
              SELECT
                MAX(id)
              FROM
                checkpoints
            )
        ) / 50
      ) THEN (
        SELECT
          MAX(id)
        FROM
          checkpoints
      ) + 1
      -- Otherwise, use the same ID as the latest checkpoint
      ELSE (
        SELECT
          MAX(id)
        FROM
          checkpoints
      )
    END,
    NEW.height,
    (
      WITH
        row_hash AS (
          SELECT
            hex(
              crypto_sha256 (
                concat (NEW.contract_id, NEW.path, NEW.value, NEW.deleted)
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
                  WHERE
                    id = (
                      SELECT
                        MAX(id)
                      FROM
                        checkpoints
                    )
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
ON CONFLICT (id) DO UPDATE
SET
  height = NEW.height,
  hash = excluded.hash;

END;
