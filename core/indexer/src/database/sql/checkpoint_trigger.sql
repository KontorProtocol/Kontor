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
                -- `|` delimits the fields so the digest is unambiguous: contract_id
                -- and deleted are integers, path/value are hex'd (BLOB -> deterministic
                -- text), and `|` appears in none of those charsets, so distinct
                -- (contract_id, path, value, deleted) tuples can't share a hash input.
                concat (
                  NEW.contract_id,
                  '|',
                  hex(NEW.path),
                  '|',
                  hex(NEW.value),
                  '|',
                  NEW.deleted,
                  '|',
                  -- depositor is a deterministic rowid (or NULL → '' here); it's
                  -- the floor basis, which is consensus state, so it must be hashed.
                  NEW.depositor,
                  '|',
                  -- the deposit amount (decimal string, no `|` in its charset, or
                  -- NULL → '') is part of the floor, so it's hashed too.
                  NEW.deposited_amount
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
