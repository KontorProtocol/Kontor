-- Lists the immediate child keys of a map at `:path` (one row per distinct
-- child segment). `deleted` is filtered *after* ranking, not before: ranking
-- considers every row under a child key and keeps only the latest by height,
-- then drops that child if its latest row is a tombstone. This lets a
-- higher-height tombstone shadow a live row written for the same key in an
-- earlier block, so a key removed via `delete` disappears from iteration even
-- across heights. (Filtering `deleted = false` before ranking would instead
-- let the older live row win and the key would never go away.)
--
-- `deleted` is also the secondary `ORDER BY` key so that, when a child's
-- subtree has both a live and a tombstoned row at the *same* top height (e.g.
-- a struct-valued child whose `count` is rewritten in the same block one of
-- its leaves is tombstoned), the live row wins deterministically instead of
-- relying on SQLite's unspecified ordering of equal-`height` rows. For leaf
-- children there is at most one row per height (`UNIQUE (contract_id, height,
-- path)`), so the tie-breaker is inert there.
SELECT
  regexp_capture (path, '^' || :path || '\.([^.]*)(\.|$)', 1)
FROM
  (
    SELECT
      path,
      height,
      deleted,
      ROW_NUMBER() OVER (
        PARTITION BY
          regexp_capture (path, '^(' || :path || '\.[^.]*)(\.|$)', 1)
        ORDER BY
          height DESC,
          deleted
      ) AS rank
    FROM
      contract_state
    WHERE
      contract_id = :contract_id
      AND path LIKE :path || '%'
  ) t
WHERE
  rank = 1
  AND deleted = false;
