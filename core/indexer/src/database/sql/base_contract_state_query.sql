-- `deleted` is the tie-breaker, not just `height DESC`: when this query is run
-- over a *prefix* (the `exists` variant), several distinct paths can share the
-- same top height — e.g. a struct-valued map bucket where a leaf is tombstoned
-- in the same block its sibling `count` is rewritten. Without the tie-breaker
-- the rank=1 winner among equal-height rows is unspecified, so a tombstone
-- could shadow a live sibling and make `exists` wrongly report the bucket
-- empty (a consensus hazard, since the order is not portable across SQLite
-- query plans). `deleted` (false < true) sorts the live row first, so any live
-- row at the top height wins. For exact-path lookups this is inert: the
-- `UNIQUE (contract_id, height, path)` constraint forbids two rows at one
-- height, so there is never a tie to break.
FROM (
  SELECT
    *,
    ROW_NUMBER() OVER (
      ORDER BY
        height DESC,
        deleted
    ) AS rank
  FROM
    contract_state
  WHERE
    contract_id = :contract_id
    AND path {{path_operator}} {{path_prefix}} :path {{path_suffix}}
) t
WHERE
  rank = 1
  AND deleted = false;
