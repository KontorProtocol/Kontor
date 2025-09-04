-- SELECT path
-- FROM (
--   SELECT
--     path,
--     height,
--     tx_id,
--     ROW_NUMBER() OVER (PARTITION BY path ORDER BY height DESC, tx_id DESC) AS rank
--   FROM
--     contract_state
--   WHERE
--     contract_id = :contract_id
--     AND path LIKE :path || '%'
--     AND deleted = false
-- ) t
-- WHERE
--   rank = 1;
SELECT path
FROM (
  SELECT
    path,
    height,
    tx_id,
    ROW_NUMBER() OVER (
      PARTITION BY 
        CASE 
          WHEN INSTR(SUBSTR(path, LENGTH(:path) + 2), '.') > 0 
          THEN SUBSTR(path, 1, LENGTH(:path) + INSTR(SUBSTR(path, LENGTH(:path) + 2), '.'))
          ELSE path
        END
      ORDER BY height DESC, tx_id DESC
    ) AS rank
  FROM
    contract_state
  WHERE
    contract_id = :contract_id
    AND path LIKE :path || '%'
    AND deleted = false
) t
WHERE
  rank = 1;