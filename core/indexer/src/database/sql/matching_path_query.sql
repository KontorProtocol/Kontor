SELECT path FROM (
  SELECT
  path
  FROM (
    SELECT
      *,
      ROW_NUMBER() OVER (ORDER BY height DESC, tx_id DESC) AS rank
    FROM
      contract_state
    WHERE
      contract_id = :contract_id
      AND path LIKE :base_path || '%'
  ) t
  WHERE
    rank = 1
    AND deleted = false
)
WHERE
  path REGEXP :path;
