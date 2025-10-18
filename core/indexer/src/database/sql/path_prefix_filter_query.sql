SELECT regexp_capture(path, '^' || :path || '\.([^.]*)(\.|$)', 1)
FROM (
  SELECT
    path,
    height,
    ROW_NUMBER() OVER (
      PARTITION BY regexp_capture(path, '^(' || :path || '\.[^.]*)(\.|$)', 1)
      ORDER BY height DESC
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
