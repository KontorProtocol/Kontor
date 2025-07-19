FROM
  contract_state t1
WHERE
  contract_id = :contract_id
  AND path LIKE :path || '%'
  AND deleted = false
  AND (height, tx_id) = (
    SELECT
      height,
      tx_id
    FROM
      contract_state t2
    WHERE
      t2.contract_id = t1.contract_id
      AND t2.path LIKE t1.path || '%'
    ORDER BY
      height DESC,
      tx_id DESC
    LIMIT
      1
  );

