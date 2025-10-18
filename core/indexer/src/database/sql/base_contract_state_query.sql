FROM (
  SELECT
    *,
    ROW_NUMBER() OVER (ORDER BY height DESC) AS rank
  FROM
    contract_state
  WHERE
    contract_id = :contract_id
    AND path {{path_operator}} {{path_prefix}} :path {{path_suffix}}
) t
WHERE
  rank = 1
  AND deleted = false;
