DELETE FROM contract_state
WHERE contract_id = :contract_id AND height = :height
AND path REGEXP :path_regexp
