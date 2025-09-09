DELETE FROM contract_state
WHERE contract_id = :contract_id AND height = :height AND tx_id = :tx_id
AND path REGEXP :path_regexp