use anyhow::Result;
use bon::Builder;
use libsql::Connection;

use crate::{
    database::{
        queries::{
            delete_contract_state, exists_contract_state, get_contract_bytes_by_id,
            get_contract_id_from_address, get_latest_contract_state_value, insert_contract_state,
            matching_path,
        },
        types::ContractStateRow,
    },
    runtime::ContractAddress,
};

#[derive(Builder, Clone)]
pub struct Storage {
    pub conn: Connection,
    #[builder(default = 0)]
    pub tx_id: i64,
    #[builder(default = 1)]
    pub height: i64,
}

impl Storage {
    pub async fn get(&self, contract_id: i64, path: &str) -> Result<Option<Vec<u8>>> {
        Ok(get_latest_contract_state_value(&self.conn, contract_id, path).await?)
    }

    pub async fn set(&self, contract_id: i64, path: &str, value: &[u8]) -> Result<()> {
        insert_contract_state(
            &self.conn,
            ContractStateRow::builder()
                .contract_id(contract_id)
                .tx_id(self.tx_id)
                .height(self.height)
                .path(path.to_string())
                .value(value.to_vec())
                .build(),
        )
        .await?;
        Ok(())
    }

    pub async fn delete(&self, contract_id: i64, path: &str) -> Result<bool> {
        Ok(delete_contract_state(&self.conn, self.height, self.tx_id, contract_id, path).await?)
    }

    pub async fn exists(&self, contract_id: i64, path: &str) -> Result<bool> {
        Ok(exists_contract_state(&self.conn, contract_id, path).await?)
    }

    pub async fn matching_path(&self, contract_id: i64, regexp: &str) -> Result<Option<String>> {
        Ok(matching_path(&self.conn, contract_id, regexp).await?)
    }

    pub async fn contract_id(&self, contract_address: &ContractAddress) -> Result<Option<i64>> {
        Ok(get_contract_id_from_address(&self.conn, contract_address).await?)
    }

    pub async fn contract_bytes(&self, contract_id: i64) -> Result<Option<Vec<u8>>> {
        Ok(get_contract_bytes_by_id(&self.conn, contract_id).await?)
    }
}
