use anyhow::Result;
use bon::Builder;
use libsql::Connection;

use crate::database::{
    queries::{delete_contract_state, get_latest_contract_state_value, insert_contract_state},
    types::ContractStateRow,
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
    pub async fn get(&self, contract_id: &str, path: &str) -> Result<Option<Vec<u8>>> {
        Ok(get_latest_contract_state_value(&self.conn, contract_id, path).await?)
    }

    pub async fn set(&self, contract_id: &str, path: &str, value: &[u8]) -> Result<()> {
        insert_contract_state(
            &self.conn,
            ContractStateRow::builder()
                .contract_id(contract_id.to_string())
                .tx_id(self.tx_id)
                .height(self.height)
                .path(path.to_string())
                .value(value.to_vec())
                .build(),
        )
        .await?;
        Ok(())
    }

    pub async fn delete(&self, contract_id: &str, path: &str) -> Result<bool> {
        Ok(delete_contract_state(&self.conn, self.height, self.tx_id, contract_id, path).await?)
    }
}
