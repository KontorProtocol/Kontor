use anyhow::Result;
use bon::Builder;
use futures_util::Stream;
use libsql::Connection;

use crate::{
    database::{
        queries::{
            delete_contract_state, delete_matching_paths, exists_contract_state,
            get_contract_bytes_by_id, get_contract_id_from_address,
            get_latest_contract_state_value, insert_contract_result, insert_contract_state,
            matching_path, path_prefix_filter_contract_state,
        },
        types::{ContractResultRow, ContractStateRow},
    },
    runtime::{ContractAddress, counter::Counter, stack::Stack},
};

#[derive(Builder, Clone)]
pub struct Storage {
    pub conn: Connection,
    #[builder(default = Counter::builder().build())]
    pub savepoint_counter: Counter,
    #[builder(default = Stack::builder().build())]
    pub savepoint_stack: Stack<u64>,
    #[builder(default = 1)]
    pub tx_id: i64,
    #[builder(default = 1)]
    pub height: i64,
    #[builder(default = 0)]
    pub input_index: i64,
    #[builder(default = 0)]
    pub op_index: i64,
}

impl Storage {
    pub async fn get(&self, fuel: u64, contract_id: i64, path: &str) -> Result<Option<Vec<u8>>> {
        Ok(get_latest_contract_state_value(&self.conn, fuel, contract_id, path).await?)
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

    pub async fn delete_matching_paths(&self, contract_id: i64, regexp: &str) -> Result<u64> {
        Ok(delete_matching_paths(&self.conn, contract_id, self.height, self.tx_id, regexp).await?)
    }

    pub async fn contract_id(&self, contract_address: &ContractAddress) -> Result<Option<i64>> {
        Ok(get_contract_id_from_address(&self.conn, contract_address).await?)
    }

    pub async fn contract_bytes(&self, contract_id: i64) -> Result<Option<Vec<u8>>> {
        Ok(get_contract_bytes_by_id(&self.conn, contract_id).await?)
    }

    pub async fn insert_contract_result(
        &self,
        contract_id: i64,
        ok: bool,
        value: Option<String>,
    ) -> Result<i64> {
        Ok(insert_contract_result(
            &self.conn,
            ContractResultRow::builder()
                .tx_id(self.tx_id)
                .input_index(self.input_index)
                .op_index(self.op_index)
                .contract_id(contract_id)
                .height(self.height)
                .ok(ok)
                .maybe_value(value)
                .build(),
        )
        .await?)
    }

    pub async fn keys(
        &self,
        contract_id: i64,
        path: String,
    ) -> Result<impl Stream<Item = Result<String, libsql::Error>> + Send + 'static> {
        Ok(path_prefix_filter_contract_state(&self.conn, contract_id, path).await?)
    }

    pub async fn savepoint(&self) -> Result<()> {
        if self.savepoint_stack.is_empty().await {
            self.conn.execute("BEGIN TRANSACTION", ()).await?;
            self.savepoint_stack.push(0).await?;
            self.savepoint_counter.reset().await;
        } else {
            let i = self.savepoint_counter.get().await;
            self.conn.execute(&format!("SAVEPOINT S{}", i), ()).await?;
            self.savepoint_stack.push(i).await?;
        }
        self.savepoint_counter.increment().await;
        Ok(())
    }

    pub async fn commit(&self) -> Result<()> {
        match self.savepoint_stack.pop().await {
            Some(0) => self.conn.execute("COMMIT", ()).await?,
            Some(i) => self.conn.execute(&format!("RELEASE S{}", i), ()).await?,
            None => 0,
        };
        Ok(())
    }

    pub async fn rollback_transaction(&self) -> Result<()> {
        self.savepoint_stack.clear().await;
        self.conn.execute("ROLLBACK", ()).await?;
        Ok(())
    }

    pub async fn rollback(&self) -> Result<()> {
        match self.savepoint_stack.pop().await {
            Some(0) => self.conn.execute("ROLLBACK", ()).await?,
            Some(i) => {
                self.conn
                    .execute(&format!("ROLLBACK TO S{}", i), ())
                    .await?
            }
            None => 0,
        };
        Ok(())
    }
}
