use anyhow::{Context, Result, anyhow};
use bon::Builder;
use futures_util::Stream;
use libsql::Connection;
use regex::bytes::RegexBuilder;
use std::io::Read;
use wit_component::{ComponentEncoder, WitPrinter};

use crate::{
    database::{
        queries::{
            delete_contract_state, delete_matching_paths, exists_contract_state,
            get_contract_address_from_id, get_contract_bytes_by_id, get_contract_id_from_address,
            get_latest_contract_state_value, insert_contract, insert_contract_result,
            insert_contract_state, matching_path, path_prefix_filter_contract_state,
        },
        types::{ContractResultRow, ContractRow, ContractStateRow},
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
    pub tx_index: i64,
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
                .tx_index(self.tx_index)
                .height(self.height)
                .path(path.to_string())
                .value(value.to_vec())
                .build(),
        )
        .await?;
        Ok(())
    }

    pub async fn delete(&self, contract_id: i64, path: &str) -> Result<bool> {
        Ok(
            delete_contract_state(&self.conn, self.height, self.tx_index, contract_id, path)
                .await?,
        )
    }

    pub async fn exists(&self, contract_id: i64, path: &str) -> Result<bool> {
        Ok(exists_contract_state(&self.conn, contract_id, path).await?)
    }

    pub async fn extend_path_with_match(
        &self,
        contract_id: i64,
        path: &str,
        regexp: &str,
    ) -> Result<Option<String>> {
        Ok(matching_path(&self.conn, contract_id, path, regexp).await?)
    }

    pub async fn delete_matching_paths(&self, contract_id: i64, regexp: &str) -> Result<u64> {
        Ok(delete_matching_paths(&self.conn, contract_id, self.height, regexp).await?)
    }

    pub async fn contract_id(&self, contract_address: &ContractAddress) -> Result<Option<i64>> {
        Ok(get_contract_id_from_address(&self.conn, contract_address).await?)
    }

    pub async fn contract_address(&self, contract_id: i64) -> Result<Option<ContractAddress>> {
        Ok(get_contract_address_from_id(&self.conn, contract_id).await?)
    }

    pub async fn contract_bytes(&self, contract_id: i64) -> Result<Option<Vec<u8>>> {
        Ok(get_contract_bytes_by_id(&self.conn, contract_id).await?)
    }

    pub async fn component_bytes(&self, contract_id: i64) -> Result<Vec<u8>> {
        let compressed_bytes = self
            .contract_bytes(contract_id)
            .await?
            .ok_or(anyhow!("Contract not found when trying to load component"))?;
        let module_bytes = tokio::task::spawn_blocking(move || {
            let mut decompressor = brotli::Decompressor::new(&compressed_bytes[..], 4096);
            let mut module_bytes = Vec::new();
            decompressor.read_to_end(&mut module_bytes)?;
            Ok::<_, std::io::Error>(module_bytes)
        })
        .await??;

        ComponentEncoder::default()
            .module(&module_bytes)?
            .validate(true)
            .encode()
    }

    pub async fn component_wit(&self, contract_id: i64) -> Result<String> {
        let bs = self.component_bytes(contract_id).await?;
        let decoded = wit_component::decode(&bs).context("Failed to decode component")?;
        let mut printer = WitPrinter::default();
        printer
            .print(decoded.resolve(), decoded.package(), &[])
            .context("Failed to print component")?;
        let wit = format!("{}", printer.output);
        // regexr.com/8i6dk
        let re = RegexBuilder::new(r"(\n^.*(borrow<core-context>|export init:|\{\s*core-context\s*\}).*$|[,]{0,1}\s*core-context[,]{0,1}\s*)")
            .multi_line(true)
            .build()?;
        let wit =
            String::from_utf8_lossy(&re.replace_all(wit.as_bytes(), "".as_bytes())).into_owned();
        Ok(wit)
    }

    pub async fn insert_contract(&self, name: &str, bytes: &[u8]) -> Result<i64> {
        Ok(insert_contract(
            &self.conn,
            ContractRow::builder()
                .height(self.height)
                .tx_index(self.tx_index)
                .name(name.to_string())
                .bytes(bytes.to_vec())
                .build(),
        )
        .await?)
    }

    pub fn build_contract_result_row(
        &self,
        result_index: i64,
        contract_id: i64,
        func: String,
        gas: i64,
        value: Option<String>,
    ) -> ContractResultRow {
        ContractResultRow::builder()
            .contract_id(contract_id)
            .height(self.height)
            .tx_index(self.tx_index)
            .input_index(self.input_index)
            .op_index(self.op_index)
            .result_index(result_index)
            .func(func)
            .gas(gas)
            .maybe_value(value)
            .build()
    }

    pub async fn insert_contract_result(
        &self,
        result_index: i64,
        contract_id: i64,
        func: String,
        gas: i64,
        value: Option<String>,
    ) -> Result<i64> {
        Ok(insert_contract_result(
            &self.conn,
            self.build_contract_result_row(result_index, contract_id, func, gas, value),
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
