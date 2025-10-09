use std::{collections::HashMap, path::PathBuf};

use bon::Builder;
use glob::Paths;
pub use indexer::runtime::wit::kontor::built_in::{
    error::Error,
    foreign::ContractAddress,
    numbers::{Decimal, Integer},
};
pub use indexer::runtime::{CheckedArithmetics, numerics as numbers};
use indexer::{
    config::Config,
    database::{queries::insert_block, types::BlockRow},
    runtime::{
        ComponentCache, Runtime as IndexerRuntime, Storage, fuel::FuelGauge, load_contracts,
        wit::Signer,
    },
    test_utils::{new_mock_block_hash, new_test_db},
};
use libsql::Connection;
pub use macros::{import_test as import, interface_test as interface};

pub use anyhow::{Error as AnyhowError, Result, anyhow};
use tokio::{fs::File, io::AsyncReadExt, task};

pub struct ContractReader {
    dir: String,
    contracts: HashMap<String, PathBuf>,
}

impl ContractReader {
    pub async fn new(dir: &str) -> Result<Self> {
        let paths = Self::find_contracts(dir).await?;
        Ok(Self {
            dir: dir.to_string(),
            contracts: paths
                .filter_map(Result::ok)
                .filter(|p| p.is_file())
                .map(|p| {
                    {
                        (
                            p.file_name()
                                .expect("File has no name")
                                .to_string_lossy()
                                .strip_suffix(".wasm.br")
                                .unwrap()
                                .replace("_", "-")
                                .to_string(),
                            p,
                        )
                    }
                })
                .collect(),
        })
    }

    pub async fn read(&self, name: &str) -> Result<Option<Vec<u8>>> {
        Ok(if let Some(path) = self.contracts.get(name) {
            let mut file = File::open(path).await?;
            let mut buffer = Vec::new();
            file.read_to_end(&mut buffer).await?;
            Some(buffer)
        } else {
            None
        })
    }

    async fn find_contracts(dir: &str) -> Result<Paths> {
        let pattern = format!("{}/**/target/wasm32-unknown-unknown/release/*.wasm.br", dir);
        Ok(
            task::spawn_blocking(move || glob::glob(&pattern).expect("Invalid glob pattern"))
                .await?,
        )
    }
}

#[derive(Clone)]
pub struct CallContext {
    height: i64,
    tx_id: i64,
}

#[derive(Default, Builder)]
pub struct RuntimeConfig<'a> {
    contracts_dir: &'a str,
    call_context: Option<CallContext>,
}

impl RuntimeConfig<'_> {
    pub fn get_call_context(&self) -> CallContext {
        self.call_context.clone().unwrap_or(CallContext {
            height: 1,
            tx_id: 1,
        })
    }
}

pub struct Runtime {
    pub runtime: IndexerRuntime,
    pub contract_reader: ContractReader,
}

impl Runtime {
    async fn make_storage(call_context: CallContext, conn: Connection) -> Result<Storage> {
        insert_block(
            &conn,
            BlockRow::builder()
                .height(call_context.height)
                .hash(new_mock_block_hash(call_context.height as u32))
                .build(),
        )
        .await?;
        Ok(Storage::builder()
            .height(call_context.height)
            .tx_id(call_context.tx_id)
            .conn(conn)
            .build())
    }

    pub async fn new(config: RuntimeConfig<'_>) -> Result<Self> {
        let (_, writer, _test_db_dir) = new_test_db(&Config::new_na()).await?;
        let conn = writer.connection();
        let storage = Runtime::make_storage(config.get_call_context(), conn).await?;
        let component_cache = ComponentCache::new();
        let contract_reader = ContractReader::new(config.contracts_dir).await?;
        let runtime = IndexerRuntime::new(storage, component_cache).await?;
        Ok(Self {
            runtime,
            contract_reader,
        })
    }

    pub async fn publish(&self, name: &str) -> Result<ContractAddress> {
        self.publish_as(name, name).await
    }

    pub async fn publish_as(&self, name: &str, alias: &str) -> Result<ContractAddress> {
        let name = name.replace("_", "-");
        let alias = alias.replace("_", "-");
        let contract = self.contract_reader.read(&name).await?.ok_or(anyhow!(
            "Contract not found: {} in {}",
            name,
            self.contract_reader.dir,
        ))?;
        load_contracts(&self.runtime, &[(&alias, &contract)]).await?;
        Ok(ContractAddress {
            name: alias,
            height: 0,
            tx_index: 0,
        })
    }

    pub async fn set_call_context(&mut self, context: CallContext) -> Result<()> {
        self.runtime
            .set_storage(Runtime::make_storage(context, self.runtime.get_storage_conn()).await?);
        Ok(())
    }

    pub async fn set_starting_fuel(&mut self, starting_fuel: u64) {
        self.runtime.set_starting_fuel(starting_fuel)
    }

    pub async fn execute(
        &mut self,
        signer: Option<&str>,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String> {
        let result = self
            .runtime
            .execute(
                signer.map(|s| Signer::XOnlyPubKey(s.to_string())),
                contract_address,
                expr,
            )
            .await;
        self.runtime.storage.op_index += 1;
        result
    }

    pub fn fuel_gauge(&self) -> FuelGauge {
        self.runtime
            .gauge
            .clone()
            .expect("Test environment runtime doesn't have fuel gauge")
    }
}
