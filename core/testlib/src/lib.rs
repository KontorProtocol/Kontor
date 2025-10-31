use anyhow::Context;
use async_trait::async_trait;
use bon::Builder;
use glob::Paths;
pub use indexer::testlib_exports::*;
use indexer::{
    config::Config,
    database::{
        queries::{
            contract_has_state, get_transaction_by_txid, insert_contract, insert_processed_block,
            insert_transaction,
        },
        types::{BlockRow, ContractRow, TransactionRow},
    },
    reactor::types::Inst,
    reg_tester::{self, generate_taproot_address},
    runtime::{ComponentCache, Runtime as IndexerRuntime, Storage},
    test_utils::{new_mock_block_hash, new_mock_transaction, new_test_db},
};
use libsql::Connection;
use std::{collections::HashMap, path::PathBuf};
use tempfile::TempDir;
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

#[derive(Default, Builder)]
pub struct RuntimeConfig<'a> {
    pub contracts_dir: &'a str,
}

#[async_trait]
pub trait RuntimeImpl: Send {
    async fn identity(&mut self) -> Result<Signer>;
    async fn publish(
        &mut self,
        signer: &Signer,
        name: &str,
        contract: &[u8],
    ) -> Result<ContractAddress>;
    async fn wit(&self, contract_address: &ContractAddress) -> Result<String>;
    async fn execute(
        &mut self,
        signer: Option<&Signer>,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String>;
}

pub struct RuntimeLocal {
    runtime: IndexerRuntime,
    _db_dir: TempDir,
}

impl RuntimeLocal {
    pub async fn load_contracts(
        &mut self,
        signer: &Signer,
        contracts: &[(&str, &[u8])],
    ) -> Result<()> {
        let height = 1;
        let tx_index = 0;
        let conn = self.runtime.get_storage_conn();
        let tx = new_mock_transaction(1);
        if get_transaction_by_txid(&conn, &tx.txid.to_string())
            .await?
            .is_none()
        {
            insert_transaction(
                &conn,
                TransactionRow::builder()
                    .height(height)
                    .tx_index(0)
                    .txid(tx.txid.to_string())
                    .build(),
            )
            .await?;
        };

        for (name, bytes) in contracts {
            let contract_id = insert_contract(
                &conn,
                ContractRow::builder()
                    .height(height)
                    .tx_index(tx_index)
                    .name(name.to_string())
                    .bytes(bytes.to_vec())
                    .build(),
            )
            .await?;
            if !contract_has_state(&conn, contract_id).await? {
                self.runtime
                    .execute(
                        Some(signer),
                        &ContractAddress {
                            name: name.to_string(),
                            height,
                            tx_index,
                        },
                        "init()",
                    )
                    .await?;
            }
        }
        Ok(())
    }

    async fn make_storage(conn: Connection) -> Result<Storage> {
        insert_processed_block(
            &conn,
            BlockRow::builder()
                .height(1)
                .hash(new_mock_block_hash(1))
                .build(),
        )
        .await?;
        Ok(Storage::builder().height(1).tx_index(1).conn(conn).build())
    }

    pub async fn new() -> Result<Self> {
        let (_, writer, _db_dir) = new_test_db(&Config::new_na()).await?;
        let conn = writer.connection();
        let storage = Self::make_storage(conn).await?;
        storage.store_native_contracts().await?;
        let component_cache = ComponentCache::new();
        let runtime = IndexerRuntime::new(storage, component_cache).await?;
        Ok(Self { runtime, _db_dir })
    }
}

#[async_trait]
impl RuntimeImpl for RuntimeLocal {
    async fn identity(&mut self) -> Result<Signer> {
        let (address, ..) = generate_taproot_address();
        Ok(Signer::XOnlyPubKey(address.to_string()))
    }

    async fn publish(
        &mut self,
        signer: &Signer,
        name: &str,
        contract: &[u8],
    ) -> Result<ContractAddress> {
        self.load_contracts(signer, &[(name, contract)]).await?;
        Ok(ContractAddress {
            name: name.to_string(),
            height: 1,
            tx_index: 0,
        })
    }

    async fn wit(&self, contract_address: &ContractAddress) -> Result<String> {
        let contract_id = self
            .runtime
            .storage
            .contract_id(contract_address)
            .await?
            .ok_or(anyhow!("Contract not found"))?;
        self.runtime.storage.component_wit(contract_id).await
    }

    async fn execute(
        &mut self,
        signer: Option<&Signer>,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String> {
        let result = self.runtime.execute(signer, contract_address, expr).await;
        self.runtime.storage.op_index += 1;
        result
    }
}

pub struct RuntimeRegtest {
    reg_tester: RegTester,
    identities: HashMap<Signer, reg_tester::Identity>,
}

impl RuntimeRegtest {
    pub fn new(reg_tester: RegTester) -> Self {
        let identities = HashMap::new();
        Self {
            reg_tester,
            identities,
        }
    }
}

#[async_trait]
impl RuntimeImpl for RuntimeRegtest {
    async fn identity(&mut self) -> Result<Signer> {
        let identity = self.reg_tester.identity().await?;
        let signer = identity.signer();
        self.identities.insert(signer.clone(), identity);
        Ok(signer)
    }

    async fn publish(
        &mut self,
        signer: &Signer,
        name: &str,
        contract: &[u8],
    ) -> Result<ContractAddress> {
        let identity = self
            .identities
            .get_mut(signer)
            .ok_or_else(|| anyhow!("Identity not found"))?;
        let expr = self
            .reg_tester
            .instruction(
                identity,
                Inst::Publish {
                    name: name.to_string(),
                    bytes: contract.to_vec(),
                },
            )
            .await
            .map(|r| r.value)
            .context("Failed to publish contract")?;
        Ok(
            wasm_wave::from_str::<wasm_wave::value::Value>(&ContractAddress::wave_type(), &expr)?
                .into(),
        )
    }

    async fn wit(&self, contract_address: &ContractAddress) -> Result<String> {
        self.reg_tester.wit(contract_address).await
    }

    async fn execute(
        &mut self,
        signer: Option<&Signer>,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String> {
        if let Some(signer) = signer {
            let identity = self
                .identities
                .get_mut(signer)
                .ok_or_else(|| anyhow!("Identity not found"))?;
            self.reg_tester
                .instruction(
                    identity,
                    Inst::Call {
                        contract: contract_address.clone(),
                        expr: expr.to_string(),
                    },
                )
                .await
                .map(|r| r.value)
        } else {
            self.reg_tester.view(contract_address, expr).await
        }
    }
}

pub struct Runtime {
    pub contract_reader: ContractReader,
    pub runtime: Box<dyn RuntimeImpl>,
}

impl Runtime {
    pub async fn new_local(config: RuntimeConfig<'_>) -> Result<Self> {
        let runtime = RuntimeLocal::new().await?;
        Ok(Runtime {
            contract_reader: ContractReader::new(config.contracts_dir).await?,
            runtime: Box::new(runtime),
        })
    }

    pub async fn new_regtest(config: RuntimeConfig<'_>, reg_tester: RegTester) -> Result<Self> {
        let runtime = Box::new(RuntimeRegtest::new(reg_tester));
        Ok(Runtime {
            contract_reader: ContractReader::new(config.contracts_dir).await?,
            runtime,
        })
    }

    pub async fn identity(&mut self) -> Result<Signer> {
        self.runtime.identity().await
    }

    pub async fn publish(&mut self, signer: &Signer, name: &str) -> Result<ContractAddress> {
        self.publish_as(signer, name, name).await
    }

    pub async fn wit(&mut self, contract_address: &ContractAddress) -> Result<String> {
        self.runtime.wit(contract_address).await
    }

    pub async fn publish_as(
        &mut self,
        signer: &Signer,
        name: &str,
        alias: &str,
    ) -> Result<ContractAddress> {
        let name = name.replace("_", "-");
        let alias = alias.replace("_", "-");
        let contract = self.contract_reader.read(&name).await?.ok_or(anyhow!(
            "Contract not found: {} in {}",
            name,
            self.contract_reader.dir,
        ))?;
        self.runtime.publish(signer, &alias, &contract).await
    }

    pub async fn execute(
        &mut self,
        signer: Option<&Signer>,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String> {
        self.runtime.execute(signer, contract_address, expr).await
    }
}
