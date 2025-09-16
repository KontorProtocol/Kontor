use std::{env::current_dir, path::Path};

use bon::Builder;
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
        ComponentCache, Runtime as IndexerRuntime, Storage, load_contracts, load_native_contracts,
        wit::Signer,
    },
    test_utils::{new_mock_block_hash, new_test_db},
};
use libsql::Connection;
pub use macros::{import_test as import, interface_test as interface};

use anyhow::anyhow;
pub use anyhow::{Error as AnyhowError, Result};
use tokio::{fs::File, io::AsyncReadExt, task};

async fn find_first_file_with_extension(dir: &Path, extension: &str) -> Option<String> {
    let pattern = format!("{}/*.{}", dir.display(), extension.trim_start_matches('.'));

    task::spawn_blocking(move || {
        glob::glob(&pattern)
            .expect("Invalid glob pattern")
            .filter_map(Result::ok)
            .find(|path| path.is_file())
            .and_then(|path| path.file_name().map(|s| s.to_string_lossy().into_owned()))
    })
    .await
    .unwrap_or_default()
}

async fn read_file(path: &Path) -> Result<Vec<u8>> {
    let mut file = File::open(path).await?;
    let mut buffer = Vec::new();
    file.read_to_end(&mut buffer).await?;
    Ok(buffer)
}

async fn read_wasm_file(cd: &Path) -> Result<Vec<u8>> {
    let release_dir = cd.join("target/wasm32-unknown-unknown/release");
    let ext = ".wasm.br";
    let file_name = find_first_file_with_extension(&release_dir, ext)
        .await
        .ok_or(anyhow!(
            "Could not find file with extension: {}@{:?}",
            ext,
            release_dir
        ))?;
    read_file(&release_dir.join(file_name)).await
}

pub async fn contract_bytes() -> Result<Vec<u8>> {
    let mut cd = current_dir()?;
    cd.pop();
    read_wasm_file(&cd).await
}

pub async fn dep_contract_bytes(dir_name: &str) -> Result<Vec<u8>> {
    let mut cd = current_dir()?;
    cd.pop();
    cd.pop();
    read_wasm_file(&cd.join(dir_name)).await
}

#[derive(Clone)]
pub struct CallContext {
    height: i64,
    tx_id: i64,
}

#[derive(Default, Builder)]
pub struct RuntimeConfig<'a> {
    call_context: Option<CallContext>,
    contracts: Option<&'a [(&'a str, &'a [u8])]>,
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
        let na = "n/a".to_string();
        let (_, writer, _test_db_dir) = new_test_db(&Config {
            bitcoin_rpc_url: na.clone(),
            bitcoin_rpc_user: na.clone(),
            bitcoin_rpc_password: na.clone(),
            zmq_address: na,
            api_port: 0,
            data_dir: "will be set".into(),
            starting_block_height: 1,
        })
        .await?;
        let conn = writer.connection();
        let storage = Runtime::make_storage(config.get_call_context(), conn).await?;
        let component_cache: ComponentCache = ComponentCache::new();
        let runtime = IndexerRuntime::new(storage, component_cache).await?;
        if let Some(contracts) = config.contracts {
            load_contracts(&runtime, contracts).await?;
        } else {
            load_native_contracts(&runtime).await?;
        }
        Ok(Self { runtime })
    }

    pub async fn set_call_context(&mut self, context: CallContext) -> Result<()> {
        self.runtime
            .set_storage(Runtime::make_storage(context, self.runtime.get_storage_conn()).await?);
        Ok(())
    }

    pub async fn execute(
        &self,
        signer: Option<&str>,
        contract_address: &ContractAddress,
        expr: &str,
    ) -> Result<String> {
        self.runtime
            .execute(
                signer.map(|s| Signer::XOnlyPubKey(s.to_string())),
                contract_address,
                expr,
            )
            .await
    }
}
