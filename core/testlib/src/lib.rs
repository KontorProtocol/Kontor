pub use indexer::runtime::wit::kontor::built_in::{error::Error, foreign::ContractAddress};
use indexer::{
    config::Config,
    database::{queries::insert_block, types::BlockRow},
    runtime::{ComponentCache, Runtime as IndexerRuntime, Storage, load_native_contracts},
    test_utils::{new_mock_block_hash, new_test_db},
};
use libsql::Connection;
pub use stdlib::import;
pub use tokio::test;

pub use anyhow::Result;

#[derive(Clone)]
pub struct CallContext {
    height: i64,
    tx_id: i64,
}

#[derive(Default)]
pub struct RuntimeConfig {
    call_context: Option<CallContext>,
}

impl RuntimeConfig {
    pub fn get_call_context(&self) -> CallContext {
        self.call_context.clone().unwrap_or(CallContext {
            height: 1,
            tx_id: 1,
        })
    }
}

pub struct Runtime {
    runtime: IndexerRuntime,
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

    pub async fn new(config: RuntimeConfig) -> Result<Self> {
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
        load_native_contracts(&runtime).await?;
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
        self.runtime.execute(signer, contract_address, expr).await
    }
}
