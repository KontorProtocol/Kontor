use std::sync::{Arc, Mutex};

use anyhow::Result;
use indexer::reg_tester::RegTesterCluster;
use testlib::{ContractReader, Runtime};

static CLUSTER: Mutex<Option<Arc<RegTesterCluster>>> = Mutex::new(None);
static INIT: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();

pub async fn get() -> Arc<RegTesterCluster> {
    INIT.get_or_init(|| async {
        let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
        let cluster = RegTesterCluster::setup(3, 300, 50)
            .await
            .expect("Failed to setup RegTesterCluster");
        *CLUSTER.lock().unwrap() = Some(Arc::new(cluster));
    })
    .await;
    CLUSTER.lock().unwrap().as_ref().unwrap().clone()
}

#[ctor::dtor]
fn cleanup() {
    let cluster = {
        let mut guard = match CLUSTER.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        guard.take().and_then(|arc| Arc::try_unwrap(arc).ok())
    };
    if let Some(cluster) = cluster
        && let Ok(rt) = tokio::runtime::Runtime::new()
    {
        let _ = rt.block_on(cluster.teardown());
    }
}

/// Build a `Runtime` (a per-module reg-tester wrapping a contract
/// reader) from any `RegTesterCluster`. Works for both the shared
/// OnceCell instance below and dedicated per-test clusters used by
/// tests that need ledger isolation (e.g. `regtest_file_storage`).
pub async fn build_runtime(cluster: &RegTesterCluster) -> Result<Runtime> {
    let reg_tester = cluster.new_module_reg_tester().await?;
    let contracts_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../test-contracts")
        .canonicalize()
        .unwrap()
        .to_string_lossy()
        .to_string();
    let contract_reader = ContractReader::new(&contracts_dir).await?;
    Ok(Runtime::new_regtest_with_reader(
        contract_reader,
        reg_tester,
    ))
}

pub async fn new_runtime() -> Result<Runtime> {
    let cluster = get().await;
    build_runtime(&cluster).await
}
