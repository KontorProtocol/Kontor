use std::sync::{Arc, Mutex, OnceLock};

use anyhow::Result;
use indexer::reg_tester::RegTesterCluster;
use testlib::{ContractReader, Runtime};

static CLUSTER: Mutex<Option<Arc<RegTesterCluster>>> = Mutex::new(None);
static INIT: tokio::sync::OnceCell<()> = tokio::sync::OnceCell::const_new();
/// Process-lifetime runtime that owns everything the shared cluster spawns.
/// Setup must NOT run on the calling test's `#[tokio::test]` runtime: the node
/// children and their stdout-drain tasks bind to the runtime driving `setup`,
/// and when that first test finishes its runtime is destroyed — the drains
/// abort, so every node's stdout pipe loses its reader. From that moment all
/// node logs vanish from test output (each write becomes a `[tracing-subscriber]
/// ... Broken pipe` stderr complaint), which is exactly what blinded the
/// cluster-flake CI logs: a node's death reason went down the broken pipe.
static CLUSTER_RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

pub async fn get() -> Arc<RegTesterCluster> {
    INIT.get_or_init(|| async {
        let _ = tracing_subscriber::fmt().with_env_filter("info").try_init();
        // 300 registered is NOT over-provisioned: measured consumption across the
        // ~24 sharing tests is ~256 registered (the AMM/pool tests create many
        // accounts), so this is ~17% headroom over the real peak. Do not shrink it —
        // `pop_registered` fails loud on exhaustion. Each pre-created registered
        // identity is a serial BLS RegistrationProof + reveal tx on this OnceCell
        // setup path that blocks every `regtest_*` test, so raise (not lower) these
        // if a new batch of tests pushes consumption past the pool.
        let (tx, rx) = tokio::sync::oneshot::channel();
        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_multi_thread()
                .enable_all()
                .build()
                .expect("Failed to build shared-cluster runtime");
            let cluster = rt.block_on(RegTesterCluster::setup(3, 300, 50));
            // Keep the runtime alive for the whole process so the node
            // children, their stdout drains, and any cluster-internal tasks
            // outlive the test that happened to trigger this OnceCell.
            CLUSTER_RT.set(rt).ok();
            let _ = tx.send(cluster);
        });
        let cluster = rx
            .await
            .expect("shared-cluster setup thread died")
            .expect("Failed to setup RegTesterCluster");
        *CLUSTER.lock().unwrap() = Some(Arc::new(cluster));
    })
    .await;
    CLUSTER.lock().unwrap().as_ref().unwrap().clone()
}

#[dtor::dtor]
unsafe fn cleanup() {
    let cluster = {
        let mut guard = match CLUSTER.lock() {
            Ok(g) => g,
            Err(e) => e.into_inner(),
        };
        guard.take().and_then(|arc| Arc::try_unwrap(arc).ok())
    };
    // Tear down on the runtime that spawned the children — their `Child`
    // handles are registered with its reaper, so `wait()` is only reliable
    // there.
    if let Some(cluster) = cluster
        && let Some(rt) = CLUSTER_RT.get()
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
