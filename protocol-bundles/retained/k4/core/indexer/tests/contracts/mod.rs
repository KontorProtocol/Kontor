mod amm_contract;
mod bls_attack_vectors;
mod bls_bulk_compose;
mod bls_key_derivation_and_registration;
mod bls_publisher_pays;
mod bls_replay_protection;
mod bls_user_registry;
mod compose;
mod counter_contract;
mod crypto_contract;
mod error_classification;
mod fib_contract;
mod file_storage;
mod native_nft_attach_contract;
mod native_nft_contract;
mod native_token_attach_contract;
mod native_token_contract;
mod native_token_sponsor_swap;
mod ops_contract;
mod pool_contract;
mod provenance_op;
mod regtester_cluster;
mod shared_account_contract;
mod shared_cluster;
mod simulate_contract;
mod simulate_errors;
mod staking_contract;
mod status_classification;
mod storage_deposit;
mod token_contract;
mod token_gate;
mod wit_contract;

use indexer::reg_tester::RegTesterCluster;

#[tokio::test]
async fn regtest_file_storage() -> anyhow::Result<()> {
    if std::env::var("REGTEST").is_err() {
        return Ok(());
    }
    // Dedicated cluster: `test_file_storage_regtest_e2e` uses precomputed
    // KontorPoR proof fixtures pinned to a specific `file_ledger.historical_roots`
    // trajectory. Sharing the cluster with other tests that mutate the file
    // ledger (e.g. `native_nft_contract` via `filestorage::create_agreement`)
    // would invalidate those roots and break the proofs.
    //
    // Its two CI drivers pop only ~45-50 registered / ~1 unregistered, so the pool
    // is sized to that plus headroom rather than copying the shared cluster's larger
    // pool — this dedicated chain pays its own full registration tax on a separate
    // bitcoind + 3 nodes, on every run.
    let cluster = RegTesterCluster::setup(3, 64, 10).await?;
    let mut runtime = shared_cluster::build_runtime(&cluster).await?;
    file_storage::test_file_storage_regtest_e2e(&mut runtime).await?;
    file_storage::test_file_storage_regtest(&mut runtime).await?;
    cluster.teardown().await
}

testlib::regtest_tests! {
    amm_contract,
    bls_attack_vectors,
    bls_bulk_compose,
    bls_key_derivation_and_registration,
    bls_publisher_pays,
    bls_replay_protection,
    bls_user_registry,
    compose,
    counter_contract,
    crypto_contract,
    fib_contract,
    native_token_attach_contract,
    native_token_contract,
    native_token_sponsor_swap,
    ops_contract,
    pool_contract,
    provenance_op,
    shared_account_contract,
    simulate_contract,
    simulate_errors,
    status_classification,
    storage_deposit,
    token_contract,
    wit_contract,
}

#[tokio::test]
async fn regtest_native_nft() -> anyhow::Result<()> {
    if std::env::var("REGTEST").is_err() {
        return Ok(());
    }
    // Runs on the SHARED cluster (no dedicated chain). `native_nft_contract`
    // asserts absolute global nft state (`total_minted`, `list_nfts` order +
    // pagination), which is safe here because nft state is mutated by ONLY these
    // two tests — nothing else on the shared cluster calls `nft::mint` (token /
    // shared-account touch `token::mint`, a different contract). They run as one
    // sequential driver: nft_contract first against an empty nft store (so its
    // exact-set assertions hold), then attach. Teardown is the cluster's dtor.
    let cluster = shared_cluster::get().await;
    let mut runtime = shared_cluster::build_runtime(&cluster).await?;
    native_nft_contract::test_native_nft_contract(&mut runtime).await?;
    native_nft_attach_contract::test_native_nft_attach_contract(&mut runtime).await?;
    Ok(())
}
