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
mod regtester_cluster;
mod shared_account_contract;
mod shared_cluster;
mod simulate_contract;
mod simulate_errors;
mod staking_contract;
mod staking_slash;
mod status_classification;
mod token_contract;
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
    let cluster = RegTesterCluster::setup(3, 300, 50).await?;
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
    shared_account_contract,
    simulate_contract,
    simulate_errors,
    status_classification,
    token_contract,
    wit_contract,
}

#[tokio::test]
async fn regtest_native_nft() -> anyhow::Result<()> {
    if std::env::var("REGTEST").is_err() {
        return Ok(());
    }
    // Dedicated cluster: `native_nft_contract` asserts on absolute counts
    // (total_minted, list_nfts ordering) that would be wrong if the attach
    // test's mint ran first on the shared cluster. Running both tests
    // sequentially on their own chain gives each test a clean slate.
    let cluster = RegTesterCluster::setup(3, 300, 50).await?;
    let mut runtime = shared_cluster::build_runtime(&cluster).await?;
    native_nft_contract::test_native_nft_contract(&mut runtime).await?;
    native_nft_attach_contract::test_native_nft_attach_contract(&mut runtime).await?;
    cluster.teardown().await
}
