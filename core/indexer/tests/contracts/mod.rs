mod amm_contract;
mod bls_attack_vectors;
mod bls_bulk_compose;
mod bls_key_derivation_and_registration;
mod bls_replay_protection;
mod bls_user_registry;
mod compose;
mod counter_contract;
mod crypto_contract;
mod error_classification;
mod fib_contract;
mod file_storage;
mod native_nft_contract;
mod native_token_attach_contract;
mod native_token_contract;
mod ops_contract;
mod pool_contract;
mod regtester_cluster;
mod shared_account_contract;
mod shared_cluster;
mod simulate_contract;
mod staking_contract;
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
    bls_replay_protection,
    bls_user_registry,
    compose,
    counter_contract,
    crypto_contract,
    fib_contract,
    native_nft_contract,
    native_token_attach_contract,
    native_token_contract,
    ops_contract,
    pool_contract,
    shared_account_contract,
    simulate_contract,
    token_contract,
    wit_contract,
}
