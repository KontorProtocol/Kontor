mod amm_contract;
mod bls_attack_vectors;
mod bls_bulk_compose;
mod bls_key_derivation_and_registration;
mod bls_replay_protection;
mod bls_user_registry;
mod compose;
mod counter_contract;
mod crypto_contract;
mod fib_contract;
mod file_storage;
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

#[tokio::test]
async fn regtest_file_storage() -> anyhow::Result<()> {
    if std::env::var("REGTEST").is_err() {
        return Ok(());
    }
    let mut runtime = shared_cluster::new_runtime().await?;
    file_storage::test_file_storage_regtest_e2e(&mut runtime).await?;
    file_storage::test_file_storage_regtest(&mut runtime).await
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
    native_token_attach_contract,
    native_token_contract,
    ops_contract,
    pool_contract,
    shared_account_contract,
    simulate_contract,
    token_contract,
    wit_contract,
}
