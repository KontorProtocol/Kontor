use testlib::*;

pub mod native_filestorage_contract;
pub mod proof_verification;
pub mod proof_verification_e2e;

import!(
    name = "staking",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/staking/wit",
);

async fn bonded_identity(runtime: &mut Runtime) -> Result<Signer> {
    let signer = runtime.identity().await?;
    staking::add_stake(runtime, &signer, 1u64.try_into()?).await??;
    Ok(signer)
}
