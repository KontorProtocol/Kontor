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

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/token/wit",
);

async fn bonded_identity(runtime: &mut Runtime) -> Result<Signer> {
    let signer = runtime.identity().await?;
    token::mint(runtime, &signer, 100u64.try_into()?).await??;
    staking::add_stake(runtime, &signer, 100u64.try_into()?).await??;
    Ok(signer)
}
