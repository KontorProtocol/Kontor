use anyhow::{Context, Result};
use tracing::info;

use crate::runtime::{
    Runtime,
    filestorage::api::{
        accrue_storage_rewards, expire_challenges, generate_challenges_for_block,
        record_block_root, settle_expired_challenges,
    },
    staking::{
        address as staking_address,
        api::{
            distribute_ordering_reward, process_pending_validators,
            wave::{has_reward_recipients_call_expr, has_reward_recipients_parse_return_expr},
        },
    },
    token::api::mint_emission,
    wit::Signer,
};

pub async fn run_block_lifecycle(runtime: &mut Runtime, height: u64, hash: [u8; 32]) -> Result<()> {
    let core_signer = Signer::Core(Box::new(Signer::Nobody));
    let block_hash = hash.to_vec();
    runtime.set_context(height, None, None, None).await;
    let result = runtime
        .execute_system_view(&staking_address(), &has_reward_recipients_call_expr())
        .await?;
    let eligible = has_reward_recipients_parse_return_expr(&result);
    let emission = mint_emission(runtime, &core_signer, eligible).await??;
    // Credit the block-start active set before penalties can exhaust its last
    // member. A minted reward must not be stranded behind an empty recipient set.
    distribute_ordering_reward(runtime, &core_signer, emission.ordering_minted).await??;
    accrue_storage_rewards(runtime, &core_signer).await??;
    // Finalize the registry root for the block's `create_agreement`s (deferred
    // off the user's gas) before the challenge lifecycle. No-op if no files
    // were added this block.
    record_block_root(runtime, &core_signer)
        .await
        .context("Failed to record block root")?
        .map_err(|e| anyhow::anyhow!("{e:?}"))
        .context("record_block_root returned error")?;
    expire_challenges(runtime, &core_signer, height)
        .await
        .context("Failed to expire challenges")?;
    settle_expired_challenges(runtime, &core_signer).await??;
    let challenges = generate_challenges_for_block(runtime, &core_signer, height, block_hash)
        .await
        .context("Failed to generate challenges")?;
    if !challenges.is_empty() {
        info!(
            "Generated {} challenges at block height {}",
            challenges.len(),
            height
        );
    }

    let change = process_pending_validators(runtime, &core_signer, height)
        .await
        .context("Failed to call process_pending_validators")?
        .map_err(|e| anyhow::anyhow!("{e:?}"))
        .context("process_pending_validators returned error")?;
    if change.activated > 0 || change.deactivated > 0 {
        info!(
            "Validator set change at height {}: {} activated, {} deactivated",
            height, change.activated, change.deactivated
        );
    }
    Ok(())
}
