use axum::extract::State;
use indexer_types::Info;

use crate::api::{Env, result::Result};
use crate::built_info;
use crate::database::queries::{
    get_checkpoint_latest, select_block_latest, select_latest_consensus_height,
};

async fn get_info(env: &Env) -> anyhow::Result<Info> {
    let conn = env.reader.connection().await?;
    let height = select_block_latest(&conn)
        .await?
        .map(|b| b.height)
        .unwrap_or((env.config.starting_block_height - 1) as i64);
    let checkpoint = get_checkpoint_latest(&conn).await?.map(|c| c.hash);
    let consensus_height = select_latest_consensus_height(&conn).await?;
    Ok(Info {
        version: built_info::PKG_VERSION.to_string(),
        target: built_info::TARGET.to_string(),
        network: env.config.network.to_string(),
        available: *env.available.read().await,
        height,
        checkpoint,
        consensus_height,
    })
}

pub async fn get_index(State(env): State<Env>) -> Result<Info> {
    Ok(get_info(&env).await?.into())
}

pub async fn stop(State(env): State<Env>) -> Result<Info> {
    env.cancel_token.cancel();
    Ok(get_info(&env).await?.into())
}
