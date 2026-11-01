use anyhow::{Result, ensure};
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::serialize;
use bitcoin::{Block, BlockHash, Network, hashes::Hash};
use libsql::{Connection, params};
use tempfile::TempDir;

use super::{at, boundary, record, reserve, tip, validate};
use crate::database::certified_history::{context_bytes, initialize};
use crate::database::connection::new_connection;
use crate::protocol::coordinator::certified_decision::Decision;
use crate::protocol::coordinator::certified_input::{Command, EraContext, ExactInput};
use crate::protocol::identity::{ChainId, ProtocolId};

fn block(parent: BlockHash, nonce: u32) -> Block {
    let mut block = genesis_block(Network::Regtest);
    block.header.prev_blockhash = parent;
    block.header.nonce = nonce;
    block
}

// This fixture isolates the branch index, not certificate or closure validation.
// The callback qualification separately exercises authenticated append and ack.
async fn append_index(conn: &Connection, height: u64, input: &ExactInput) -> Result<()> {
    let tx = conn.transaction().await?;
    let authority = [9; 32];
    let decision = Decision {
        height,
        predecessor: [8; 32],
        committee: authority,
        descriptor: input.descriptor().clone(),
    };
    tx.execute(
        "INSERT OR IGNORE INTO certified_inputs (body_digest, body) VALUES (?1, ?2)",
        params![decision.descriptor.body_digest.to_vec(), input.body()],
    )
    .await?;
    tx.execute("INSERT INTO certified_decisions (height, decision_id, record, body_digest, committee_id, original_proof) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
        params![height.to_be_bytes().to_vec(), decision.id()?.to_vec(), decision.encode()?,
            decision.descriptor.body_digest.to_vec(), authority.to_vec(), Vec::<u8>::new()]).await?;
    record(&tx, &decision).await?;
    tx.execute(
        "UPDATE certified_history_state SET authenticated_height = ?1 WHERE singleton = 1",
        [height.to_be_bytes().to_vec()],
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn run() -> Result<()> {
    let directory = TempDir::new()?;
    let conn = new_connection(directory.path(), "branch-index.db").await?;
    initialize(&conn).await?;
    let context = EraContext {
        chain: ChainId([1; 32]),
        era: [2; 32],
        protocol: ProtocolId([3; 32]),
        codec: 1,
    };
    let tx = conn.transaction().await?;
    reserve(&tx, context, 100, true).await?;
    tx.commit().await?;
    ensure!(boundary(&conn, context).await?.parent.is_none());
    let tx = conn.transaction().await?;
    reserve(&tx, context, 100, false).await?;
    ensure!(reserve(&tx, context, 99, false).await.is_err());
    tx.commit().await?;
    let reopened = new_connection(directory.path(), "branch-index.db").await?;
    ensure!(boundary(&reopened, context).await?.first_height == 100);
    let empty = ExactInput::batch(context, 99, BlockHash::all_zeros(), &[])?;
    ensure!(
        validate(&conn, context, &empty.descriptor().command)
            .await
            .is_err()
    );
    let parent = BlockHash::from_byte_array([4; 32]);
    let a = block(parent, 1);
    for height in [0, 99, 101, u64::MAX] {
        let input = ExactInput::block(context, height, serialize(&a))?;
        ensure!(
            validate(&conn, context, &input.descriptor().command)
                .await
                .is_err()
        );
    }
    conn.execute(
        "INSERT INTO historical_committees (height, committee_id, record) VALUES (?1, ?2, ?3)",
        params![
            1u64.to_be_bytes().to_vec(),
            vec![9; 32],
            context_bytes(context)?
        ],
    )
    .await?;
    let first = ExactInput::block(context, 100, serialize(&a))?;
    conn.execute_batch("CREATE TRIGGER reject_branch BEFORE INSERT ON certified_bitcoin_branch BEGIN SELECT RAISE(ABORT, 'injected branch failure'); END;").await?;
    ensure!(append_index(&conn, 1, &first).await.is_err());
    ensure!(tip(&conn).await?.is_none());
    ensure!(boundary(&conn, context).await?.parent.is_none());
    ensure!(
        conn.query("SELECT 1 FROM certified_decisions", ())
            .await?
            .next()
            .await?
            .is_none()
    );
    ensure!(
        conn.query("SELECT 1 FROM certified_inputs", ())
            .await?
            .next()
            .await?
            .is_none()
    );
    conn.execute_batch("DROP TRIGGER reject_branch").await?;
    append_index(&conn, 1, &first).await?;
    ensure!(boundary(&reopened, context).await?.parent == Some(parent));
    ensure!(at(&conn, 100, 0).await?.is_none());
    ensure!(at(&conn, 100, 1).await? == Some(a.block_hash()));
    ensure!(
        validate(&conn, context, &first.descriptor().command)
            .await
            .is_err()
    );
    let b = block(a.block_hash(), 2);
    append_index(&conn, 2, &ExactInput::block(context, 101, serialize(&b))?).await?;
    let batch = ExactInput::batch(context, 101, b.block_hash(), &[])?;
    append_index(&conn, 3, &batch).await?;
    let replacement = block(parent, 3);
    append_index(
        &conn,
        4,
        &ExactInput::block(context, 100, serialize(&replacement))?,
    )
    .await?;
    ensure!(tip(&reopened).await? == Some((100, replacement.block_hash())));
    ensure!(at(&conn, 101, 3).await? == Some(b.block_hash()));
    ensure!(at(&conn, 101, 4).await?.is_none());
    ensure!(at(&conn, 100, 3).await? == Some(a.block_hash()));
    ensure!(at(&conn, 100, 4).await? == Some(replacement.block_hash()));
    ensure!(at(&conn, 100, 5).await.is_err());
    ensure!(
        validate(&conn, context, &batch.descriptor().command)
            .await
            .is_err()
    );
    for (height, parent) in [
        (100, BlockHash::from_byte_array([5; 32])),
        (101, a.block_hash()),
        (102, replacement.block_hash()),
    ] {
        let wrong = ExactInput::block(context, height, serialize(&block(parent, 4)))?;
        ensure!(append_index(&conn, 5, &wrong).await.is_err());
        ensure!(tip(&conn).await? == Some((100, replacement.block_hash())));
    }
    // Returning to a previously replaced block is legal when its current parent
    // matches. It creates a new interval rather than reviving old descendants.
    append_index(&conn, 5, &first).await?;
    ensure!(at(&conn, 100, 4).await? == Some(replacement.block_hash()));
    ensure!(at(&conn, 100, 5).await? == Some(a.block_hash()));
    ensure!(at(&conn, 101, 5).await?.is_none());
    ensure!(
        validate(
            &conn,
            context,
            &Command::Batch {
                anchor_height: 0,
                anchor_hash: BlockHash::all_zeros()
            }
        )
        .await
        .is_err()
    );
    Ok(())
}
