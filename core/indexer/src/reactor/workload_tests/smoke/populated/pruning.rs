use anyhow::{Context, Result, ensure};
use libsql::{Connection, Value, params};

use crate::database::queries::{PRUNE_WATERMARK_KEY, get_meta_u64};

pub(super) struct PruningProof {
    contract: u64,
    path: Vec<u8>,
    removed_height: u64,
    cutoff: u64,
    retained: Vec<Value>,
}

impl PruningProof {
    pub(super) async fn capture(
        conn: &Connection,
        history_start: u64,
        cutoff: u64,
    ) -> Result<Self> {
        ensure!(get_meta_u64(conn, PRUNE_WATERMARK_KEY, 0).await? < cutoff);
        let mut rows = conn
            .query(
                "SELECT s.contract_id, s.path, s.height FROM contract_state s
             WHERE s.height >= ? AND s.height < ?
               AND EXISTS (SELECT 1 FROM contract_state n
                           WHERE n.contract_id = s.contract_id AND n.path = s.path
                             AND n.height > s.height AND n.height <= ?)
               AND (SELECT n.deleted FROM contract_state n
                    WHERE n.contract_id = s.contract_id AND n.path = s.path
                      AND n.height <= ? ORDER BY n.height DESC LIMIT 1) = 0
             ORDER BY s.contract_id, s.path, s.height LIMIT 1",
                params![history_start, cutoff, cutoff, cutoff],
            )
            .await?;
        let row = rows
            .next()
            .await?
            .context("populated history has no useful pruning candidate")?;
        let mut proof = Self {
            contract: row.get(0)?,
            path: row.get(1)?,
            removed_height: row.get(2)?,
            cutoff,
            retained: Vec::new(),
        };
        proof.retained = proof.retained_row(conn).await?;
        Ok(proof)
    }

    async fn retained_row(&self, conn: &Connection) -> Result<Vec<Value>> {
        let mut rows = conn
            .query(
                "SELECT height, value, deleted, depositor, deposited_gas FROM contract_state
             WHERE contract_id = ? AND path = ? AND height <= ?
             ORDER BY height DESC LIMIT 1",
                params![self.contract, self.path.clone(), self.cutoff],
            )
            .await?;
        let row = rows
            .next()
            .await?
            .context("populated pruning lost retained successor")?;
        (0..5)
            .map(|index| row.get_value(index).map_err(Into::into))
            .collect()
    }

    pub(super) async fn check(&self, conn: &Connection) -> Result<()> {
        // Block application can succeed even when best-effort pruning fails.
        ensure!(
            get_meta_u64(conn, PRUNE_WATERMARK_KEY, 0).await? == self.cutoff,
            "populated replay did not advance pruning watermark"
        );
        ensure!(
            conn.query(
                "SELECT 1 FROM contract_state WHERE contract_id = ? AND path = ? AND height = ?",
                params![self.contract, self.path.clone(), self.removed_height],
            )
            .await?
            .next()
            .await?
            .is_none(),
            "populated replay retained an obsolete state version"
        );
        ensure!(
            self.retained_row(conn).await? == self.retained,
            "populated replay changed the retained state version"
        );
        Ok(())
    }
}
