use anyhow::{Context, Result, ensure};
use indexer_types::ContractAddress;
use libsql::{Connection, params};

use super::super::{ANCHOR_HEIGHT, PRUNE_RETAIN, SMOKE_HEIGHT};
use super::configuration::MixedConfig;
use super::pagination;
use crate::consensus::finality_types::FINALITY_WINDOW;
use crate::database::queries::{footprint_cache_get, live_deposit_gas_sum};
use crate::runtime::Runtime;

const FIRST_HEIGHT: u64 = 89;
pub(super) fn prune_height() -> u64 {
    prune_height_at(SMOKE_HEIGHT)
}

pub(super) fn prune_height_at(height: u64) -> u64 {
    height.saturating_sub(PRUNE_RETAIN.max(FINALITY_WINDOW))
}

pub(super) struct HistoryPopulation {
    pub(super) contract: ContractAddress,
    contract_id: u64,
    live_keys: usize,
    historical_rows: usize,
}

impl HistoryPopulation {
    pub(super) async fn restore(
        runtime: &mut Runtime,
        config: MixedConfig,
    ) -> Result<Option<Self>> {
        config.validate()?;
        if config.historical_rows == 0 {
            return Ok(None);
        }
        let contract = ContractAddress {
            name: "mixedpages".into(),
            height: 0,
            tx_index: 7,
        };
        let contract_id = runtime
            .storage
            .contract_id(&contract)
            .await?
            .context("saved history contract missing")?;
        let population = Self {
            contract,
            contract_id,
            live_keys: config.live_keys,
            historical_rows: config.historical_rows,
        };
        population
            .check_at(&runtime.get_storage_conn(), None)
            .await?;
        Ok(Some(population))
    }

    pub(super) async fn prepare(
        runtime: &mut Runtime,
        config: MixedConfig,
    ) -> Result<Option<Self>> {
        config.validate()?;
        if config.historical_rows == 0 {
            return Ok(None);
        }
        let contract = pagination::publish(runtime, 0).await?;
        let contract_id = runtime
            .storage
            .contract_id(&contract)
            .await?
            .context("missing history fixture contract")?;
        Ok(Some(Self {
            contract,
            contract_id,
            live_keys: config.live_keys,
            historical_rows: config.historical_rows,
        }))
    }

    fn count(&self, height: u64) -> usize {
        if height == ANCHOR_HEIGHT {
            return self.live_keys;
        }
        if !(FIRST_HEIGHT..ANCHOR_HEIGHT).contains(&height) {
            return 0;
        }
        self.historical_rows
            .saturating_sub((height - FIRST_HEIGHT) as usize * self.live_keys)
            .min(self.live_keys)
    }

    fn retained(&self, height: u64, cutoff: u64) -> usize {
        let count = self.count(height);
        if height > cutoff {
            return count;
        }
        // Every version writes a prefix of the same keys. The last partial
        // version can leave a suffix whose newest pre-cutoff row is older.
        let superseded = ((height + 1)..=cutoff)
            .map(|later| self.count(later))
            .max()
            .unwrap_or(0);
        count.saturating_sub(superseded)
    }

    pub(super) async fn seed_height(&self, runtime: &mut Runtime, height: u64) -> Result<()> {
        runtime.set_context(height, None, None, None).await;
        pagination::seed(runtime, &self.contract, self.count(height)).await
    }

    pub(super) async fn check(&self, conn: &Connection, pruned: bool) -> Result<()> {
        self.check_at(conn, pruned.then_some(prune_height())).await
    }

    pub(super) async fn check_at(&self, conn: &Connection, cutoff: Option<u64>) -> Result<()> {
        let mut counts = Vec::new();
        for height in FIRST_HEIGHT..=ANCHOR_HEIGHT {
            let mut rows = conn
                .query(
                    "SELECT count(*) FROM contract_state WHERE contract_id = ? AND height = ?",
                    params![self.contract_id, height],
                )
                .await?;
            let actual: u64 = rows
                .next()
                .await?
                .context("missing history count")?
                .get(0)?;
            let expected = cutoff.map_or_else(
                || self.count(height),
                |cutoff| self.retained(height, cutoff),
            );
            ensure!(
                actual == u64::try_from(expected)?,
                "history rows at {height}: expected {expected}, got {actual}, cutoff={cutoff:?}"
            );
            counts.push((height, actual));
        }
        let mut rows = conn
            .query(
                "SELECT count(*) FROM contract_state old
                 LEFT JOIN contract_state live ON live.contract_id = old.contract_id
                     AND live.path = old.path AND live.height = ?
                 LEFT JOIN current_contract_state current ON current.contract_id = old.contract_id
                     AND current.path = old.path
                 WHERE old.contract_id = ? AND old.height >= ?
                   AND (live.path IS NULL OR current.height IS NOT ?
                        OR old.value IS NOT live.value OR old.size IS NOT live.size
                        OR old.deleted != 0 OR live.deleted != 0
                        OR old.depositor IS NOT live.depositor
                        OR old.deposited_gas IS NOT live.deposited_gas)",
                params![ANCHOR_HEIGHT, self.contract_id, FIRST_HEIGHT, ANCHOR_HEIGHT],
            )
            .await?;
        let inconsistent: u64 = rows
            .next()
            .await?
            .context("missing history consistency result")?
            .get(0)?;
        ensure!(inconsistent == 0, "history values or live pointers differ");
        for height in cutoff.unwrap_or(FIRST_HEIGHT)..=ANCHOR_HEIGHT {
            let mut rows = conn
                .query(
                    "SELECT count(*) FROM contract_state s
                     WHERE s.contract_id = ?1 AND s.height >= ?2 AND s.height <= ?3
                       AND NOT EXISTS (SELECT 1 FROM contract_state n
                           WHERE n.contract_id = s.contract_id AND n.path = s.path
                             AND n.height > s.height AND n.height <= ?3)",
                    params![self.contract_id, FIRST_HEIGHT, height],
                )
                .await?;
            let visible: u64 = rows
                .next()
                .await?
                .context("missing visible count")?
                .get(0)?;
            let expected = (FIRST_HEIGHT..=height)
                .map(|h| self.count(h))
                .max()
                .unwrap_or(0);
            ensure!(
                visible == u64::try_from(expected)?,
                "history visibility differs at {height}"
            );
        }
        let mut depositors = conn
            .query(
                "SELECT depositor FROM depositor_footprint UNION SELECT DISTINCT depositor
             FROM contract_state WHERE depositor IS NOT NULL",
                (),
            )
            .await?;
        while let Some(row) = depositors.next().await? {
            let depositor: u64 = row.get(0)?;
            ensure!(
                footprint_cache_get(conn, depositor).await?.unwrap_or(0)
                    == live_deposit_gas_sum(conn, depositor).await?,
                "history workload deposit cache differs from live rows for {depositor}"
            );
        }
        eprintln!(
            "workload_history_rows={}",
            serde_json::json!({
                "contract": self.contract.to_string(),
                "historical_rows_before_pruning": self.historical_rows,
                "live_keys": self.live_keys,
                "cutoff": cutoff,
                "rows_by_height": counts,
                "setup": "Core guest calls, unchanged values, no signed historical transactions"
            })
        );
        Ok(())
    }
}

#[test]
fn workload_history_retains_partial_prefix_and_unfinalized_versions() {
    let population = |historical_rows| HistoryPopulation {
        contract: ContractAddress {
            name: "history".into(),
            height: 0,
            tx_index: 7,
        },
        contract_id: 1,
        live_keys: 10,
        historical_rows,
    };
    let partial = population(25);
    assert_eq!(partial.retained(89, prune_height()), 0);
    assert_eq!(partial.retained(90, prune_height()), 5);
    assert_eq!(partial.retained(91, prune_height()), 5);
    assert_eq!(partial.retained(ANCHOR_HEIGHT, prune_height()), 10);
    let across_cutoff = population(85);
    assert_eq!(across_cutoff.retained(95, prune_height()), 0);
    assert_eq!(across_cutoff.retained(96, prune_height()), 10);
    assert_eq!(across_cutoff.retained(97, prune_height()), 5);
    assert_eq!(across_cutoff.retained(ANCHOR_HEIGHT, prune_height()), 10);
    let full = population(120);
    assert_eq!(
        (89..101).map(|height| full.count(height)).sum::<usize>(),
        120
    );
    assert_eq!(
        (89..101)
            .map(|height| full.retained(height, prune_height()))
            .sum::<usize>(),
        50
    );
}
