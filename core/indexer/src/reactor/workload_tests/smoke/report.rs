use anyhow::{Context, Result, ensure};
use bitcoin::BlockHash;
use indexer_types::ContractAddress;
use libsql::params;
use serde_json::{Map, Value, json};

use super::diagnostic::money;
use super::{database_projection, receipts, state};
use crate::database::queries::{
    PRUNE_WATERMARK_KEY, get_checkpoint_by_height, get_meta_u64, select_block_at_height,
};
use crate::runtime::Runtime;
use crate::runtime::token::api as token;
use crate::runtime::wit::kontor::built_in::context::HolderRef;

pub(super) struct Reporter {
    pub payer: String,
    pub addresses: [ContractAddress; 2],
    pub prune_contract: u64,
    pub prune_path: Vec<u8>,
}

impl Reporter {
    pub(super) async fn capture(
        &self,
        runtime: &mut Runtime,
        height: u64,
        hash: BlockHash,
        raw_positions: &[(String, u32)],
    ) -> Result<Value> {
        let conn = runtime.get_storage_conn();
        let projection = database_projection(&conn).await?;
        ensure!(
            select_block_at_height(&conn, height)
                .await?
                .context("report block missing")?
                .hash
                == hash
        );
        let mut accounts = Map::new();
        for (name, holder) in [
            ("payer", HolderRef::XOnlyPubkey(self.payer.clone())),
            ("burner", HolderRef::Burner),
            ("core", HolderRef::Core),
            ("ordering_pool", HolderRef::OrderingPool),
            ("storage_pool", HolderRef::StoragePool),
        ] {
            let balance = token::balance(runtime, holder.clone())
                .await?
                .unwrap_or_default();
            let floor = token::floor(runtime, holder).await?;
            accounts.insert(
                name.into(),
                json!({"balance":money(balance)?,"floor":money(floor)?}),
            );
        }
        accounts.insert(
            "total_supply".into(),
            json!({
                "balance":money(token::total_supply(runtime).await?)?,"floor":"0"
            }),
        );
        let views = json!({
            "A":{"address":self.addresses[0].to_string(),"storage_state":state(runtime,&self.addresses[0]).await?},
            "B":{"address":self.addresses[1].to_string(),"storage_state":state(runtime,&self.addresses[1]).await?},
        });
        let mut usage = Vec::new();
        let mut rows = conn.query(
            "SELECT t.txid, u.user_fuel, u.system_fuel, u.deposit_fuel FROM transactions t
             JOIN transaction_execution_usage u ON u.tx_id = t.id WHERE t.height = ? ORDER BY t.tx_index",
            [height],
        ).await?;
        while let Some(row) = rows.next().await? {
            let txid: String = row.get(0)?;
            let positions: Vec<_> = raw_positions.iter().filter(|(id, _)| id == &txid).collect();
            ensure!(
                positions.len() == 1,
                "usage lacks a unique raw transaction position"
            );
            usage.push(
                json!({"height":height,"tx_index":positions[0].1,"txid":txid,
                "user_fuel":row.get::<u64>(1)?,"system_fuel":row.get::<u64>(2)?,
                "deposit_fuel":row.get::<u64>(3)?,"kind":"transaction"}),
            );
        }
        ensure!(
            usage.len() == raw_positions.len(),
            "missing persisted transaction usage"
        );
        let mut rows = conn
            .query(
                "SELECT system_fuel FROM block_execution_usage WHERE height = ?",
                [height],
            )
            .await?;
        let row = rows.next().await?.context("missing lifecycle usage")?;
        usage.push(json!({"height":height,"tx_index":null,"txid":null,
            "user_fuel":0,"system_fuel":row.get::<u64>(0)?,"deposit_fuel":0,"kind":"block"}));
        ensure!(rows.next().await?.is_none());
        let a = runtime
            .storage
            .contract_id(&self.addresses[0])
            .await?
            .context("missing A")?;
        let b = runtime
            .storage
            .contract_id(&self.addresses[1])
            .await?
            .context("missing B")?;
        let mut rows = conn.query(
            "SELECT c.name, c.height, c.tx_index, s.path, s.height, s.value, s.deleted, s.depositor, s.deposited_gas
             FROM contract_state s JOIN contracts c ON c.id = s.contract_id
             WHERE s.contract_id IN (?, ?) OR (s.contract_id = ? AND s.path = ?)
             ORDER BY c.name || '_' || c.height || '_' || c.tx_index, hex(s.path), s.height",
            params![a, b, self.prune_contract, self.prune_path.clone()],
        ).await?;
        let mut versions = Vec::new();
        while let Some(row) = rows.next().await? {
            let contract = ContractAddress {
                name: row.get(0)?,
                height: row.get(1)?,
                tx_index: row.get(2)?,
            };
            versions.push(json!({"contract":contract.to_string(),"path_hex":hex::encode(row.get::<Vec<u8>>(3)?),
                "height":row.get::<u64>(4)?,"value_hex":hex::encode(row.get::<Vec<u8>>(5)?),
                "deleted":row.get::<i64>(6)? != 0,"depositor":row.get::<Option<u64>>(7)?,
                "deposited_gas":row.get::<Option<u64>>(8)?}));
        }
        let counts: Vec<_> = projection.as_array().context("database projection")?.iter()
            .map(|table| json!({"table":table["table"],"rows":table["rows"].as_array().expect("projection rows").len()}))
            .collect();
        let report = json!({"schema_version":1,"height":height,"block_hash":hash,
            "checkpoint":get_checkpoint_by_height(&conn,height).await?.context("missing report checkpoint")?.hash,
            "prune_watermark":get_meta_u64(&conn,PRUNE_WATERMARK_KEY,0).await?,
            "receipts":receipts(&conn,height).await?,"usage":usage,"accounts":accounts,
            "contract_views":views,"state_versions":versions,"table_counts":counts});
        ensure!(
            database_projection(&conn).await? == projection,
            "typed report observation mutated database"
        );
        Ok(report)
    }
}
