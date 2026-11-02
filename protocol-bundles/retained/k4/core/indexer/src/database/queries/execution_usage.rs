use anyhow::{Result, ensure};
use libsql::{Connection, params};

use crate::runtime::fuel::ExecutionUsage;

pub async fn insert_transaction_execution_usage(
    conn: &Connection,
    tx_id: u64,
    usage: ExecutionUsage,
) -> Result<()> {
    conn.execute(
        "INSERT INTO transaction_execution_usage (tx_id, user_fuel, system_fuel, deposit_fuel) VALUES (?, ?, ?, ?)",
        params![i64::try_from(tx_id)?, i64::try_from(usage.user_fuel)?, i64::try_from(usage.system_fuel)?, i64::try_from(usage.deposit_fuel)?],
    ).await?;
    Ok(())
}

pub async fn insert_block_execution_usage(
    conn: &Connection,
    height: u64,
    usage: ExecutionUsage,
) -> Result<()> {
    ensure!(
        usage.user_fuel == 0 && usage.deposit_fuel == 0,
        "block maintenance recorded user fuel"
    );
    conn.execute(
        "INSERT INTO block_execution_usage (height, system_fuel) VALUES (?, ?)",
        params![i64::try_from(height)?, i64::try_from(usage.system_fuel)?],
    )
    .await?;
    Ok(())
}

pub async fn get_transaction_execution_usage(
    conn: &Connection,
    tx_id: u64,
) -> Result<Option<ExecutionUsage>> {
    let mut rows = conn.query(
        "SELECT user_fuel, system_fuel, deposit_fuel FROM transaction_execution_usage WHERE tx_id = ?",
        params![i64::try_from(tx_id)?],
    ).await?;
    rows.next()
        .await?
        .map(|row| {
            Ok(ExecutionUsage {
                user_fuel: row.get(0)?,
                system_fuel: row.get(1)?,
                deposit_fuel: row.get(2)?,
            })
        })
        .transpose()
}
