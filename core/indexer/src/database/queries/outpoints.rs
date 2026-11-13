use std::collections::{HashMap, HashSet};

use bitcoin::hashes::Hash;
use bitcoin::{OutPoint, Transaction, Txid, Wtxid};
use libsql::{Connection, params};

use super::Error;

const TXID_CHUNK: usize = 900;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct OutpointOwner {
    pub(crate) tx_id: u64,
    pub(crate) txid: Txid,
    pub(crate) wtxid: Wtxid,
    pub(crate) batch_height: Option<u64>,
    pub(crate) anchor_height: u64,
}

pub(crate) async fn outpoint_owners(
    conn: &Connection,
    transactions: &[Transaction],
) -> Result<HashMap<OutPoint, OutpointOwner>, Error> {
    let requested: HashSet<OutPoint> = transactions
        .iter()
        .flat_map(|tx| tx.input.iter().map(|input| input.previous_output))
        .collect();
    let txids: HashSet<Txid> = requested.iter().map(|outpoint| outpoint.txid).collect();
    let txids: Vec<Txid> = txids.into_iter().collect();
    let mut consumed = HashMap::new();
    for chunk in txids.chunks(TXID_CHUNK) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let query = format!(
            "SELECT e.prev_txid, e.prev_vout, e.tx_id, e.wtxid, t.txid, t.batch_height, t.height \
             FROM executed_outpoints e JOIN transactions t ON t.id = e.tx_id \
             WHERE e.prev_txid IN ({placeholders})"
        );
        let values = chunk
            .iter()
            .map(|txid| libsql::Value::Blob(txid.to_byte_array().to_vec()))
            .collect();
        let mut rows = conn
            .query(&query, libsql::params::Params::Positional(values))
            .await?;
        while let Some(row) = rows.next().await? {
            let bytes: Vec<u8> = row.get(0)?;
            let txid =
                Txid::from_slice(&bytes).map_err(|error| Error::InvalidData(error.to_string()))?;
            let outpoint = OutPoint {
                txid,
                vout: row.get(1)?,
            };
            if requested.contains(&outpoint) {
                let wtxid: Vec<u8> = row.get(3)?;
                consumed.insert(
                    outpoint,
                    OutpointOwner {
                        tx_id: row.get(2)?,
                        txid: row
                            .get::<String>(4)?
                            .parse::<Txid>()
                            .map_err(|error| Error::InvalidData(error.to_string()))?,
                        wtxid: Wtxid::from_slice(&wtxid)
                            .map_err(|error| Error::InvalidData(error.to_string()))?,
                        batch_height: row.get(5)?,
                        anchor_height: row.get(6)?,
                    },
                );
            }
        }
    }
    Ok(consumed)
}

pub async fn consumed_outpoints(
    conn: &Connection,
    transactions: &[Transaction],
) -> Result<HashSet<OutPoint>, Error> {
    Ok(outpoint_owners(conn, transactions)
        .await?
        .into_keys()
        .collect())
}

pub async fn reserve_transaction_outpoints(
    conn: &Connection,
    outpoints: &[OutPoint],
    wtxid: Wtxid,
    tx_id: u64,
) -> Result<(), Error> {
    for &outpoint in outpoints {
        conn.execute(
            "INSERT INTO executed_outpoints (prev_txid, prev_vout, tx_id, wtxid) VALUES (?1, ?2, ?3, ?4)",
            params![
                outpoint.txid.to_byte_array().to_vec(),
                outpoint.vout,
                tx_id,
                wtxid.to_byte_array().to_vec()
            ],
        )
        .await?;
    }
    Ok(())
}

pub async fn executed_wtxid(conn: &Connection, tx_id: u64) -> Result<Option<Wtxid>, Error> {
    let mut rows = conn
        .query(
            "SELECT DISTINCT wtxid FROM executed_outpoints WHERE tx_id = ?1",
            [tx_id],
        )
        .await?;
    let Some(row) = rows.next().await? else {
        return Ok(None);
    };
    let bytes: Vec<u8> = row.get(0)?;
    let wtxid = Wtxid::from_slice(&bytes).map_err(|error| Error::InvalidData(error.to_string()))?;
    if rows.next().await?.is_some() {
        return Err(Error::InvalidData(
            "executed transaction has conflicting witness identities".to_string(),
        ));
    }
    Ok(Some(wtxid))
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, ScriptBuf, TxIn, TxOut, Witness};
    use indexer_types::{BlockRow, TransactionRow};

    use super::*;
    use crate::database::queries::{insert_block, insert_transaction};
    use crate::test_utils::{new_mock_block_hash, new_test_db};

    #[tokio::test]
    async fn executed_outpoint_reservation_rolls_back_with_its_transaction() -> anyhow::Result<()> {
        let (_reader, writer, _dir) = new_test_db().await?;
        let conn = writer.connection();
        insert_block(
            &conn,
            BlockRow::builder()
                .height(1)
                .hash(new_mock_block_hash(1))
                .build(),
        )
        .await?;
        let outpoint = OutPoint {
            txid: Txid::from_byte_array([7; 32]),
            vout: 2,
        };
        let mut raw = Transaction {
            version: Version::TWO,
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: outpoint,
                ..TxIn::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: ScriptBuf::new(),
            }],
        };
        let tx_id = insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(1)
                .txid(raw.compute_txid().to_string())
                .build(),
        )
        .await?;
        reserve_transaction_outpoints(&conn, &[outpoint], raw.compute_wtxid(), tx_id).await?;
        assert_eq!(
            executed_wtxid(&conn, tx_id).await?,
            Some(raw.compute_wtxid())
        );
        assert_eq!(
            consumed_outpoints(&conn, &[raw.clone()]).await?,
            [outpoint].into()
        );
        raw.input[0].witness = Witness::from_slice(&[vec![1]]);
        assert_eq!(
            consumed_outpoints(&conn, &[raw.clone()]).await?,
            [outpoint].into()
        );
        assert!(
            reserve_transaction_outpoints(&conn, &[outpoint], raw.compute_wtxid(), tx_id)
                .await
                .is_err()
        );
        conn.execute("DELETE FROM blocks WHERE height = 1", ())
            .await?;
        assert!(consumed_outpoints(&conn, &[raw]).await?.is_empty());
        assert_eq!(executed_wtxid(&conn, tx_id).await?, None);
        Ok(())
    }
}
