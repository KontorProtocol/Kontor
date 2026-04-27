use turso::{Connection, params};

use super::Error;
use crate::database::de::first_row;
use crate::database::types::{Identity, SignerEntry};

impl Identity {
    /// Returns the most recent x_only_pubkey for this signer. `Identity` wraps
    /// a user signer by construction, so every `Identity` has an associated
    /// pubkey.
    pub async fn x_only_pubkey(&self, conn: &Connection) -> Result<String, Error> {
        let mut rows = conn
            .query(
                "SELECT x_only_pubkey FROM x_only_pubkeys \
                 WHERE signer_id = ? ORDER BY height DESC LIMIT 1",
                params![self.signer_id()],
            )
            .await?;
        let row = rows.next().await?.ok_or_else(|| {
            Error::InvalidData(format!(
                "no x_only_pubkey for signer_id {}",
                self.signer_id()
            ))
        })?;
        Ok(row.get(0)?)
    }

    pub async fn bls_pubkey(&self, conn: &Connection) -> Result<Option<Vec<u8>>, Error> {
        let mut rows = conn
            .query(
                "SELECT bls_pubkey FROM bls_keys WHERE signer_id = ? ORDER BY height DESC LIMIT 1",
                params![self.signer_id()],
            )
            .await?;
        Ok(rows.next().await?.map(|row| row.get(0)).transpose()?)
    }

    pub async fn next_nonce(&self, conn: &Connection) -> Result<i64, Error> {
        let mut rows = conn
            .query(
                "SELECT next_nonce FROM nonces WHERE signer_id = ? ORDER BY height DESC LIMIT 1",
                params![self.signer_id()],
            )
            .await?;
        Ok(rows
            .next()
            .await?
            .map(|row| row.get(0))
            .transpose()?
            .unwrap_or(0))
    }

    pub async fn advance_nonce(
        &self,
        conn: &Connection,
        caller_nonce: i64,
        height: i64,
    ) -> Result<i64, Error> {
        let mut rows = conn
            .query(
                "SELECT next_nonce FROM nonces WHERE signer_id = ? ORDER BY height DESC LIMIT 1",
                params![self.signer_id()],
            )
            .await?;

        let stored_nonce: i64 = rows
            .next()
            .await?
            .ok_or_else(|| {
                Error::InvalidData(format!("no nonce for signer_id {}", self.signer_id()))
            })?
            .get(0)?;

        const MAX_NONCE_GAP: i64 = 10_000;

        if caller_nonce < stored_nonce {
            return Err(Error::InvalidData(format!(
                "nonce too low for signer_id {}: got {caller_nonce}, expected >= {stored_nonce}",
                self.signer_id()
            )));
        }
        if caller_nonce - stored_nonce > MAX_NONCE_GAP {
            return Err(Error::InvalidData(format!(
                "nonce too far ahead for signer_id {}: got {caller_nonce}, expected <= {}",
                self.signer_id(),
                stored_nonce + MAX_NONCE_GAP
            )));
        }

        let next_nonce = caller_nonce
            .checked_add(1)
            .ok_or_else(|| Error::InvalidData("nonce overflow".to_string()))?;
        conn.execute(
            "INSERT OR REPLACE INTO nonces (signer_id, next_nonce, height) VALUES (?, ?, ?)",
            params![self.signer_id(), next_nonce, height],
        )
        .await?;

        Ok(next_nonce)
    }

    pub async fn register_bls_key(
        &self,
        conn: &Connection,
        bls_pubkey: &[u8],
        height: i64,
    ) -> Result<(), Error> {
        conn.execute(
            "INSERT OR REPLACE INTO bls_keys (signer_id, bls_pubkey, height) VALUES (?, ?, ?)",
            params![self.signer_id(), bls_pubkey.to_vec(), height],
        )
        .await?;
        Ok(())
    }
}

pub async fn get_or_create_identity(
    conn: &Connection,
    x_only_pubkey: &str,
    height: i64,
) -> Result<Identity, Error> {
    let mut rows = conn
        .query(
            "SELECT signer_id FROM x_only_pubkeys WHERE x_only_pubkey = ?",
            params![x_only_pubkey],
        )
        .await?;

    if let Some(row) = rows.next().await? {
        return Ok(Identity::new(row.get(0)?));
    }

    conn.execute("INSERT INTO signers (height) VALUES (?)", params![height])
        .await?;
    let signer_id = conn.last_insert_rowid();

    conn.execute(
        "INSERT INTO x_only_pubkeys (signer_id, x_only_pubkey, height) VALUES (?, ?, ?)",
        params![signer_id, x_only_pubkey, height],
    )
    .await?;

    conn.execute(
        "INSERT INTO nonces (signer_id, next_nonce, height) VALUES (?, 0, ?)",
        params![signer_id, height],
    )
    .await?;

    Ok(Identity::new(signer_id))
}

/// Create the reserved Core signer row. The Core signer row has id = 1 by
/// construction — it's the first row inserted into `signers` at genesis, before
/// any other signer. Idempotent — returns the existing id on repeat calls.
pub async fn create_core_signer(conn: &Connection) -> Result<i64, Error> {
    let existing = conn
        .query("SELECT id FROM signers ORDER BY id ASC LIMIT 1", ())
        .await?
        .next()
        .await?
        .map(|r| r.get::<i64>(0))
        .transpose()?;
    if let Some(id) = existing {
        return Ok(id);
    }
    conn.execute("INSERT INTO signers (height) VALUES (0)", ())
        .await?;
    Ok(conn.last_insert_rowid())
}

/// Create a signer row for a contract. No x_only_pubkey — contracts don't
/// have bitcoin keys. The signer_id is assigned by auto-increment.
pub async fn create_contract_signer(conn: &Connection, height: i64) -> Result<i64, Error> {
    conn.execute("INSERT INTO signers (height) VALUES (?)", params![height])
        .await?;
    Ok(conn.last_insert_rowid())
}

/// Look up the signer_id associated with a contract.
pub async fn get_contract_signer_id(
    conn: &Connection,
    contract_id: i64,
) -> Result<Option<i64>, Error> {
    let mut rows = conn
        .query(
            "SELECT signer_id FROM contracts WHERE id = ?",
            params![contract_id],
        )
        .await?;
    Ok(rows.next().await?.map(|r| r.get(0)).transpose()?)
}

/// Shared SELECT + JOIN body for signer entry lookups. Uses LEFT JOINs so
/// core and contract signers (which lack x_only_pubkeys/nonces rows) are
/// returned with NULL fields rather than filtered out.
const SIGNER_ENTRY_SELECT: &str = r#"SELECT
        s.id AS signer_id,
        p.x_only_pubkey,
        b.bls_pubkey,
        n.next_nonce
    FROM signers s
    LEFT JOIN x_only_pubkeys p ON p.signer_id = s.id
        AND p.height = (SELECT MAX(height) FROM x_only_pubkeys WHERE signer_id = s.id)
    LEFT JOIN bls_keys b ON b.signer_id = s.id
        AND b.height = (SELECT MAX(height) FROM bls_keys WHERE signer_id = s.id)
    LEFT JOIN nonces n ON n.signer_id = s.id
        AND n.height = (SELECT MAX(height) FROM nonces WHERE signer_id = s.id)"#;

pub async fn get_signer_entry_by_x_only_pubkey(
    conn: &Connection,
    x_only_pubkey: &str,
) -> Result<Option<SignerEntry>, Error> {
    let sql = format!("{SIGNER_ENTRY_SELECT} WHERE p.x_only_pubkey = ?");
    let mut rows = conn.query(&sql, params![x_only_pubkey]).await?;
    first_row(&mut rows).await
}

pub async fn get_signer_entry_by_id(
    conn: &Connection,
    signer_id: i64,
) -> Result<Option<SignerEntry>, Error> {
    let sql = format!("{SIGNER_ENTRY_SELECT} WHERE s.id = ?");
    let mut rows = conn.query(&sql, params![signer_id]).await?;
    first_row(&mut rows).await
}

/// Look up a signer by BLS pubkey. Policy allows only one signer per BLS
/// pubkey (enforced at registration in the runtime), but the schema permits
/// historical rows if rotation is ever added — so pick the most recent.
pub async fn get_signer_entry_by_bls_pubkey(
    conn: &Connection,
    bls_pubkey: &[u8],
) -> Result<Option<SignerEntry>, Error> {
    let mut rows = conn
        .query(
            "SELECT signer_id FROM bls_keys WHERE bls_pubkey = ? ORDER BY height DESC LIMIT 1",
            params![bls_pubkey.to_vec()],
        )
        .await?;
    let signer_id: i64 = match rows.next().await? {
        Some(row) => row.get(0)?,
        None => return Ok(None),
    };
    get_signer_entry_by_id(conn, signer_id).await
}
