use libsql::{Connection, de::from_row, params};

use super::Error;
use super::versioned::latest_one;
use crate::database::types::{CORE_SIGNER_ID, Identity, SignerEntry};

impl Identity {
    /// Returns the most recent x_only_pubkey for this signer. `Identity` wraps
    /// a user signer by construction, so every `Identity` has an associated
    /// pubkey.
    pub async fn x_only_pubkey(&self, conn: &Connection) -> Result<String, Error> {
        let mut rows = conn
            .query(
                &latest_one("x_only_pubkeys", "signer_id", "x_only_pubkey"),
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
                &latest_one("bls_keys", "signer_id", "bls_pubkey"),
                params![self.signer_id()],
            )
            .await?;
        Ok(rows.next().await?.map(|row| row.get(0)).transpose()?)
    }

    pub async fn next_nonce(&self, conn: &Connection) -> Result<u64, Error> {
        let mut rows = conn
            .query(
                &latest_one("nonces", "signer_id", "next_nonce"),
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
        caller_nonce: u64,
        height: u64,
    ) -> Result<u64, Error> {
        let mut rows = conn
            .query(
                &latest_one("nonces", "signer_id", "next_nonce"),
                params![self.signer_id()],
            )
            .await?;

        let stored_nonce: u64 = rows
            .next()
            .await?
            .ok_or_else(|| {
                Error::InvalidData(format!("no nonce for signer_id {}", self.signer_id()))
            })?
            .get(0)?;

        const MAX_NONCE_GAP: u64 = 10_000;

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
        height: u64,
    ) -> Result<(), Error> {
        conn.execute(
            "INSERT OR REPLACE INTO bls_keys (signer_id, bls_pubkey, height) VALUES (?, ?, ?)",
            params![self.signer_id(), bls_pubkey.to_vec(), height],
        )
        .await?;
        Ok(())
    }
}

/// Look up the signer identity for `x_only_pubkey`. Read-only — no
/// writes, no side effects. Returns `None` if no row exists yet
/// (typical when a view-context query references a pubkey nobody has
/// transacted as).
///
/// Use this from any path that must not mutate, especially anything
/// dispatched under a `ViewContext` frame. Use [`ensure_identity`]
/// when the caller is allowed to create the row on miss (proc-context
/// execution, reactor / aggregate-verify paths).
pub async fn get_identity(
    conn: &Connection,
    x_only_pubkey: &str,
) -> Result<Option<Identity>, Error> {
    let mut rows = conn
        .query(
            "SELECT signer_id FROM x_only_pubkeys WHERE x_only_pubkey = ?",
            params![x_only_pubkey],
        )
        .await?;
    match rows.next().await? {
        Some(row) => Ok(Some(Identity::new(row.get::<i64>(0)? as u64))),
        None => Ok(None),
    }
}

/// Look up the signer identity for `x_only_pubkey`, creating the
/// signers / x_only_pubkeys / nonces rows on miss. Mutating — call
/// only from contexts where state growth is permitted (proc-context
/// contract calls, reactor processing).
pub async fn ensure_identity(
    conn: &Connection,
    x_only_pubkey: &str,
    height: u64,
) -> Result<Identity, Error> {
    if let Some(existing) = get_identity(conn, x_only_pubkey).await? {
        return Ok(existing);
    }

    conn.execute("INSERT INTO signers (height) VALUES (?)", params![height])
        .await?;
    let signer_id = conn.last_insert_rowid() as u64;

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

/// Create the reserved Core signer row. The Core signer row has id =
/// `CORE_SIGNER_ID` by construction — it's the first row inserted into
/// `signers` at genesis, before any other signer. Idempotent — returns the
/// existing id on repeat calls. Asserts the produced id matches the constant
/// so downstream code can rely on `CORE_SIGNER_ID` as compile-time-known.
pub async fn create_core_signer(conn: &Connection) -> Result<u64, Error> {
    let existing = conn
        .query("SELECT id FROM signers ORDER BY id ASC LIMIT 1", ())
        .await?
        .next()
        .await?
        .map(|r| r.get::<i64>(0).map(|v| v as u64))
        .transpose()?;
    if let Some(id) = existing {
        if id != CORE_SIGNER_ID {
            return Err(Error::InvalidData(format!(
                "existing Core signer id ({id}) does not match CORE_SIGNER_ID ({CORE_SIGNER_ID})"
            )));
        }
        return Ok(id);
    }
    conn.execute("INSERT INTO signers (height) VALUES (0)", ())
        .await?;
    let id = conn.last_insert_rowid() as u64;
    if id != CORE_SIGNER_ID {
        return Err(Error::InvalidData(format!(
            "newly-created Core signer id ({id}) does not match CORE_SIGNER_ID ({CORE_SIGNER_ID})"
        )));
    }
    Ok(id)
}

/// Create a signer row for a contract. No x_only_pubkey — contracts don't
/// have bitcoin keys. The signer_id is assigned by auto-increment.
pub async fn create_contract_signer(conn: &Connection, height: u64) -> Result<u64, Error> {
    conn.execute("INSERT INTO signers (height) VALUES (?)", params![height])
        .await?;
    Ok(conn.last_insert_rowid() as u64)
}

/// Look up the signer_id associated with a contract.
pub async fn get_contract_signer_id(
    conn: &Connection,
    contract_id: u64,
) -> Result<Option<u64>, Error> {
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
    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
}

pub async fn get_signer_entry_by_id(
    conn: &Connection,
    signer_id: u64,
) -> Result<Option<SignerEntry>, Error> {
    let sql = format!("{SIGNER_ENTRY_SELECT} WHERE s.id = ?");
    let mut rows = conn.query(&sql, params![signer_id]).await?;
    Ok(rows.next().await?.map(|r| from_row(&r)).transpose()?)
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
            &latest_one("bls_keys", "bls_pubkey", "signer_id"),
            params![bls_pubkey.to_vec()],
        )
        .await?;
    let signer_id: u64 = match rows.next().await? {
        Some(row) => row.get::<i64>(0)? as u64,
        None => return Ok(None),
    };
    get_signer_entry_by_id(conn, signer_id).await
}
