//! Shared SQL fragments for latest-by-height signer and key reads.

/// Point-read of the latest-by-height row for a single key:
/// `SELECT {select} FROM {table} WHERE {key} = ? ORDER BY height DESC LIMIT 1`.
pub fn latest_one(table: &str, key: &str, select: &str) -> String {
    format!("SELECT {select} FROM {table} WHERE {key} = ? ORDER BY height DESC LIMIT 1")
}

/// The latest height for a key, as a scalar subquery for use inside a JOIN's
/// `ON` clause (or any correlation): `(SELECT MAX(height) FROM {table} WHERE
/// {key} = {correlate})`. Unlike [`latest_one`], this yields a
/// scalar — the only form usable where `ORDER BY ... LIMIT 1` can't go.
/// `correlate` is an SQL expression (e.g. an outer column `s.id`), not a bind.
pub fn max_height_of(table: &str, key: &str, correlate: &str) -> String {
    format!("(SELECT MAX(height) FROM {table} WHERE {key} = {correlate})")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn latest_one_builds_point_read() {
        assert_eq!(
            latest_one("nonces", "signer_id", "next_nonce"),
            "SELECT next_nonce FROM nonces WHERE signer_id = ? ORDER BY height DESC LIMIT 1"
        );
    }

    #[test]
    fn max_height_of_builds_correlated_scalar() {
        assert_eq!(
            max_height_of("bls_keys", "signer_id", "s.id"),
            "(SELECT MAX(height) FROM bls_keys WHERE signer_id = s.id)"
        );
    }
}
