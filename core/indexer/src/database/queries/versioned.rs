//! Builders for height-versioned reads — the shared shape behind every
//! height-keyed table (`signers`/`nonces`/`bls_keys`, `contract_state`, and the
//! forthcoming challenge ledger): a logical row is the latest by `height` for
//! its key. Keeps the `ORDER BY height DESC` / `ROW_NUMBER` boilerplate in one
//! place instead of re-hand-rolling it per table.

/// Point-read of the latest-by-height row for a single key:
/// `SELECT {select} FROM {table} WHERE {key} = ? ORDER BY height DESC LIMIT 1`.
pub fn latest_one(table: &str, key: &str, select: &str) -> String {
    format!("SELECT {select} FROM {table} WHERE {key} = ? ORDER BY height DESC LIMIT 1")
}

/// The latest height for a key, as a scalar subquery for use inside a JOIN's
/// `ON` clause (or any correlation): `(SELECT MAX(height) FROM {table} WHERE
/// {key} = {correlate})`. Unlike [`latest_one`]/[`LatestMany`], this yields a
/// scalar — the only form usable where `ORDER BY ... LIMIT 1` can't go.
/// `correlate` is an SQL expression (e.g. an outer column `s.id`), not a bind.
pub fn max_height_of(table: &str, key: &str, correlate: &str) -> String {
    format!("(SELECT MAX(height) FROM {table} WHERE {key} = {correlate})")
}

/// Latest-version-per-key collapse. The `filter` is applied INSIDE the window
/// subquery so only relevant rows are ranked (matters on large tables like
/// `contract_state`, where ranking the whole table would be a regression).
/// Clauses use named binds (`:foo`), so callers bind by name and `?` ordering
/// never bites.
#[derive(bon::Builder)]
pub struct LatestMany<'a> {
    /// Table to read.
    table: &'a str,
    /// Outer `SELECT` list.
    select: &'a str,
    /// Predicate applied inside the subquery, before ranking.
    filter: &'a str,
    /// `PARTITION BY` expression; omit for a single "latest by height" row.
    partition_by: Option<&'a str>,
    /// Extra predicate on the collapsed (`rank = 1`) row, e.g. `deleted = false`.
    post: Option<&'a str>,
    /// Outer `ORDER BY` for a deterministic result order. SQLite leaves row
    /// order unspecified without it, so any caller that consumes rows
    /// positionally and needs the order reproducible across nodes (e.g. a
    /// contract's `keys()` feeding consensus-relevant selection) must set this.
    order_by: Option<&'a str>,
}

impl LatestMany<'_> {
    pub fn to_sql(&self) -> String {
        let partition = self
            .partition_by
            .map(|p| format!("PARTITION BY {p} "))
            .unwrap_or_default();
        let post = self.post.map(|p| format!(" AND {p}")).unwrap_or_default();
        let order_by = self
            .order_by
            .map(|o| format!(" ORDER BY {o}"))
            .unwrap_or_default();
        format!(
            // `rowid` breaks same-height ties deterministically (later insert
            // wins — e.g. the write following an in-tx `delete_matching`), so the
            // ranked row is reproducible across nodes.
            "SELECT {select} FROM (\n  \
               SELECT *, ROW_NUMBER() OVER ({partition}ORDER BY height DESC, rowid DESC) AS rank\n  \
               FROM {table}\n  \
               WHERE {filter}\n\
             ) t WHERE rank = 1{post}{order_by}",
            select = self.select,
            table = self.table,
            filter = self.filter,
        )
    }
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

    #[test]
    fn latest_many_without_partition() {
        let sql = LatestMany::builder()
            .table("contract_state")
            .select("*")
            .filter("contract_id = :contract_id AND path = :path")
            .post("deleted = false")
            .build()
            .to_sql();
        assert!(sql.contains("ROW_NUMBER() OVER (ORDER BY height DESC, rowid DESC) AS rank"));
        assert!(sql.contains("WHERE contract_id = :contract_id AND path = :path"));
        assert!(
            sql.trim_end()
                .ends_with("WHERE rank = 1 AND deleted = false")
        );
    }

    #[test]
    fn latest_many_with_partition_and_no_post() {
        let sql = LatestMany::builder()
            .table("challenge_status")
            .select("challenge_id, status")
            .filter("status = :status")
            .partition_by("challenge_id")
            .build()
            .to_sql();
        assert!(sql.contains(
            "ROW_NUMBER() OVER (PARTITION BY challenge_id ORDER BY height DESC, rowid DESC) AS rank"
        ));
        assert!(sql.trim_end().ends_with("WHERE rank = 1"));
    }

    #[test]
    fn latest_many_with_order_by() {
        let sql = LatestMany::builder()
            .table("contract_state")
            .select("path")
            .filter("contract_id = :contract_id")
            .partition_by("path")
            .order_by("path")
            .build()
            .to_sql();
        assert!(sql.trim_end().ends_with("WHERE rank = 1 ORDER BY path"));
    }
}
