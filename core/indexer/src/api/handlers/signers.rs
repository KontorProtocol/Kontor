use std::collections::BTreeMap;

use axum::extract::{Path, State};
use indexer_types::{ContractFootprint, FootprintResponse, SignerResponse};
use libsql::Connection;
use numerics::{Decimal, add_decimal, decimal_to_string, string_to_decimal, u64_to_decimal};

use crate::api::{Env, error::Error, error::HttpError, result::Result};
use crate::database::queries::{
    FootprintRow, find_footprint_by_depositor, get_signer_entry_by_bls_pubkey,
    get_signer_entry_by_id, get_signer_entry_by_x_only_pubkey,
};
use crate::database::types::SignerEntry;

/// Identifier accepted by the signer routes. Disambiguated by shape — numeric is
/// a signer_id, 64-char hex is an x-only pubkey, 192-char hex is a BLS pubkey.
fn is_hex_of_len(s: &str, len: usize) -> bool {
    s.len() == len && s.chars().all(|c| c.is_ascii_hexdigit())
}

/// Resolve any of the accepted identifier forms to the signer's full entry, or a
/// `BadRequest`/`NotFound` — shared by every signer sub-resource.
async fn resolve_signer_entry(
    conn: &Connection,
    identifier: &str,
) -> std::result::Result<SignerEntry, Error> {
    let entry = if let Ok(signer_id) = identifier.parse::<u64>() {
        get_signer_entry_by_id(conn, signer_id).await
    } else if is_hex_of_len(identifier, 64) {
        get_signer_entry_by_x_only_pubkey(conn, identifier).await
    } else if is_hex_of_len(identifier, 192) {
        let bytes = hex::decode(identifier)
            .map_err(|e| HttpError::BadRequest(format!("invalid bls_pubkey hex: {e}")))?;
        get_signer_entry_by_bls_pubkey(conn, &bytes).await
    } else {
        return Err(HttpError::BadRequest(
            "identifier must be signer_id (numeric), x-only pubkey (64 hex), or bls pubkey (192 hex)"
                .to_string(),
        )
        .into());
    };
    entry
        .map_err(|e| HttpError::BadRequest(e.to_string()))?
        .ok_or_else(|| HttpError::NotFound(format!("signer not found for: {identifier}")).into())
}

pub async fn get_signer(
    Path(identifier): Path<String>,
    State(env): State<Env>,
) -> Result<SignerResponse> {
    let runtime = env.runtime_pool.get().await?;
    let conn = runtime.get_storage_conn();
    let e = resolve_signer_entry(&conn, &identifier).await?;
    Ok(SignerResponse {
        signer_id: e.signer_id,
        x_only_pubkey: e.x_only_pubkey,
        bls_pubkey: e.bls_pubkey,
        next_nonce: e.next_nonce,
    }
    .into())
}

/// `GET /api/signers/{identifier}/footprint` — the signer's storage-deposit
/// footprint, broken down by contract. Heavier than the plain signer lookup (a
/// liveness aggregation over `contract_state`), so it's its own sub-resource
/// rather than a field on the default response.
pub async fn get_signer_footprint(
    Path(identifier): Path<String>,
    State(env): State<Env>,
) -> Result<FootprintResponse> {
    let runtime = env.runtime_pool.get().await?;
    let conn = runtime.get_storage_conn();
    let entry = resolve_signer_entry(&conn, &identifier).await?;

    let rows = find_footprint_by_depositor(&conn, entry.signer_id)
        .await
        .map_err(|e| HttpError::BadRequest(e.to_string()))?;
    let (total_vaulted, total_footprint_bytes, by_contract) =
        aggregate_footprint(rows).map_err(|e| HttpError::BadRequest(format!("{e:?}")))?;

    Ok(FootprintResponse {
        signer_id: entry.signer_id,
        x_only_pubkey: entry.x_only_pubkey,
        total_vaulted,
        total_footprint_bytes,
        by_contract,
    }
    .into())
}

/// Fold per-row deposits into a per-contract breakdown + totals. Decimal strings
/// are summed via `numerics` (no SQL decimal SUM); `BTreeMap` gives a stable
/// contract-id order. `percent` is a display-only f64 share of `total_vaulted`.
fn aggregate_footprint(
    rows: Vec<FootprintRow>,
) -> std::result::Result<(String, u64, Vec<ContractFootprint>), numerics::Error> {
    let mut groups: BTreeMap<u64, (String, Decimal, u64)> = BTreeMap::new();
    let mut total_vaulted = u64_to_decimal(0)?;
    let mut total_footprint_bytes: u64 = 0;
    for row in rows {
        let amt = string_to_decimal(&row.deposited_amount)?;
        total_vaulted = add_decimal(total_vaulted, amt)?;
        total_footprint_bytes += row.footprint_bytes;
        match groups.get_mut(&row.contract_id) {
            Some((_, v, f)) => {
                *v = add_decimal(*v, amt)?;
                *f += row.footprint_bytes;
            }
            None => {
                groups.insert(row.contract_id, (row.contract_name, amt, row.footprint_bytes));
            }
        }
    }
    let total_str = decimal_to_string(total_vaulted);
    let total_f: f64 = total_str.parse().unwrap_or(0.0);
    let by_contract = groups
        .into_iter()
        .map(|(contract_id, (contract_name, v, footprint_bytes))| {
            let vaulted = decimal_to_string(v);
            // Display-only share; exact figures are the decimal strings.
            let percent = if total_f > 0.0 {
                vaulted.parse::<f64>().unwrap_or(0.0) / total_f * 100.0
            } else {
                0.0
            };
            ContractFootprint {
                contract_id,
                contract_name,
                vaulted,
                footprint_bytes,
                percent,
            }
        })
        .collect();
    Ok((total_str, total_footprint_bytes, by_contract))
}

#[cfg(test)]
mod footprint_tests {
    use super::{FootprintRow, aggregate_footprint};

    fn row(contract_id: u64, name: &str, amt: &str, bytes: u64) -> FootprintRow {
        FootprintRow {
            contract_id,
            contract_name: name.to_string(),
            deposited_amount: amt.to_string(),
            footprint_bytes: bytes,
        }
    }

    #[test]
    fn folds_rows_into_per_contract_totals() {
        let rows = vec![
            row(1, "token", "10", 100),
            row(2, "nft", "30", 300),
            row(1, "token", "5", 50), // same contract → folds into contract 1
        ];
        let (total, total_bytes, by) = aggregate_footprint(rows).unwrap();

        assert_eq!(total.parse::<f64>().unwrap(), 45.0);
        assert_eq!(total_bytes, 450);
        assert_eq!(by.len(), 2);

        let c1 = by.iter().find(|c| c.contract_id == 1).unwrap();
        assert_eq!(c1.vaulted.parse::<f64>().unwrap(), 15.0);
        assert_eq!(c1.footprint_bytes, 150);
        let c2 = by.iter().find(|c| c.contract_id == 2).unwrap();
        assert_eq!(c2.vaulted.parse::<f64>().unwrap(), 30.0);
        assert_eq!(c2.footprint_bytes, 300);

        // Σ by_contract == total, and percents sum to ~100.
        let sum: f64 = by.iter().map(|c| c.vaulted.parse::<f64>().unwrap()).sum();
        assert_eq!(sum, 45.0);
        let pct: f64 = by.iter().map(|c| c.percent).sum();
        assert!((pct - 100.0).abs() < 1e-9, "percents must sum to 100, got {pct}");
    }

    #[test]
    fn empty_footprint_is_zero() {
        let (total, bytes, by) = aggregate_footprint(vec![]).unwrap();
        assert_eq!(total.parse::<f64>().unwrap(), 0.0);
        assert_eq!(bytes, 0);
        assert!(by.is_empty());
    }
}
