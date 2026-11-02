use bitcoin::{Txid, secp256k1::XOnlyPublicKey};
use indexer_types::HolderRef;
use stdlib::{KeyElement, KeyPath};

use crate::protocol::v1::migration::{MigrationContext, MigrationFailure};
use crate::protocol::v1::native::TOKEN_CONTRACT_ID;
use crate::runtime::Decimal;

type Result<T> = std::result::Result<T, MigrationFailure>;

pub(crate) async fn backfill(context: &mut MigrationContext) -> Result<()> {
    let ledger = KeyPath::new().push_interned(0);
    let count_key = KeyPath::new().push_interned(5);
    if context
        .input_point(TOKEN_CONTRACT_ID, &count_key)
        .await?
        .is_some()
    {
        return Err(MigrationFailure::InvalidOperation(
            "token count already exists in migration input",
        ));
    }
    let mut after = None;
    let mut count = 0u64;
    while let Some(entry) = context
        .input_next(TOKEN_CONTRACT_ID, after.as_deref())
        .await?
    {
        let key = context.input_key(&entry).await?;
        context.step(key.len() as u64)?;
        if let Some(holder) = key.strip_prefix(ledger.as_bytes()) {
            validate_holder(holder)?;
            let value = context.input_value(&entry).await?;
            context.step(value.len() as u64)?;
            if positive_balance(&value)? {
                count = count
                    .checked_add(1)
                    .ok_or(MigrationFailure::InvalidOperation("token count overflow"))?;
            }
        }
        after = Some(key);
    }
    let value = postcard::to_allocvec(&count)
        .map_err(|_| MigrationFailure::InvalidOperation("token count encoding failed"))?;
    context
        .set(TOKEN_CONTRACT_ID, &count_key, &value, (None, None))
        .await
}

fn validate_holder(bytes: &[u8]) -> Result<()> {
    let invalid = || MigrationFailure::InvalidOperation("invalid token ledger holder key");
    let (key, tail) = String::decode_from(bytes).map_err(|_| invalid())?;
    if !tail.is_empty() || key.encode() != bytes {
        return Err(invalid());
    }
    let holder = key.parse::<HolderRef>().map_err(|_| invalid())?;
    match &holder {
        HolderRef::XOnlyPubkey(key) => {
            key.parse::<XOnlyPublicKey>().map_err(|_| invalid())?;
        }
        HolderRef::Utxo(outpoint) => {
            // P1 validates txids but preserves their original hex spelling.
            outpoint.txid.parse::<Txid>().map_err(|_| invalid())?;
        }
        _ => {}
    }
    if holder.to_string() != key {
        return Err(invalid());
    }
    Ok(())
}

fn positive_balance(bytes: &[u8]) -> Result<bool> {
    let invalid = || MigrationFailure::InvalidOperation("invalid token ledger balance");
    let (encoded, tail) = postcard::take_from_bytes::<Vec<u8>>(bytes).map_err(|_| invalid())?;
    if !tail.is_empty() || postcard::to_allocvec(&encoded).map_err(|_| invalid())? != bytes {
        return Err(invalid());
    }
    let (balance, tail) = Decimal::decode_from(&encoded).map_err(|_| invalid())?;
    if !tail.is_empty() || balance.encode() != encoded {
        return Err(invalid());
    }
    Ok(balance > Decimal::default())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_complete_holder_keys_without_losing_p1_txid_spelling() {
        for key in ["core", "burn", "ordering_pool", "storage_pool", "0", "42"] {
            assert!(validate_holder(&key.to_string().encode()).is_ok(), "{key}");
        }
        for key in [
            format!("{}:7", "AB".repeat(32)),
            format!("{}:4294967295", "00".repeat(32)),
        ] {
            assert!(validate_holder(&key.encode()).is_ok(), "{key}");
        }
        for key in ["", "unknown", "01", "bad:7", "1:4294967296"] {
            assert!(validate_holder(&key.to_string().encode()).is_err(), "{key}");
        }
        let mut extra = "42".to_string().encode();
        extra.extend(1u64.encode());
        assert!(validate_holder(&extra).is_err());
        assert!(validate_holder(&[]).is_err());
    }

    #[test]
    fn decodes_both_balance_layers_and_rejects_trailing_data() {
        for (value, positive) in [
            ("0", false),
            ("-1", false),
            ("0.00000001", true),
            ("100", true),
        ] {
            let encoded = Decimal::from(value).encode();
            let stored = postcard::to_allocvec(&encoded).unwrap();
            assert_eq!(positive_balance(&stored).unwrap(), positive);
            let mut trailing = stored;
            trailing.push(0);
            assert!(positive_balance(&trailing).is_err());
            let mut trailing = encoded;
            trailing.push(0);
            assert!(positive_balance(&postcard::to_allocvec(&trailing).unwrap()).is_err());
        }
        assert!(positive_balance(&[]).is_err());
        assert!(positive_balance(&postcard::to_allocvec(&vec![0xffu8]).unwrap()).is_err());
    }
}
