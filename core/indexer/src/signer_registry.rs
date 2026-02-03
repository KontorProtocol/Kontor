use bitcoin::hashes::{Hash, sha256};
use bitcoin::secp256k1::{
    Message, Secp256k1, XOnlyPublicKey, schnorr::Signature as SchnorrSignature,
};
use libsql::Connection;

use crate::bls;
use crate::database::queries::{Error as DbError, assign_or_get_signer_id_by_xonly_and_bls};

const SCHNORR_BINDING_PREFIX: &[u8] = b"KONTOR_REG_XONLY_TO_BLS_V1";
const BLS_BINDING_PREFIX: &[u8] = b"KONTOR_REG_BLS_TO_XONLY_V1";

fn schnorr_binding_message(bls_pubkey: &[u8; 96]) -> Message {
    let mut preimage = Vec::with_capacity(SCHNORR_BINDING_PREFIX.len() + bls_pubkey.len());
    preimage.extend_from_slice(SCHNORR_BINDING_PREFIX);
    preimage.extend_from_slice(bls_pubkey);
    let digest = sha256::Hash::hash(&preimage).to_byte_array();
    Message::from_digest_slice(&digest).expect("sha256 digest is 32 bytes")
}

fn bls_binding_message(xonly_pubkey: &[u8; 32]) -> Vec<u8> {
    let mut msg = Vec::with_capacity(BLS_BINDING_PREFIX.len() + xonly_pubkey.len());
    msg.extend_from_slice(BLS_BINDING_PREFIX);
    msg.extend_from_slice(xonly_pubkey);
    msg
}

pub fn verify_registration_proofs(
    xonly_pubkey: &XOnlyPublicKey,
    bls_pubkey: &[u8; 96],
    schnorr_sig: &[u8; 64],
    bls_sig: &[u8; 48],
) -> Result<(), DbError> {
    let secp = Secp256k1::verification_only();
    let msg = schnorr_binding_message(bls_pubkey);
    let sig = SchnorrSignature::from_slice(schnorr_sig)
        .map_err(|e| DbError::InvalidData(format!("invalid schnorr signature: {e}")))?;
    secp.verify_schnorr(&sig, &msg, xonly_pubkey)
        .map_err(|e| DbError::InvalidData(format!("invalid schnorr binding signature: {e}")))?;

    let pk = bls::parse_public_key(bls_pubkey).map_err(|e| DbError::InvalidData(format!("{e}")))?;
    let sig = bls::parse_signature(bls_sig).map_err(|e| DbError::InvalidData(format!("{e}")))?;
    let msg = bls_binding_message(&xonly_pubkey.serialize());
    bls::verify_signature(&pk, &sig, &msg).map_err(|e| DbError::InvalidData(format!("{e}")))?;

    Ok(())
}

pub async fn register_signer(
    conn: &Connection,
    xonly_pubkey: &XOnlyPublicKey,
    bls_pubkey: &[u8; 96],
    schnorr_sig: &[u8; 64],
    bls_sig: &[u8; 48],
    height: i64,
    tx_index: i64,
) -> Result<u32, DbError> {
    verify_registration_proofs(xonly_pubkey, bls_pubkey, schnorr_sig, bls_sig)?;
    assign_or_get_signer_id_by_xonly_and_bls(
        conn,
        &xonly_pubkey.serialize(),
        bls_pubkey,
        height,
        tx_index,
    )
    .await
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::{Keypair, Secp256k1};
    use blst::min_sig::SecretKey as BlsSecretKey;
    use indexer_types::BlockRow;

    use crate::database::queries::{
        insert_block, reserve_signer_nonce, rollback_to_height, select_signer_nonce,
        select_signer_registry_by_id,
    };
    use crate::test_utils::new_test_db;

    #[tokio::test]
    async fn register_signer_inserts_and_reuses_id() -> Result<(), anyhow::Error> {
        let (_reader, writer, _temp) = new_test_db().await?;
        let conn = writer.connection();

        let height = 100;
        insert_block(
            &conn,
            BlockRow::builder()
                .height(height)
                .hash(crate::test_utils::new_mock_block_hash(height as u32))
                .build(),
        )
        .await?;

        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[42u8; 32])?;
        let (xonly, _) = keypair.public_key().x_only_public_key();

        let bls_sk = BlsSecretKey::key_gen(&[7u8; 32], &[]).expect("bls sk");
        let bls_pk_bytes = bls_sk.sk_to_pk().to_bytes();

        let schnorr_msg = schnorr_binding_message(&bls_pk_bytes);
        let schnorr_sig = secp.sign_schnorr(&schnorr_msg, &keypair).serialize();

        let bls_msg = bls_binding_message(&xonly.serialize());
        let bls_sig = bls_sk.sign(&bls_msg, bls::KONTOR_BLS_DST, &[]).to_bytes();

        let id1 = register_signer(
            &conn,
            &xonly,
            &bls_pk_bytes,
            &schnorr_sig,
            &bls_sig,
            height,
            0,
        )
        .await?;
        let id2 = register_signer(
            &conn,
            &xonly,
            &bls_pk_bytes,
            &schnorr_sig,
            &bls_sig,
            height,
            1,
        )
        .await?;

        assert_eq!(id1, id2);

        let row = select_signer_registry_by_id(&conn, id1)
            .await?
            .expect("row");
        let xonly_bytes = xonly.serialize();
        assert_eq!(row.xonly_pubkey, xonly_bytes);
        assert_eq!(row.bls_pubkey, Some(bls_pk_bytes));
        assert_eq!(row.first_seen_height, height);

        Ok(())
    }

    #[tokio::test]
    async fn signer_registry_id_reuses_after_rollback() -> Result<(), anyhow::Error> {
        let (_reader, writer, _temp) = new_test_db().await?;
        let conn = writer.connection();

        let secp = Secp256k1::new();
        let keypair1 = Keypair::from_seckey_slice(&secp, &[1u8; 32])?;
        let (xonly1, _) = keypair1.public_key().x_only_public_key();
        let bls_sk1 = BlsSecretKey::key_gen(&[11u8; 32], &[]).expect("bls sk1");
        let bls_pk1 = bls_sk1.sk_to_pk().to_bytes();
        let schnorr_sig1 = secp
            .sign_schnorr(&schnorr_binding_message(&bls_pk1), &keypair1)
            .serialize();
        let bls_sig1 = bls_sk1
            .sign(
                &bls_binding_message(&xonly1.serialize()),
                bls::KONTOR_BLS_DST,
                &[],
            )
            .to_bytes();

        let keypair2 = Keypair::from_seckey_slice(&secp, &[2u8; 32])?;
        let (xonly2, _) = keypair2.public_key().x_only_public_key();
        let bls_sk2 = BlsSecretKey::key_gen(&[22u8; 32], &[]).expect("bls sk2");
        let bls_pk2 = bls_sk2.sk_to_pk().to_bytes();
        let schnorr_sig2 = secp
            .sign_schnorr(&schnorr_binding_message(&bls_pk2), &keypair2)
            .serialize();
        let bls_sig2 = bls_sk2
            .sign(
                &bls_binding_message(&xonly2.serialize()),
                bls::KONTOR_BLS_DST,
                &[],
            )
            .to_bytes();

        insert_block(
            &conn,
            BlockRow::builder()
                .height(100)
                .hash(crate::test_utils::new_mock_block_hash(100))
                .build(),
        )
        .await?;
        insert_block(
            &conn,
            BlockRow::builder()
                .height(101)
                .hash(crate::test_utils::new_mock_block_hash(101))
                .build(),
        )
        .await?;

        let id1 =
            register_signer(&conn, &xonly1, &bls_pk1, &schnorr_sig1, &bls_sig1, 100, 0).await?;
        let id2 =
            register_signer(&conn, &xonly2, &bls_pk2, &schnorr_sig2, &bls_sig2, 101, 0).await?;

        rollback_to_height(&conn, 100).await?;

        // Re-create the next block after rollback and register a different signer; we should reuse
        // the rolled-back ID (no AUTOINCREMENT semantics).
        insert_block(
            &conn,
            BlockRow::builder()
                .height(101)
                .hash(crate::test_utils::new_mock_block_hash(201))
                .build(),
        )
        .await?;

        let keypair3 = Keypair::from_seckey_slice(&secp, &[3u8; 32])?;
        let (xonly3, _) = keypair3.public_key().x_only_public_key();
        let bls_sk3 = BlsSecretKey::key_gen(&[33u8; 32], &[]).expect("bls sk3");
        let bls_pk3 = bls_sk3.sk_to_pk().to_bytes();
        let schnorr_sig3 = secp
            .sign_schnorr(&schnorr_binding_message(&bls_pk3), &keypair3)
            .serialize();
        let bls_sig3 = bls_sk3
            .sign(
                &bls_binding_message(&xonly3.serialize()),
                bls::KONTOR_BLS_DST,
                &[],
            )
            .to_bytes();

        let id3 =
            register_signer(&conn, &xonly3, &bls_pk3, &schnorr_sig3, &bls_sig3, 101, 1).await?;

        assert_ne!(id1, id2);
        assert_eq!(id2, id3);
        Ok(())
    }

    #[tokio::test]
    async fn signer_nonce_is_removed_on_block_rollback() -> Result<(), anyhow::Error> {
        let (_reader, writer, _temp) = new_test_db().await?;
        let conn = writer.connection();

        insert_block(
            &conn,
            BlockRow::builder()
                .height(100)
                .hash(crate::test_utils::new_mock_block_hash(100))
                .build(),
        )
        .await?;
        insert_block(
            &conn,
            BlockRow::builder()
                .height(101)
                .hash(crate::test_utils::new_mock_block_hash(101))
                .build(),
        )
        .await?;

        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[42u8; 32])?;
        let (xonly, _) = keypair.public_key().x_only_public_key();
        let bls_sk = BlsSecretKey::key_gen(&[7u8; 32], &[]).expect("bls sk");
        let bls_pk = bls_sk.sk_to_pk().to_bytes();

        let schnorr_sig = secp
            .sign_schnorr(&schnorr_binding_message(&bls_pk), &keypair)
            .serialize();
        let bls_sig = bls_sk
            .sign(
                &bls_binding_message(&xonly.serialize()),
                bls::KONTOR_BLS_DST,
                &[],
            )
            .to_bytes();

        let signer_id =
            register_signer(&conn, &xonly, &bls_pk, &schnorr_sig, &bls_sig, 100, 0).await?;

        reserve_signer_nonce(&conn, signer_id, 123, 101, 0, 0, 0).await?;
        assert!(select_signer_nonce(&conn, signer_id, 123).await?.is_some());

        rollback_to_height(&conn, 100).await?;

        // Nonces written in rolled-back blocks must be removed.
        assert!(select_signer_nonce(&conn, signer_id, 123).await?.is_none());
        Ok(())
    }

    #[tokio::test]
    async fn signer_nonce_replay_is_rejected() -> Result<(), anyhow::Error> {
        let (_reader, writer, _temp) = new_test_db().await?;
        let conn = writer.connection();

        insert_block(
            &conn,
            BlockRow::builder()
                .height(100)
                .hash(crate::test_utils::new_mock_block_hash(100))
                .build(),
        )
        .await?;

        let secp = Secp256k1::new();
        let keypair = Keypair::from_seckey_slice(&secp, &[42u8; 32])?;
        let (xonly, _) = keypair.public_key().x_only_public_key();
        let bls_sk = BlsSecretKey::key_gen(&[7u8; 32], &[]).expect("bls sk");
        let bls_pk = bls_sk.sk_to_pk().to_bytes();

        let schnorr_sig = secp
            .sign_schnorr(&schnorr_binding_message(&bls_pk), &keypair)
            .serialize();
        let bls_sig = bls_sk
            .sign(
                &bls_binding_message(&xonly.serialize()),
                bls::KONTOR_BLS_DST,
                &[],
            )
            .to_bytes();

        let signer_id =
            register_signer(&conn, &xonly, &bls_pk, &schnorr_sig, &bls_sig, 100, 0).await?;

        reserve_signer_nonce(&conn, signer_id, 999, 100, 0, 0, 0).await?;
        assert!(
            reserve_signer_nonce(&conn, signer_id, 999, 100, 0, 0, 1)
                .await
                .is_err()
        );
        Ok(())
    }
}
