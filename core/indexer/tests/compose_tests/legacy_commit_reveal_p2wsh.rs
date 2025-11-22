use anyhow::Result;
use bitcoin::CompressedPublicKey;
use bitcoin::EcdsaSighashType;
use bitcoin::Network;
use bitcoin::hashes::Hash;
use bitcoin::secp256k1::Keypair;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::SighashCache;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Witness,
    absolute::LockTime,
    address::Address,
    consensus::encode::serialize as serialize_tx,
    key::Secp256k1,
    transaction::{Transaction, TxIn, TxOut, Version},
};
use indexer::legacy_test_utils;
use indexer::witness_data::TokenBalance;
use indexer_types::serialize;
use testlib::RegTester;

pub async fn test_legacy_commit_reveal_p2wsh(reg_tester: &mut RegTester) -> Result<()> {
    let seller_identity = reg_tester.identity().await?;
    let seller_address = seller_identity.address;
    let seller_keypair = seller_identity.keypair;
    let (seller_out_point, seller_utxo_for_output) = seller_identity.next_funding_utxo;

    let secp = Secp256k1::new();

    let recipient_identity = reg_tester.identity().await?;
    let recipient_address = recipient_identity.address;

    let keypair = Keypair::from_secret_key(&secp, &seller_keypair.secret_key());

    let token_balance = TokenBalance {
        value: 1000,
        name: "token_name".to_string(),
    };

    let serialized_token_balance = serialize(&token_balance)?;

    let seller_compressed = CompressedPublicKey::from_private_key(
        &secp,
        &bitcoin::PrivateKey::new(seller_keypair.secret_key(), Network::Regtest),
    )
    .expect("compressed pubkey");
    let witness_script = legacy_test_utils::build_witness_script(
        legacy_test_utils::PublicKey::Segwit(&seller_compressed),
        &serialized_token_balance,
    );

    let script_address: Address = Address::p2wsh(&witness_script, Network::Bitcoin);

    let attach_tx = legacy_test_utils::build_signed_taproot_attach_tx(
        &secp,
        &keypair,
        &seller_address,
        &script_address,
        seller_out_point,
        seller_utxo_for_output,
    )?;

    // Spend the p2sh output
    let mut spend_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: attach_tx.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::default(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![TxOut {
            value: Amount::from_sat(700), // 1000 - 300 fee
            script_pubkey: recipient_address.script_pubkey(),
        }],
    };
    let sighash_type = EcdsaSighashType::All;

    let mut sighasher = SighashCache::new(&spend_tx);
    let sighash = sighasher
        .p2wsh_signature_hash(0, &witness_script, Amount::from_sat(1000), sighash_type)
        .expect("failed to construct sighash");
    let msg = Message::from_digest(sighash.to_byte_array());
    let sig = secp.sign_ecdsa(&msg, &seller_keypair.secret_key());
    let sig = bitcoin::ecdsa::Signature {
        signature: sig,
        sighash_type,
    };
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"kon");
    witness.push(witness_script.as_bytes());
    spend_tx.input[0].witness = witness;

    let spend_tx_hex = hex::encode(serialize_tx(&spend_tx));
    let attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let result = reg_tester
        .mempool_accept_result(&[attach_tx_hex, spend_tx_hex])
        .await?;

    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(result[1].allowed, "Spend transaction was rejected");
    Ok(())
}
