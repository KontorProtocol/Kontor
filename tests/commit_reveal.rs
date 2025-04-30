use anyhow::Result;
use bitcoin::TapLeafHash;
use bitcoin::TapSighashType;
use bitcoin::hashes::Hash;
use bitcoin::key::{TapTweak, TweakedKeypair};
use bitcoin::secp256k1::Keypair;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Txid, Witness,
    absolute::LockTime,
    address::{Address, KnownHrp},
    consensus::encode::serialize as serialize_tx,
    key::Secp256k1,
    transaction::{Transaction, TxIn, TxOut, Version},
};
use clap::Parser;
use kontor::config::TestConfig;
use kontor::test_utils;
use kontor::witness_data::TokenBalance;
use kontor::{bitcoin_client::Client, config::Config};
use std::str::FromStr;

#[tokio::test]
async fn test_taproot_transaction() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;

    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 0)?;

    let (recipient_address, _recipient_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 1)?;

    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    // UTXO loaded with 9000 sats
    let out_point = OutPoint {
        txid: Txid::from_str("dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8")?,
        vout: 0,
    };

    let utxo_for_output = TxOut {
        value: Amount::from_sat(9000),
        script_pubkey: seller_address.script_pubkey(),
    };

    // The input for the transaction we are constructing.
    let input = TxIn {
        previous_output: out_point,       // The output we are spending
        script_sig: ScriptBuf::default(), // For a p2tr script_sig is empty
        sequence: Sequence::MAX,
        witness: Witness::default(), // Filled in after signing
    };

    // Create token balance data
    let token_value = 1000;
    let token_balance = TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    // Create the tapscript with x-only public key
    let tap_script = test_utils::build_inscription(
        serialized_token_balance.clone(),
        test_utils::PublicKey::Taproot(&internal_key),
    )?;

    // Build the Taproot tree with the script
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone()) // Add script at depth 0
        .expect("Failed to add leaf")
        .finalize(&secp, internal_key)
        .expect("Failed to finalize Taproot tree");

    // Get the output key which commits to both the internal key and the script tree
    let output_key = taproot_spend_info.output_key();

    // Create the address from the output key
    let script_spendable_address = Address::p2tr_tweaked(output_key, KnownHrp::Mainnet);

    let unspendable_out = TxOut {
        value: Amount::from_sat(1000),
        script_pubkey: script_spendable_address.script_pubkey(),
    };

    let change_out = TxOut {
        value: Amount::from_sat(7700), // 9000 - 1000 - 300 fee
        script_pubkey: seller_address.script_pubkey(),
    };

    // Create the transaction
    let mut attach_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![unspendable_out.clone(), change_out],
    };
    let input_index = 0;

    // Sign the transaction
    let sighash_type = TapSighashType::Default;
    let prevouts = vec![utxo_for_output];
    let prevouts = Prevouts::All(&prevouts);

    let mut sighasher = SighashCache::new(&attach_tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
        .expect("failed to construct sighash");

    // Sign the sighash
    let tweaked: TweakedKeypair = keypair.tap_tweak(&secp, None);
    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, &tweaked.to_inner());

    // Update the witness stack
    let signature = bitcoin::taproot::Signature {
        signature,
        sighash_type,
    };
    attach_tx.input[input_index]
        .witness
        .push(signature.to_vec());

    // Attempt to spend the unspendable output
    let input = TxIn {
        previous_output: OutPoint {
            txid: attach_tx.compute_txid(),
            vout: 0,
        },
        script_sig: ScriptBuf::default(),
        sequence: Sequence::MAX,
        witness: Witness::default(),
    };

    // Create the spending transaction
    let mut spend_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![input],
        output: vec![TxOut {
            value: Amount::from_sat(700), // 1000 - 300 fee
            script_pubkey: recipient_address.script_pubkey(),
        }],
    };

    // Get the control block for the script
    let control_block = taproot_spend_info
        .control_block(&(tap_script.clone(), LeafVersion::TapScript))
        .expect("Failed to create control block");
    // taproot_spend_info.

    // Create the witness for script path spending
    let mut sighasher = SighashCache::new(&spend_tx);
    let sighash = sighasher
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[unspendable_out.clone()]),
            TapLeafHash::from_script(&tap_script, LeafVersion::TapScript),
            TapSighashType::Default,
        )
        .expect("Failed to create sighash");

    // Sign the transaction with the seller's keypair
    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, &keypair);
    let signature = bitcoin::taproot::Signature {
        signature,
        sighash_type: TapSighashType::Default,
    };

    // Build the witness stack for script path spending
    spend_tx.input[0].witness.push(signature.to_vec());
    spend_tx.input[0].witness.push(tap_script.as_bytes());
    spend_tx.input[0].witness.push(control_block.serialize());

    let attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let spend_tx_hex = hex::encode(serialize_tx(&spend_tx));

    let result = client
        .test_mempool_accept(&[attach_tx_hex, spend_tx_hex])
        .await?;
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(result[1].allowed, "Spend transaction was rejected");

    let witness = spend_tx.input[0].witness.clone();
    // 1. Check the total number of witness elements first
    assert_eq!(witness.len(), 3, "Witness should have exactly 5 elements");

    // 2. Check each element individually
    let signature = witness.to_vec()[0].clone();
    assert!(!signature.is_empty(), "Signature should not be empty");

    let script_bytes = witness.to_vec()[1].clone();
    assert_eq!(
        script_bytes,
        tap_script.as_bytes().to_vec(),
        "Script in witness doesn't match expected script"
    );

    let control_block_bytes = witness.to_vec()[2].clone();
    assert_eq!(
        control_block_bytes,
        control_block.serialize(),
        "Control block in witness doesn't match expected control block"
    );

    Ok(())
}
