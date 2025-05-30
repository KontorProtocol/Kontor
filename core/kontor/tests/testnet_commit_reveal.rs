use anyhow::Result;
use bitcoin::FeeRate;
use bitcoin::Network;
use bitcoin::secp256k1::Keypair;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{
    Amount, OutPoint, Txid, consensus::encode::serialize as serialize_tx, key::Secp256k1,
    transaction::TxOut,
};
use clap::Parser;
use kontor::api::compose::compose;

use kontor::api::compose::ComposeInputs;
use kontor::config::TestConfig;
use kontor::test_utils;
use kontor::witness_data::TokenBalance;
use kontor::{bitcoin_client::Client, config::Config};
use std::str::FromStr;

#[tokio::test]
#[ignore]
async fn test_taproot_transaction() -> Result<()> {
    // Initialize regtest client
    let mut config = Config::try_parse()?;
    config.bitcoin_rpc_url = "http://127.0.0.1:48332".to_string();

    let client = Client::new_from_config(&config)?;
    let mut test_config = TestConfig::try_parse()?;
    test_config.network = Network::Testnet4;

    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &test_config, 0)?;

    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    // UTXO loaded with 9000 sats
    let out_point = OutPoint {
        txid: Txid::from_str("738c9c29646f2efe149fc3abb23976f4e3c3009656bdb4349a8e04570ed2ba9a")?,
        vout: 1,
    };

    let utxo_for_output = TxOut {
        value: Amount::from_sat(500000),
        script_pubkey: seller_address.script_pubkey(),
    };

    // Create token balance data
    let token_value = 1000;
    let token_balance = TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let compose_params = ComposeInputs::builder()
        .address(seller_address.clone())
        .x_only_public_key(internal_key)
        .funding_utxos(vec![(out_point, utxo_for_output.clone())])
        .script_data(serialized_token_balance)
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .envelope(546)
        .build();

    let compose_outputs = compose(compose_params)?;

    let mut attach_tx = compose_outputs.commit_transaction;
    let mut spend_tx = compose_outputs.reveal_transaction;
    let tap_script = compose_outputs.tap_script;

    // Sign the attach transaction
    test_utils::sign_key_spend(&secp, &mut attach_tx, &[utxo_for_output], &keypair, 0)?;

    let spend_tx_prevouts = vec![attach_tx.output[0].clone()];

    // sign the script_spend input for the spend transaction
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, internal_key)
        .expect("Failed to finalize Taproot tree");

    test_utils::sign_script_spend(
        &secp,
        &taproot_spend_info,
        &tap_script,
        &mut spend_tx,
        &spend_tx_prevouts,
        &keypair,
        0,
    )?;

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
    assert_eq!(witness.len(), 3, "Witness should have exactly 3 elements");

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
        taproot_spend_info
            .control_block(&(tap_script.clone(), LeafVersion::TapScript))
            .expect("Failed to create control block")
            .serialize(),
        "Control block in witness doesn't match expected control block"
    );

    Ok(())
}
