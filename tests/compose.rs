use anyhow::Result;
use bitcoin::secp256k1::Keypair;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{
    Amount, OutPoint, Txid, consensus::encode::serialize as serialize_tx, key::Secp256k1,
    transaction::TxOut,
};
use bitcoin::{FeeRate, Witness};
use clap::Parser;
use kontor::api::compose::{RevealInputs, compose, compose_reveal};

use kontor::api::compose::ComposeInputs;
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

    // Create token balance data
    let token_value = 1000;
    let token_balance = TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let compose_params = ComposeInputs::builder()
        .sender_address(&seller_address)
        .internal_key(&internal_key)
        .sender_utxos(vec![(out_point, utxo_for_output.clone())])
        .script_data(b"Hello, world!")
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .chained_script_data(serialized_token_balance.as_slice())
        .build();

    let compose_outputs = compose(compose_params)?;

    let mut commit_tx = compose_outputs.commit_transaction;
    let tap_script = compose_outputs.tap_script;
    let mut reveal_tx = compose_outputs.reveal_transaction;
    let chained_tap_script = compose_outputs.chained_tap_script.unwrap();

    let chained_reveal_taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, chained_tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, internal_key)
        .expect("Failed to finalize Taproot tree");

    let chained_reveal_tx = compose_reveal(
        RevealInputs::builder()
            .internal_key(&internal_key)
            .sender_address(&seller_address)
            .commit_output((
                OutPoint {
                    txid: reveal_tx.compute_txid(),
                    vout: 0,
                },
                reveal_tx.output[0].clone(),
            ))
            .funding_outputs(vec![(
                OutPoint {
                    txid: reveal_tx.compute_txid(),
                    vout: 1,
                },
                reveal_tx.output[1].clone(),
            )])
            .tap_script(&chained_tap_script)
            .taproot_spend_info(&chained_reveal_taproot_spend_info)
            .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
            // .op_return_recipient(&internal_key)
            .build(),
    )?;

    // 1. SIGN THE ORIGINAL COMMIT
    test_utils::sign_key_spend(&secp, &mut commit_tx, &[utxo_for_output], &keypair, 0)?;

    let spend_tx_prevouts = vec![commit_tx.output[0].clone()];

    // 2. SIGN THE REVEAL

    // sign the script_spend input for the reveal transaction
    let reveal_taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, internal_key)
        .expect("Failed to finalize Taproot tree");

    test_utils::sign_script_spend(
        &secp,
        &reveal_taproot_spend_info,
        &tap_script,
        &mut reveal_tx,
        &spend_tx_prevouts,
        &keypair,
        0,
    )?;

    let mut chained_reveal_tx = chained_reveal_tx.reveal_transaction;

    // 3. SIGN THE CHAINED REVEAL
    let reveal_tx_prevouts = vec![reveal_tx.output[0].clone()];

    // sign the script_spend input for the chained reveal transaction
    let chained_taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, chained_tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, internal_key)
        .expect("Failed to finalize Taproot tree");

    test_utils::sign_script_spend(
        &secp,
        &chained_taproot_spend_info,
        &chained_tap_script,
        &mut chained_reveal_tx,
        &reveal_tx_prevouts,
        &keypair,
        0,
    )?;

    let commit_tx_hex = hex::encode(serialize_tx(&commit_tx));
    let reveal_tx_hex = hex::encode(serialize_tx(&reveal_tx));
    let chained_reveal_tx_hex = hex::encode(serialize_tx(&chained_reveal_tx));

    let result = client
        .test_mempool_accept(&[commit_tx_hex, reveal_tx_hex, chained_reveal_tx_hex])
        .await?;

    assert_eq!(result.len(), 3, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Commit transaction was rejected");
    assert!(result[1].allowed, "Reveal transaction was rejected");
    assert!(result[2].allowed, "Chained reveal transaction was rejected");

    Ok(())
}
