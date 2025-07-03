use anyhow::Result;
use bitcoin::FeeRate;
use bitcoin::secp256k1::Keypair;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{
    Amount, OutPoint, Txid, consensus::encode::serialize as serialize_tx, key::Secp256k1,
    transaction::TxOut,
};
use clap::Parser;
use indexer::api::compose::{RevealInputs, compose, compose_reveal};

use indexer::api::compose::ComposeInputs;
use indexer::config::TestConfig;
use indexer::test_utils;
use indexer::witness_data::TokenBalance;
use indexer::{bitcoin_client::Client, config::Config};
use std::str::FromStr;

#[tokio::test]
async fn test_taproot_transaction() -> Result<()> {
    let client = Client::new_from_config(&Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;

    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config, 0)?;

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
        .address(seller_address.clone())
        .x_only_public_key(internal_key)
        .funding_utxos(vec![(out_point, utxo_for_output.clone())])
        .script_data(b"Hello, world!".to_vec())
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .envelope(546)
        .chained_script_data(serialized_token_balance.clone())
        .build();

    let compose_outputs = compose(compose_params)?;

    let mut commit_tx = compose_outputs.commit_transaction;
    let tap_script = compose_outputs.tap_script;
    let mut reveal_tx = compose_outputs.reveal_transaction;
    let chained_tap_script = compose_outputs.chained_tap_script.unwrap();

    let chained_reveal_tx = compose_reveal(
        RevealInputs::builder()
            .x_only_public_key(internal_key)
            .address(seller_address.clone())
            .commit_output((
                OutPoint {
                    txid: reveal_tx.compute_txid(),
                    vout: 0,
                },
                reveal_tx.output[0].clone(),
            ))
            .funding_utxos(vec![(
                OutPoint {
                    txid: reveal_tx.compute_txid(),
                    vout: 1,
                },
                reveal_tx.output[1].clone(),
            )])
            .envelope(546)
            .commit_script_data(serialized_token_balance)
            .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
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

    let mut chained_reveal_tx = chained_reveal_tx.transaction;

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

#[tokio::test]
async fn test_compose_progressive_size_limit() -> Result<()> {
    let client = Client::new_from_config(&Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;

    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config, 0)?;

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

    // Start with a reasonable size and progressively increase
    let mut current_size = 10_000; // Start with 10KB
    let increment = 50_000; // Increase by 50KB each iteration
    let max_attempts = 40; // Test up to ~2MB

    let mut last_successful_size = 0;
    let mut attempts = 0;

    println!("Testing progressive compose data size limits...");

    while attempts < max_attempts {
        // Create test data of current size
        let script_data = vec![0xFF; current_size];

        let compose_params = ComposeInputs::builder()
            .address(seller_address.clone())
            .x_only_public_key(internal_key)
            .funding_utxos(vec![(out_point, utxo_for_output.clone())])
            .script_data(script_data)
            .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
            .envelope(546)
            .build();

        match compose(compose_params) {
            Ok(compose_outputs) => {
                let mut commit_tx = compose_outputs.commit_transaction;
                let tap_script = compose_outputs.tap_script;
                let mut reveal_tx = compose_outputs.reveal_transaction;

                // Sign the transactions to get realistic sizes
                test_utils::sign_key_spend(
                    &secp,
                    &mut commit_tx,
                    &[utxo_for_output.clone()],
                    &keypair,
                    0,
                )?;

                let spend_tx_prevouts = vec![commit_tx.output[0].clone()];

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

                let commit_tx_size = serialize_tx(&commit_tx).len();
                let reveal_tx_size = serialize_tx(&reveal_tx).len();
                let total_size = commit_tx_size + reveal_tx_size;

                println!(
                    "✓ Success: {} bytes data ({} KB) -> commit: {} bytes, reveal: {} bytes, total: {} bytes ({} KB)",
                    current_size,
                    current_size / 1024,
                    commit_tx_size,
                    reveal_tx_size,
                    total_size,
                    total_size / 1024
                );

                // Test mempool acceptance
                let commit_tx_hex = hex::encode(serialize_tx(&commit_tx));
                let reveal_tx_hex = hex::encode(serialize_tx(&reveal_tx));

                match client
                    .test_mempool_accept(&[commit_tx_hex, reveal_tx_hex])
                    .await
                {
                    Ok(results) => {
                        if results.iter().all(|r| r.allowed) {
                            last_successful_size = current_size;
                            println!("  ✓ Mempool acceptance: OK");
                        } else {
                            println!("  ✗ Mempool acceptance: REJECTED");
                            for (i, result) in results.iter().enumerate() {
                                if !result.allowed {
                                    println!(
                                        "    Transaction {}: {}",
                                        i,
                                        result.reject_reason.as_deref().unwrap_or("Unknown reason")
                                    );
                                }
                            }
                            break;
                        }
                    }
                    Err(e) => {
                        println!("  ✗ Mempool test failed: {}", e);
                        break;
                    }
                }

                current_size += increment;
                attempts += 1;
            }
            Err(e) => {
                println!(
                    "✗ Compose failed at {} bytes ({} KB): {}",
                    current_size,
                    current_size / 1024,
                    e
                );
                break;
            }
        }
    }

    if attempts >= max_attempts {
        println!(
            "⚠ Reached maximum attempts ({}) without failure",
            max_attempts
        );
        println!(
            "Last tested size: {} bytes ({} KB)",
            current_size - increment,
            (current_size - increment) / 1024
        );
    }

    println!(
        "Maximum successful data size: {} bytes ({} KB)",
        last_successful_size,
        last_successful_size / 1024
    );

    // Ensure we successfully tested at least some sizes
    assert!(
        last_successful_size > 0,
        "Should have at least one successful size"
    );

    Ok(())
}
