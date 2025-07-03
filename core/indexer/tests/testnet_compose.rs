use anyhow::Result;
use bitcoin::FeeRate;
use bitcoin::Network;
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::secp256k1::Keypair;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{
    Amount, OutPoint, Txid, consensus::encode::serialize as serialize_tx, key::Secp256k1,
    transaction::TxOut,
};
use clap::Parser;
use indexer::api::compose::compose;

use indexer::api::compose::ComposeInputs;
use indexer::config::TestConfig;
use indexer::test_utils;
use indexer::witness_data::TokenBalance;
use indexer::{bitcoin_client::Client, config::Config};
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

#[tokio::test]
async fn test_compose_progressive_size_limit_testnet() -> Result<()> {
    // Initialize testnet client
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

    // Available testnet UTXOs with 500,000 sats each
    let available_utxos = [
        (
            "738c9c29646f2efe149fc3abb23976f4e3c3009656bdb4349a8e04570ed2ba9a",
            1,
        ),
        (
            "3b11a1a857ca8c0949ae13782c1371352ef42541cec19f7f75b9998db8aeddf6",
            0,
        ),
        (
            "ec8c3987df9ad02411aacfad5e7af87579e9192c7b06dcb4e2c8c125554bec09",
            0,
        ),
    ];

    // Start with 10KB and increment by 10KB each iteration to find the exact limit
    let mut current_size = 10_000; // Start with 10KB  
    let increment = 10_000; // Increase by 10KB each iteration
    let max_attempts = 50; // Test up to ~500KB, but using single UTXO as much as possible

    let mut last_successful_size = 0;
    let mut attempts = 0;

    println!("Testing progressive data size limits on testnet...");

    while attempts < max_attempts {
        let data = vec![0xFF; current_size];

        // Use single UTXO for as long as possible to avoid multi-input signing issues
        // Only use multiple UTXOs if we exceed what a single 500k sat UTXO can handle
        let estimated_fee = current_size * 2; // Very rough estimate: 2 sats per byte
        let utxos_needed = if estimated_fee < 400_000 {
            1 // Single UTXO can handle up to ~400k sat in fees
        } else {
            std::cmp::min(
                ((estimated_fee / 400_000) + 1).max(1),
                available_utxos.len(),
            )
        };

        let funding_utxos: Vec<(OutPoint, TxOut)> = {
            let mut utxos = Vec::new();
            for (txid_str, vout) in available_utxos.iter().take(utxos_needed) {
                let out_point = OutPoint {
                    txid: Txid::from_str(txid_str).unwrap(),
                    vout: *vout,
                };

                // Fetch the real UTXO from the blockchain
                let tx = client.get_raw_transaction(&out_point.txid).await?;
                let utxo_for_output = tx.output[out_point.vout as usize].clone();

                utxos.push((out_point, utxo_for_output));
            }
            utxos
        };

        println!(
            "Testing {}KB data with {} UTXOs...",
            current_size / 1000,
            utxos_needed
        );

        let compose_params = ComposeInputs::builder()
            .address(seller_address.clone())
            .x_only_public_key(internal_key)
            .funding_utxos(funding_utxos.clone())
            .script_data(data)
            .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
            .envelope(546)
            .build();

        match compose(compose_params) {
            Ok(compose_outputs) => {
                let mut attach_tx = compose_outputs.commit_transaction;
                let mut spend_tx: bitcoin::Transaction = compose_outputs.reveal_transaction;
                let tap_script = compose_outputs.tap_script;

                // Sign the attach transaction with multiple inputs
                let all_utxos: Vec<TxOut> =
                    funding_utxos.iter().map(|(_, utxo)| utxo.clone()).collect();

                if funding_utxos.len() == 1 {
                    // Single input - use the existing function
                    test_utils::sign_key_spend(&secp, &mut attach_tx, &all_utxos, &keypair, 0)?;
                } else {
                    // Multi-input - sign all inputs with proper witness handling
                    test_utils::sign_multiple_key_spend(
                        &secp,
                        &mut attach_tx,
                        &all_utxos,
                        &keypair,
                    )?;
                }

                let spend_tx_prevouts = vec![attach_tx.output[0].clone()];

                // Sign the script_spend input for the spend transaction
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

                println!("attach_tx: {:#?}", attach_tx);
                let attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
                let spend_tx_hex = hex::encode(serialize_tx(&spend_tx));
                // Test mempool acceptance
                match client
                    .test_mempool_accept(&[attach_tx_hex.clone(), spend_tx_hex.clone()])
                    .await
                {
                    Ok(result) => {
                        println!("result: {:#?}", result);
                        let commit_accepted = result[0].allowed;
                        let reveal_accepted = result[1].allowed;

                        if commit_accepted && reveal_accepted {
                            last_successful_size = current_size;
                            println!(
                                "✅ {}KB data successful - Commit TX: {} bytes, Reveal TX: {} bytes, Total: {} bytes",
                                current_size / 1000,
                                serialize_tx(&attach_tx).len(),
                                serialize_tx(&spend_tx).len(),
                                serialize_tx(&attach_tx).len() + serialize_tx(&spend_tx).len()
                            );
                        } else {
                            println!(
                                "❌ {}KB data failed mempool acceptance - Commit accepted: {}, Reveal accepted: {}",
                                current_size / 1000,
                                commit_accepted,
                                reveal_accepted
                            );
                            if !commit_accepted {
                                println!(
                                    "   Commit rejection reason: {}",
                                    result[0].reject_reason.as_deref().unwrap_or("unknown")
                                );
                            }
                            if !reveal_accepted {
                                println!(
                                    "   Reveal rejection reason: {}",
                                    result[1].reject_reason.as_deref().unwrap_or("unknown")
                                );
                            }
                            break;
                        }
                    }
                    Err(e) => {
                        println!("❌ {}KB data failed with error: {}", current_size / 1000, e);
                        break;
                    }
                }
            }
            Err(e) => {
                println!("❌ {}KB data failed to compose: {}", current_size / 1000, e);
                break;
            }
        }

        current_size += increment;
        attempts += 1;
    }

    println!("\n📊 Test Results Summary:");
    println!(
        "Last successful size: {}KB ({} bytes)",
        last_successful_size / 1000,
        last_successful_size
    );
    println!("Total attempts: {}", attempts);

    if attempts >= max_attempts {
        println!("⚠️  Reached maximum attempts without finding limit");
    }

    // Don't fail the test - this is exploratory
    Ok(())
}
