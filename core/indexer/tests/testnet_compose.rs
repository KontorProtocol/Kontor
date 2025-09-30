use anyhow::Result;
use bitcoin::FeeRate;
use bitcoin::Network;
use bitcoin::TapSighashType;
use bitcoin::secp256k1::Keypair;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{
    Amount, OutPoint, Txid, consensus::encode::serialize as serialize_tx, key::Secp256k1,
    transaction::TxOut,
};
use clap::Parser;
use indexer::api::compose::compose;
use indexer::api::compose::{ComposeAddressInputs, ComposeInputs};
use indexer::config::TestConfig;
use indexer::test_utils;
use indexer::witness_data::TokenBalance;
use indexer::{bitcoin_client::Client, logging};
use std::str::FromStr;
use tracing::info;

#[tokio::test]
async fn test_taproot_transaction_testnet() -> Result<()> {
    // Initialize testnet client
    let config = TestConfig::try_parse()?;
    let network = Network::Testnet4;

    let client = Client::new_from_config(&config)?;

    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) = test_utils::generate_taproot_address_from_mnemonic(
        &secp,
        network,
        &config.taproot_key_path,
        0,
    )?;

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
        .addresses(vec![ComposeAddressInputs {
            address: seller_address.clone(),
            x_only_public_key: internal_key,
            funding_utxos: vec![(out_point, utxo_for_output.clone())],
            script_data: serialized_token_balance,
        }])
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .envelope(546)
        .build();

    let compose_outputs = compose(compose_params)?;

    let mut attach_tx = compose_outputs.commit_transaction;
    let mut spend_tx = compose_outputs.reveal_transaction;
    let tap_script = compose_outputs.per_participant[0].commit.tap_script.clone();

    // Sign the attach transaction
    test_utils::sign_key_spend(
        &secp,
        &mut attach_tx,
        &[utxo_for_output],
        &keypair,
        0,
        Some(TapSighashType::All),
    )?;

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
    logging::setup();

    // Initialize testnet client
    let config = TestConfig::try_parse()?;
    let network = Network::Testnet4;

    let client = Client::new_from_config(&config)?;

    let secp = Secp256k1::new();

    // Generate taproot address and keys
    let (seller_address, seller_child_key, _) = test_utils::generate_taproot_address_from_mnemonic(
        &secp,
        network,
        &config.taproot_key_path,
        0,
    )?;
    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    // Available testnet UTXOs with 500,000 sats each
    let available_utxos: Vec<(OutPoint, TxOut)> = vec![
        (
            OutPoint {
                txid: Txid::from_str(
                    "738c9c29646f2efe149fc3abb23976f4e3c3009656bdb4349a8e04570ed2ba9a",
                )?,
                vout: 1,
            },
            TxOut {
                value: Amount::from_sat(500000),
                script_pubkey: seller_address.script_pubkey(),
            },
        ),
        (
            OutPoint {
                txid: Txid::from_str(
                    "3b11a1a857ca8c0949ae13782c1371352ef42541cec19f7f75b9998db8aeddf6",
                )?,
                vout: 0,
            },
            TxOut {
                value: Amount::from_sat(500000),
                script_pubkey: seller_address.script_pubkey(),
            },
        ),
    ];

    // Test progression: 10KB -> 20KB -> ... -> 390KB -> 397KB -> 400KB
    let mut current_size = 10_000;
    let increment = 10_000;

    while current_size <= 400_000 {
        let data = vec![0xFF; current_size];

        // Compose transaction
        let compose_params = ComposeInputs::builder()
            .addresses(vec![ComposeAddressInputs {
                address: seller_address.clone(),
                x_only_public_key: internal_key,
                funding_utxos: available_utxos.clone(),
                script_data: data,
            }])
            .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
            .envelope(546)
            .build();
        let compose_outputs = compose(compose_params)?;

        let mut attach_tx = compose_outputs.commit_transaction;
        let mut spend_tx = compose_outputs.reveal_transaction;
        let tap_script = compose_outputs.per_participant[0].commit.tap_script.clone();

        // Sign commit inputs with correctly ordered prevouts matching the selected inputs
        let commit_prevouts: Vec<TxOut> = attach_tx
            .input
            .iter()
            .map(|txin| {
                let op = txin.previous_output;
                available_utxos
                    .iter()
                    .find(|(outpoint, _)| outpoint.txid == op.txid && outpoint.vout == op.vout)
                    .map(|(_, utxo)| utxo.clone())
                    .expect("matching prevout for commit input")
            })
            .collect();
        test_utils::sign_multiple_key_spend(&secp, &mut attach_tx, &commit_prevouts, &keypair)?;

        // Sign the script_spend input for the reveal transaction
        let spend_tx_prevouts = vec![attach_tx.output[0].clone()];
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

        // Test mempool acceptance
        let attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
        let spend_tx_hex = hex::encode(serialize_tx(&spend_tx));
        let result = client
            .test_mempool_accept(&[attach_tx_hex, spend_tx_hex])
            .await?;

        assert_eq!(result.len(), 2, "Expected exactly two transaction results");

        let commit_accepted = result[0].allowed;
        let reveal_accepted = result[1].allowed;
        let status = if commit_accepted && reveal_accepted {
            "accepted"
        } else {
            "rejected"
        };

        info!(
            "{}KB data {} - Commit TX: {} bytes, Reveal TX: {} bytes",
            current_size / 1000,
            status,
            serialize_tx(&attach_tx).len(),
            serialize_tx(&spend_tx).len(),
        );

        // Handle 400KB limit test - should be rejected due to tx-size
        if current_size == 400_000 {
            assert!(
                !result[1].allowed,
                "400KB reveal transaction should be rejected"
            );
            assert_eq!(
                result[1].reject_reason.as_deref(),
                Some("tx-size"),
                "400KB reveal transaction should be rejected due to tx-size, got: {:?}",
                result[1].reject_reason
            );
            assert!(
                !result[0].allowed,
                "400KB commit transaction should be rejected: {}",
                result[0].reject_reason.as_deref().unwrap_or("none")
            );
            info!("400KB correctly rejected due to Bitcoin's tx-size limit");
            break;
        }

        // For all other sizes, transactions should be accepted
        assert!(
            result[1].allowed,
            "{}KB reveal transaction was rejected: {}",
            current_size / 1000,
            result[1].reject_reason.as_deref().unwrap_or("none")
        );
        assert!(
            result[0].allowed,
            "{}KB commit transaction was rejected: {}",
            current_size / 1000,
            result[0].reject_reason.as_deref().unwrap_or("none")
        );

        // Determine next test size
        current_size = match current_size {
            390_000 => 397_150,            // Test near the limit after 390KB
            397_150 => 400_000,            // Test the exact limit after 397KB
            _ => current_size + increment, // Regular increment
        };
    }

    Ok(())
}
