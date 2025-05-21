use std::str::FromStr;

use anyhow::Result;
use bitcoin::{Amount, OutPoint, TxOut, Txid};

use crate::bitcoin_client::{Client, client::RegtestRpc, types::RawTransactionInput};

pub async fn ensure_wallet_setup(client: &Client) -> Result<()> {
    // Check if wallet exists
    let wallet_name = "regtest_taproot_wallet";

    // Try to load the wallet first - this is safer than checking if it exists
    match client.load_wallet(wallet_name).await {
        Ok(_) => {
            println!("Successfully loaded existing wallet");
        }
        Err(_) => {
            // If loading fails, try to create it
            println!("Wallet not loaded, attempting to create it");
            match client.create_wallet(wallet_name).await {
                Ok(_) => println!("Created new wallet"),
                Err(e) => {
                    println!("Error creating wallet: {}", e);
                    // If creation fails but it might be because the wallet exists,
                    // continue anyway
                }
            }
        }
    }

    // Check spendable funds
    let unspent = client.list_unspent(1, 9999999, &[]).await?;

    // If we have no spendable UTXOs, we need to generate and mature coins
    if unspent.is_empty() {
        // Get a mining address
        let mining_address = client.get_new_address().await?;

        // Generate 101 blocks to get mature coins (coinbase needs 100 confirmations)
        client.generate_to_address(101, &mining_address).await?;

        // Generate 10 more blocks to another address to ensure we have multiple UTXOs
        let second_address = client.get_new_address().await?;
        client.generate_to_address(10, &second_address).await?;

        // Check UTXOs
        let new_unspent = client.list_unspent(1, 9999999, &[]).await?;

        if new_unspent.is_empty() {
            return Err(anyhow::anyhow!("Failed to generate spendable UTXOs"));
        }
    } else {
        // No-op since utxos already exist
    }

    Ok(())
}

pub async fn make_regtest_utxo(
    client: &Client,
    address: &bitcoin::Address,
) -> Result<(OutPoint, TxOut)> {
    // Amount to send to the taproot address
    let amount = Amount::from_sat(5000);

    // Get list of spendable UTXOs
    let unspent = client.list_unspent(1, 9999999, &[]).await?;

    if unspent.is_empty() {
        return Err(anyhow::anyhow!("No spendable UTXOs available"));
    }

    // Use the first available UTXO
    let input_utxo = &unspent[0];

    // Convert BTC to satoshis for precise calculation
    let input_amount_sats = (input_utxo.amount * 100_000_000.0) as u64;
    let output_amount_sats = amount.to_sat();
    let fee_sats = 1000; // 1000 satoshis fee

    // Calculate change amount in satoshis
    let change_amount_sats = input_amount_sats - output_amount_sats - fee_sats;

    // Convert back to BTC for the API
    let change_amount_btc = change_amount_sats as f64 / 100_000_000.0;

    // Create inputs for raw transaction
    let inputs = vec![RawTransactionInput {
        txid: input_utxo.txid.clone(),
        vout: input_utxo.vout,
        sequence: None,
    }];

    // Get a change address
    let change_address = client.get_new_address().await?;

    // Create outputs with precise amounts
    let mut outputs = std::collections::HashMap::new();
    outputs.insert(address.to_string(), amount.to_btc());
    outputs.insert(change_address, change_amount_btc);

    // Create the raw transaction
    let raw_tx = client
        .create_raw_transaction(&inputs, &outputs, None, None)
        .await?;

    // Sign the transaction
    let signed_tx = client.sign_raw_transaction_with_wallet(&raw_tx).await?;

    if !signed_tx.complete {
        return Err(anyhow::anyhow!("Failed to sign transaction"));
    }

    // Send the transaction
    let txid_str = client.send_raw_transaction(&signed_tx.hex).await?;

    let txid = Txid::from_str(&txid_str).unwrap();

    // Generate a block to confirm the transaction
    let mining_address = client.get_new_address().await?;
    client.generate_to_address(1, &mining_address).await?;

    // Since we can't rely on list_unspent for the taproot address,
    // we'll just create the OutPoint and TxOut directly
    let vout = 0; // Assuming the taproot address is the first output

    let out_point = OutPoint { txid, vout };
    let utxo_out = TxOut {
        value: amount,
        script_pubkey: address.script_pubkey(),
    };

    Ok((out_point, utxo_out))
}
