use anyhow::Result;
use bitcoin::{
    FeeRate, Network, TapSighashType,
    consensus::encode::serialize as serialize_tx,
    key::{Keypair, Secp256k1},
    taproot::{LeafVersion, TaprootBuilder},
};
use clap::Parser;
use indexer::{
    api::compose::{InstructionInputs, ComposeInputs, compose},
    bitcoin_client::Client,
    config::{Config, TestConfig},
    regtest_utils, test_utils,
    witness_data::TokenBalance,
};

#[tokio::test]
#[ignore]
async fn test_taproot_transaction_regtest() -> Result<()> {
    // Initialize regtest client
    let mut config = Config::try_parse()?;
    config.bitcoin_rpc_url = "http://127.0.0.1:18443".to_string();

    let client = Client::new_from_config(&config)?;
    let test_config = TestConfig::try_parse()?;
    let network = Network::Regtest;

    // Set up wallet if needed - this will ensure we have funds
    regtest_utils::ensure_wallet_setup(&client).await?;

    let secp = Secp256k1::new();

    // Generate taproot address
    let (seller_address, seller_child_key, _) = test_utils::generate_taproot_address_from_mnemonic(
        &secp,
        network,
        &test_config.taproot_key_path,
        0,
    )?;

    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    // Get a UTXO from the regtest wallet - use a smaller amount (5000 sats)
    let (out_point, utxo_for_output) =
        regtest_utils::make_regtest_utxo(&client, &seller_address).await?;

    // Create token balance data
    let token_value = 500;
    let token_balance = TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let compose_params = ComposeInputs::builder()
        .instructions(vec![InstructionInputs {
            address: seller_address.clone(),
            x_only_public_key: internal_key,
            funding_utxos: vec![(out_point, utxo_for_output.clone())],
            script_data: serialized_token_balance,
        }])
        .fee_rate(FeeRate::from_sat_per_vb(1).unwrap()) // Lower fee rate for regtest
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

    let attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let spend_tx_hex = hex::encode(serialize_tx(&spend_tx));

    let result = client
        .test_mempool_accept(&[attach_tx_hex, spend_tx_hex])
        .await?;

    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(
        result[0].allowed,
        "Attach transaction was rejected: {}",
        result[0].reject_reason.as_ref().unwrap_or(&"".to_string())
    );
    assert!(
        result[1].allowed,
        "Spend transaction was rejected: {}",
        result[1].reject_reason.as_ref().unwrap_or(&"".to_string())
    );

    // Verify witness structure
    let witness = spend_tx.input[0].witness.clone();
    assert_eq!(witness.len(), 3, "Witness should have exactly 3 elements");

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
