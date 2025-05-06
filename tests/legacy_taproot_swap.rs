use anyhow::Result;
use bitcoin::Witness;
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::Instruction;
use bitcoin::secp256k1::Keypair;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{
    address::{Address, KnownHrp},
    consensus::encode::serialize as serialize_tx,
    key::Secp256k1,
};
use clap::Parser;
use kontor::config::TestConfig;
use kontor::witness_data::TokenBalance;
use kontor::{bitcoin_client::Client, config::Config, op_return::OpReturnData};
use kontor::{legacy_test_utils, test_utils};
use std::collections::HashMap;

#[tokio::test]
async fn test_taproot_transaction() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;

    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 0)?;

    let (buyer_address, buyer_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 1)?;

    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    // Create token balance data
    let token_value = 1000;
    let token_balance = TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    // Create the tapscript with x-only public key
    let tap_script = legacy_test_utils::build_witness_script(
        legacy_test_utils::PublicKey::Taproot(&internal_key),
        &serialized_token_balance,
    );

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

    let attach_tx = legacy_test_utils::build_signed_taproot_attach_tx(
        &secp,
        &keypair,
        &seller_address,
        &script_spendable_address,
    )?;

    let (mut seller_psbt, signature, control_block) =
        legacy_test_utils::build_seller_psbt_and_sig_taproot(
            &secp,
            &keypair,
            &seller_address,
            &attach_tx,
            &internal_key,
            &taproot_spend_info,
            &tap_script,
        )?;

    // Build the witness stack for script path spending
    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"kon");
    witness.push(tap_script.as_bytes());
    witness.push(control_block.serialize());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = legacy_test_utils::build_signed_buyer_psbt_taproot(
        &secp,
        &buyer_child_key,
        &buyer_address,
        &seller_address,
        &attach_tx,
        &script_spendable_address,
        &seller_psbt,
    )?;

    // Extract the transaction (no finalize needed since we set all witnesses manually)
    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = client
        .test_mempool_accept(&[raw_attach_tx_hex, raw_swap_tx_hex])
        .await?;

    // Assert both transactions are allowed
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(result[1].allowed, "Swap transaction was rejected");

    let witness = final_tx.input[0].witness.clone();
    // 1. Check the total number of witness elements first
    assert_eq!(witness.len(), 5, "Witness should have exactly 5 elements");

    // 2. Check each element individually
    let signature = witness.to_vec()[0].clone();
    assert!(!signature.is_empty(), "Signature should not be empty");

    let token_balance_bytes = witness.to_vec()[1].clone();
    let token_balance_decoded: TokenBalance =
        ciborium::from_reader(&token_balance_bytes[..]).unwrap();
    assert_eq!(
        token_balance_decoded, token_balance,
        "Token balance in witness doesn't match expected value"
    );

    let kon_bytes = witness.to_vec()[2].clone();
    assert_eq!(
        kon_bytes, b"kon",
        "kon string in witness doesn't match expected value"
    );

    let script_bytes = witness.to_vec()[3].clone();
    assert_eq!(
        script_bytes,
        tap_script.as_bytes().to_vec(),
        "Script in witness doesn't match expected script"
    );

    let control_block_bytes = witness.to_vec()[4].clone();

    assert_eq!(
        control_block_bytes,
        control_block.serialize(),
        "Control block in witness doesn't match expected control block"
    );

    // Assert deserialize attached op_return data
    let attach_op_return_script = &attach_tx.output[1].script_pubkey; // OP_RETURN is the second output

    let attach_instructions = attach_op_return_script
        .instructions()
        .collect::<Result<Vec<_>, _>>()?;
    let [
        Instruction::Op(OP_RETURN),
        Instruction::PushBytes(prefix),
        Instruction::PushBytes(data),
    ] = attach_instructions.as_slice()
    else {
        panic!("Invalid OP_RETURN script format");
    };
    assert_eq!(prefix.as_bytes(), b"kon");
    let attach_op_return_data: OpReturnData = ciborium::from_reader(data.as_bytes())?;
    assert_eq!(attach_op_return_data, OpReturnData::A { output_index: 0 });

    // Assert deserialize swap op_return data
    let swap_op_return_script = &final_tx.output[1].script_pubkey; // OP_RETURN is the second output
    let swap_instructions = swap_op_return_script
        .instructions()
        .collect::<Result<Vec<_>, _>>()?;
    let [
        Instruction::Op(OP_RETURN),
        Instruction::PushBytes(prefix),
        Instruction::PushBytes(data),
    ] = swap_instructions.as_slice()
    else {
        panic!("Invalid OP_RETURN script format");
    };
    assert_eq!(prefix.as_bytes(), b"kon");
    let swap_op_return_data: OpReturnData = ciborium::from_reader(data.as_bytes())?;
    assert_eq!(
        swap_op_return_data,
        OpReturnData::S {
            destination: buyer_address.script_pubkey().as_bytes().to_vec(),
        }
    );

    Ok(())
}

#[tokio::test]
async fn test_psbt_with_incorrect_prefix() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;

    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 0)?;

    let (buyer_address, buyer_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 1)?;

    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    // Create token balance data
    let token_value = 1000;
    let token_balance = TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    // Create the tapscript with x-only public key
    let tap_script = legacy_test_utils::build_witness_script(
        legacy_test_utils::PublicKey::Taproot(&internal_key),
        &serialized_token_balance,
    );

    // Build the Taproot tree with the script
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone()) // Add script at depth 0
        .expect("Failed to add leaf")
        .finalize(&secp, internal_key) // does this need to be the whole keypair then?
        .expect("Failed to finalize Taproot tree");
    // Get the output key which commits to both the internal key and the script tree
    let output_key = taproot_spend_info.output_key();

    // Create the address from the output key
    let script_spendable_address = Address::p2tr_tweaked(output_key, KnownHrp::Mainnet);

    let attach_tx = legacy_test_utils::build_signed_taproot_attach_tx(
        &secp,
        &keypair,
        &seller_address,
        &script_spendable_address,
    )?;

    let (mut seller_psbt, signature, control_block) =
        legacy_test_utils::build_seller_psbt_and_sig_taproot(
            &secp,
            &keypair,
            &seller_address,
            &attach_tx,
            &internal_key,
            &taproot_spend_info,
            &tap_script,
        )?;

    // Build the witness stack for script path spending
    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"KNR");
    witness.push(tap_script.as_bytes());
    witness.push(control_block.serialize());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = legacy_test_utils::build_signed_buyer_psbt_taproot(
        &secp,
        &buyer_child_key,
        &buyer_address,
        &seller_address,
        &attach_tx,
        &script_spendable_address,
        &seller_psbt,
    )?;

    // Extract the transaction
    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = client
        .test_mempool_accept(&[raw_attach_tx_hex, raw_swap_tx_hex])
        .await?;

    // Assert both transactions are allowed
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(!result[1].allowed, "Swap transaction was rejected");
    assert!(
        result[1]
            .reject_reason
            .as_ref()
            .unwrap()
            .contains("OP_EQUALVERIFY"),
        "Swap transaction was rejected for unknown reason"
    );

    Ok(())
}

#[tokio::test]
async fn test_taproot_transaction_without_tapscript() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;

    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 0)?;

    let (buyer_address, buyer_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 1)?;

    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    // Create token balance data
    let token_value = 1000;
    let token_balance = TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    // Create the tapscript with x-only public key
    let tap_script = legacy_test_utils::build_witness_script(
        legacy_test_utils::PublicKey::Taproot(&internal_key),
        &serialized_token_balance,
    );

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

    let attach_tx = legacy_test_utils::build_signed_taproot_attach_tx(
        &secp,
        &keypair,
        &seller_address,
        &script_spendable_address,
    )?;

    let (mut seller_psbt, signature, control_block) =
        legacy_test_utils::build_seller_psbt_and_sig_taproot(
            &secp,
            &keypair,
            &seller_address,
            &attach_tx,
            &internal_key,
            &taproot_spend_info,
            &tap_script,
        )?;

    // Build the witness stack for script path spending
    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"kon");
    witness.push(control_block.serialize());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = legacy_test_utils::build_signed_buyer_psbt_taproot(
        &secp,
        &buyer_child_key,
        &buyer_address,
        &seller_address,
        &attach_tx,
        &script_spendable_address,
        &seller_psbt,
    )?;

    // Extract the transaction
    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = client
        .test_mempool_accept(&[raw_attach_tx_hex, raw_swap_tx_hex])
        .await?;

    // Assert both transactions are allowed
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(!result[1].allowed, "Swap transaction was rejected");
    assert!(
        result[1]
            .reject_reason
            .as_ref()
            .unwrap()
            .contains("Witness program hash mismatch"),
        "Swap transaction was rejected for unknown reason"
    );

    Ok(())
}

#[tokio::test]
async fn test_taproot_transaction_with_wrong_token() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;

    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 0)?;

    let (buyer_address, buyer_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 1)?;

    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    // Create token balance data
    let token_value = 1000;
    let token_balance = TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    // Create the tapscript with x-only public key
    let tap_script = legacy_test_utils::build_witness_script(
        legacy_test_utils::PublicKey::Taproot(&internal_key),
        &serialized_token_balance,
    );

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

    let attach_tx = legacy_test_utils::build_signed_taproot_attach_tx(
        &secp,
        &keypair,
        &seller_address,
        &script_spendable_address,
    )?;

    let (mut seller_psbt, signature, control_block) =
        legacy_test_utils::build_seller_psbt_and_sig_taproot(
            &secp,
            &keypair,
            &seller_address,
            &attach_tx,
            &internal_key,
            &taproot_spend_info,
            &tap_script,
        )?;

    let wrong_token_balance = TokenBalance {
        value: token_value,
        name: "wrong_token_name".to_string(),
    };

    let mut serialized_wrong_token_balance = Vec::new();
    ciborium::into_writer(&wrong_token_balance, &mut serialized_wrong_token_balance).unwrap();

    // Build the witness stack for script path spending
    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(&serialized_wrong_token_balance);
    witness.push(b"kon");
    witness.push(tap_script.as_bytes());
    witness.push(control_block.serialize());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = legacy_test_utils::build_signed_buyer_psbt_taproot(
        &secp,
        &buyer_child_key,
        &buyer_address,
        &seller_address,
        &attach_tx,
        &script_spendable_address,
        &seller_psbt,
    )?;

    // Extract the transaction
    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = client
        .test_mempool_accept(&[raw_attach_tx_hex, raw_swap_tx_hex])
        .await?;

    // Assert both transactions are allowed
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(!result[1].allowed, "Swap transaction was rejected");
    assert!(
        result[1]
            .reject_reason
            .as_ref()
            .unwrap()
            .contains("OP_EQUALVERIFY"),
        "Swap transaction was rejected for unknown reason"
    );
    Ok(())
}

#[tokio::test]
async fn test_taproot_transaction_with_wrong_token_amount() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;

    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 0)?;

    let (buyer_address, buyer_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 1)?;

    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    // Create token balance data
    let token_value = 1000;
    let token_balance = TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    // Create the tapscript with x-only public key
    let tap_script = legacy_test_utils::build_witness_script(
        legacy_test_utils::PublicKey::Taproot(&internal_key),
        &serialized_token_balance,
    );
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

    let attach_tx = legacy_test_utils::build_signed_taproot_attach_tx(
        &secp,
        &keypair,
        &seller_address,
        &script_spendable_address,
    )?;

    let (mut seller_psbt, signature, control_block) =
        legacy_test_utils::build_seller_psbt_and_sig_taproot(
            &secp,
            &keypair,
            &seller_address,
            &attach_tx,
            &internal_key,
            &taproot_spend_info,
            &tap_script,
        )?;

    let wrong_token_balance = TokenBalance {
        value: 900,
        name: "token_name".to_string(),
    };

    let mut serialized_wrong_token_balance = Vec::new();
    ciborium::into_writer(&wrong_token_balance, &mut serialized_wrong_token_balance).unwrap();

    // Build the witness stack for script path spending
    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(&serialized_wrong_token_balance);
    witness.push(b"kon");
    witness.push(tap_script.as_bytes());
    witness.push(control_block.serialize());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = legacy_test_utils::build_signed_buyer_psbt_taproot(
        &secp,
        &buyer_child_key,
        &buyer_address,
        &seller_address,
        &attach_tx,
        &script_spendable_address,
        &seller_psbt,
    )?;

    // Extract the transaction
    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = client
        .test_mempool_accept(&[raw_attach_tx_hex, raw_swap_tx_hex])
        .await?;

    // Assert both transactions are allowed
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(!result[1].allowed, "Swap transaction was rejected");
    assert!(
        result[1]
            .reject_reason
            .as_ref()
            .unwrap()
            .contains("OP_EQUALVERIFY"),
        "Swap transaction was rejected for unknown reason"
    );
    Ok(())
}

#[tokio::test]
async fn test_taproot_transaction_without_token_balance() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;

    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 0)?;

    let (buyer_address, buyer_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 1)?;

    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    // Create token balance data
    let token_value = 1000;
    let token_balance = TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    // Create the tapscript with x-only public key
    let tap_script = legacy_test_utils::build_witness_script(
        legacy_test_utils::PublicKey::Taproot(&internal_key),
        &serialized_token_balance,
    );

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

    let attach_tx = legacy_test_utils::build_signed_taproot_attach_tx(
        &secp,
        &keypair,
        &seller_address,
        &script_spendable_address,
    )?;

    let (mut seller_psbt, signature, control_block) =
        legacy_test_utils::build_seller_psbt_and_sig_taproot(
            &secp,
            &keypair,
            &seller_address,
            &attach_tx,
            &internal_key,
            &taproot_spend_info,
            &tap_script,
        )?;

    // Build the witness stack for script path spending
    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(b"kon");
    witness.push(tap_script.as_bytes());
    witness.push(control_block.serialize());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = legacy_test_utils::build_signed_buyer_psbt_taproot(
        &secp,
        &buyer_child_key,
        &buyer_address,
        &seller_address,
        &attach_tx,
        &script_spendable_address,
        &seller_psbt,
    )?;

    // Extract the transaction
    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = client
        .test_mempool_accept(&[raw_attach_tx_hex, raw_swap_tx_hex])
        .await?;

    // Assert both transactions are allowed
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(!result[1].allowed, "Swap transaction was rejected");
    assert!(
        result[1]
            .reject_reason
            .as_ref()
            .unwrap()
            .contains("OP_EQUALVERIFY"),
        "Swap transaction was rejected for unknown reason"
    );
    Ok(())
}

#[tokio::test]
async fn test_taproot_transaction_without_control_block() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;

    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 0)?;

    let (buyer_address, buyer_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 1)?;

    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    // Create token balance data
    let token_value = 1000;
    let token_balance = TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    // Create the tapscript with x-only public key
    let tap_script = legacy_test_utils::build_witness_script(
        legacy_test_utils::PublicKey::Taproot(&internal_key),
        &serialized_token_balance,
    );

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

    let attach_tx = legacy_test_utils::build_signed_taproot_attach_tx(
        &secp,
        &keypair,
        &seller_address,
        &script_spendable_address,
    )?;

    let (mut seller_psbt, signature, _control_block) =
        legacy_test_utils::build_seller_psbt_and_sig_taproot(
            &secp,
            &keypair,
            &seller_address,
            &attach_tx,
            &internal_key,
            &taproot_spend_info,
            &tap_script,
        )?;

    // Build the witness stack for script path spending
    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"kon");
    witness.push(tap_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = legacy_test_utils::build_signed_buyer_psbt_taproot(
        &secp,
        &buyer_child_key,
        &buyer_address,
        &seller_address,
        &attach_tx,
        &script_spendable_address,
        &seller_psbt,
    )?;

    // Extract the transaction
    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = client
        .test_mempool_accept(&[raw_attach_tx_hex, raw_swap_tx_hex])
        .await?;

    // Assert both transactions are allowed
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(!result[1].allowed, "Swap transaction was rejected");
    assert!(
        result[1]
            .reject_reason
            .as_ref()
            .unwrap()
            .contains("Invalid Taproot control block size"),
        "Swap transaction was rejected for unknown reason"
    );

    Ok(())
}

#[tokio::test]
async fn test_taproot_transaction_with_long_witness_stack() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;

    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 0)?;

    let (buyer_address, buyer_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 1)?;

    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    let token_balances = legacy_test_utils::build_long_token_balance();

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balances, &mut serialized_token_balance).unwrap();

    // Create the tapscript with x-only public key
    let tap_script = legacy_test_utils::build_witness_script(
        legacy_test_utils::PublicKey::Taproot(&internal_key),
        &serialized_token_balance,
    );

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

    let attach_tx = legacy_test_utils::build_signed_taproot_attach_tx(
        &secp,
        &keypair,
        &seller_address,
        &script_spendable_address,
    )?;

    let (mut seller_psbt, signature, control_block) =
        legacy_test_utils::build_seller_psbt_and_sig_taproot(
            &secp,
            &keypair,
            &seller_address,
            &attach_tx,
            &internal_key,
            &taproot_spend_info,
            &tap_script,
        )?;

    // Build the witness stack for script path spending
    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"kon");
    witness.push(tap_script.as_bytes());
    witness.push(control_block.serialize());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = legacy_test_utils::build_signed_buyer_psbt_taproot(
        &secp,
        &buyer_child_key,
        &buyer_address,
        &seller_address,
        &attach_tx,
        &script_spendable_address,
        &seller_psbt,
    )?;

    // Extract the transaction (no finalize needed since we set all witnesses manually)
    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = client
        .test_mempool_accept(&[raw_attach_tx_hex, raw_swap_tx_hex])
        .await?;

    // Assert both transactions are allowed
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    // assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(!result[1].allowed, "Swap transaction was accepted");
    assert!(
        result[1]
            .reject_reason
            .as_ref()
            .unwrap()
            .contains("bad-witness-nonstandard"),
    );
    let witness = final_tx.input[0].witness.clone();
    // 1. Check the total number of witness elements first
    assert_eq!(witness.len(), 5, "Witness should have exactly 5 elements");

    // 2. Check each element individually
    let signature = witness.to_vec()[0].clone();
    assert!(!signature.is_empty(), "Signature should not be empty");

    let token_balance_bytes = witness.to_vec()[1].clone();
    let token_balance_decoded: HashMap<String, i32> =
        ciborium::from_reader(&token_balance_bytes[..]).unwrap();
    assert_eq!(
        token_balance_decoded, token_balances,
        "Token balance in witness doesn't match expected value"
    );

    let kon_bytes = witness.to_vec()[2].clone();
    assert_eq!(
        kon_bytes, b"kon",
        "kon string in witness doesn't match expected value"
    );

    let script_bytes = witness.to_vec()[3].clone();
    assert_eq!(
        script_bytes,
        tap_script.as_bytes().to_vec(),
        "Script in witness doesn't match expected script"
    );

    let control_block_bytes = witness.to_vec()[4].clone();

    assert_eq!(
        control_block_bytes,
        control_block.serialize(),
        "Control block in witness doesn't match expected control block"
    );

    Ok(())
}
