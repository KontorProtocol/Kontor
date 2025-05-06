use anyhow::Result;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF};
use bitcoin::script::Instruction;
use bitcoin::{CompressedPublicKey, ScriptBuf};
use bitcoin::{Witness, consensus::encode::serialize as serialize_tx, key::Secp256k1};
use clap::Parser;
use kontor::config::TestConfig;
use kontor::witness_data::TokenBalance;
use kontor::{bitcoin_client::Client, config::Config};
use kontor::{legacy_test_utils, test_utils};

#[tokio::test]
async fn test_psbt_inscription() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        legacy_test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        legacy_test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let token_balance = TokenBalance {
        value: 1000,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let witness_script = test_utils::build_inscription(
        serialized_token_balance.clone(),
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
    )?;

    let attach_tx = legacy_test_utils::build_signed_attach_tx_segwit(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = legacy_test_utils::build_seller_psbt_and_sig_segwit(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(witness_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = legacy_test_utils::build_signed_buyer_psbt_segwit(
        &secp,
        &buyer_address,
        &buyer_child_key,
        &attach_tx,
        &buyer_compressed_pubkey,
        &seller_address,
        &seller_psbt,
    )?;

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

    // Assert deserialize swap witness script
    // After your assertions on witness length
    let witness = final_tx.input[0].witness.clone();
    assert_eq!(witness.len(), 2, "Witness should have exactly 2 elements");

    // Get the script from the witness
    let script_bytes = witness.to_vec()[1].clone();
    let script = ScriptBuf::from_bytes(script_bytes);

    // Parse the script instructions
    let instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;

    if let [
        Instruction::PushBytes(_key),
        Instruction::Op(op_checksig),
        Instruction::PushBytes(op_false),
        Instruction::Op(op_if),
        Instruction::PushBytes(kon),
        Instruction::PushBytes(op_0),
        Instruction::PushBytes(serialized_data),
        Instruction::Op(op_endif),
    ] = instructions.as_slice()
    {
        // Verify the opcodes
        assert!(op_false.is_empty(), "Expected empty push bytes");
        assert_eq!(*op_if, OP_IF, "Expected OP_IF");
        assert_eq!(kon.as_bytes(), b"kon", "Expected kon identifier");
        assert!(op_0.is_empty(), "Expected empty push bytes");
        assert_eq!(*op_endif, OP_ENDIF, "Expected OP_ENDIF");
        assert_eq!(*op_checksig, OP_CHECKSIG, "Expected OP_CHECKSIG");

        // Deserialize the token data
        let token_data: TokenBalance = ciborium::from_reader(serialized_data.as_bytes())?;

        // Verify the token data
        assert_eq!(
            token_data, token_balance,
            "Token data in witness doesn't match expected value"
        );

        let key_from_bytes = CompressedPublicKey::from_slice(_key.as_bytes())?;
        assert_eq!(key_from_bytes, seller_compressed_pubkey);
    } else {
        panic!("Script structure doesn't match expected pattern");
    }

    Ok(())
}

#[tokio::test]
async fn test_psbt_inscription_invalid_token_data() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        legacy_test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        legacy_test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let token_balance = TokenBalance {
        value: 1000,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let witness_script = test_utils::build_inscription(
        serialized_token_balance.clone(),
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
    )?;

    let attach_tx = legacy_test_utils::build_signed_attach_tx_segwit(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = legacy_test_utils::build_seller_psbt_and_sig_segwit(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;

    let malformed_token_balance = TokenBalance {
        value: 1000,
        name: "wrong_token_name".to_string(),
    };

    let mut serialized_malformed_token_balance = Vec::new();
    ciborium::into_writer(
        &malformed_token_balance,
        &mut serialized_malformed_token_balance,
    )
    .unwrap();

    let malformed_witness_script = test_utils::build_inscription(
        serialized_malformed_token_balance,
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
    )?;

    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(malformed_witness_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = legacy_test_utils::build_signed_buyer_psbt_segwit(
        &secp,
        &buyer_address,
        &buyer_child_key,
        &attach_tx,
        &buyer_compressed_pubkey,
        &seller_address,
        &seller_psbt,
    )?;

    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = client
        .test_mempool_accept(&[raw_attach_tx_hex, raw_swap_tx_hex])
        .await?;

    // Assert both transactions are allowed
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(!result[1].allowed, "Swap transaction was accepted");
    assert!(
        result[1]
            .reject_reason
            .as_ref()
            .unwrap_or(&String::new())
            .contains("Witness program hash mismatch"),
        "Unexpected reject reason"
    );

    // Assert deserialize swap witness script
    // After your assertions on witness length
    let witness = final_tx.input[0].witness.clone();
    assert_eq!(witness.len(), 2, "Witness should have exactly 2 elements");

    // Get the script from the witness
    let script_bytes = witness.to_vec()[1].clone();
    let script = ScriptBuf::from_bytes(script_bytes);

    // Parse the script instructions
    let instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;

    if let [
        Instruction::PushBytes(_key),
        Instruction::Op(op_checksig),
        Instruction::PushBytes(op_false),
        Instruction::Op(op_if),
        Instruction::PushBytes(kon),
        Instruction::PushBytes(op_0),
        Instruction::PushBytes(serialized_data),
        Instruction::Op(op_endif),
    ] = instructions.as_slice()
    {
        // Verify the opcodes
        assert!(op_false.is_empty(), "Expected empty push bytes");
        assert_eq!(*op_if, OP_IF, "Expected OP_IF");
        assert_eq!(kon.as_bytes(), b"kon", "Expected kon identifier");
        assert!(op_0.is_empty(), "Expected empty push bytes");
        assert_eq!(*op_endif, OP_ENDIF, "Expected OP_ENDIF");
        assert_eq!(*op_checksig, OP_CHECKSIG, "Expected OP_CHECKSIG");

        // Deserialize the token data
        let token_data: TokenBalance = ciborium::from_reader(serialized_data.as_bytes())?;

        // Verify the token data
        assert_eq!(
            token_data, malformed_token_balance,
            "Token data in witness doesn't match expected value"
        );

        let key_from_bytes = CompressedPublicKey::from_slice(_key.as_bytes())?;
        assert_eq!(key_from_bytes, seller_compressed_pubkey);
    } else {
        panic!("Script structure doesn't match expected pattern");
    }

    Ok(())
}

#[tokio::test]
async fn test_psbt_inscription_wrong_internal_key() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        legacy_test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        legacy_test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let token_balance = TokenBalance {
        value: 1000,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let witness_script = test_utils::build_inscription(
        serialized_token_balance.clone(),
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
    )?;

    let attach_tx = legacy_test_utils::build_signed_attach_tx_segwit(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = legacy_test_utils::build_seller_psbt_and_sig_segwit(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;

    let malformed_witness_script = test_utils::build_inscription(
        serialized_token_balance.clone(),
        test_utils::PublicKey::Segwit(&buyer_compressed_pubkey),
    )?;

    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(malformed_witness_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = legacy_test_utils::build_signed_buyer_psbt_segwit(
        &secp,
        &buyer_address,
        &buyer_child_key,
        &attach_tx,
        &buyer_compressed_pubkey,
        &seller_address,
        &seller_psbt,
    )?;

    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = client
        .test_mempool_accept(&[raw_attach_tx_hex, raw_swap_tx_hex])
        .await?;

    // Assert both transactions are allowed
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(!result[1].allowed, "Swap transaction was accepted");
    assert!(
        result[1]
            .reject_reason
            .as_ref()
            .unwrap_or(&String::new())
            .contains("Witness program hash mismatch"),
        "Unexpected reject reason"
    );

    // Assert deserialize swap witness script
    // After your assertions on witness length
    let witness = final_tx.input[0].witness.clone();
    assert_eq!(witness.len(), 2, "Witness should have exactly 2 elements");

    // Get the script from the witness
    let script_bytes = witness.to_vec()[1].clone();
    let script = ScriptBuf::from_bytes(script_bytes);

    // Parse the script instructions
    let instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;

    if let [
        Instruction::PushBytes(_key),
        Instruction::Op(op_checksig),
        Instruction::PushBytes(op_false),
        Instruction::Op(op_if),
        Instruction::PushBytes(kon),
        Instruction::PushBytes(op_0),
        Instruction::PushBytes(serialized_data),
        Instruction::Op(op_endif),
    ] = instructions.as_slice()
    {
        // Verify the opcodes
        assert!(op_false.is_empty(), "Expected empty push bytes");
        assert_eq!(*op_if, OP_IF, "Expected OP_IF");
        assert_eq!(kon.as_bytes(), b"kon", "Expected kon identifier");
        assert!(op_0.is_empty(), "Expected empty push bytes");
        assert_eq!(*op_endif, OP_ENDIF, "Expected OP_ENDIF");
        assert_eq!(*op_checksig, OP_CHECKSIG, "Expected OP_CHECKSIG");

        // Deserialize the token data
        let token_data: TokenBalance = ciborium::from_reader(serialized_data.as_bytes())?;

        // Verify the token data
        assert_eq!(
            token_data, token_balance,
            "Token data in witness doesn't match expected value"
        );

        let key_from_bytes = CompressedPublicKey::from_slice(_key.as_bytes())?;
        assert_eq!(key_from_bytes, buyer_compressed_pubkey);
    } else {
        panic!("Script structure doesn't match expected pattern");
    }

    Ok(())
}

#[tokio::test]
async fn test_psbt_inscription_without_checksig() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        legacy_test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        legacy_test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let token_balance = TokenBalance {
        value: 1000,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let witness_script = test_utils::build_inscription_without_checksig(
        serialized_token_balance.clone(),
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
    )?
    .into_script();

    let attach_tx = legacy_test_utils::build_signed_attach_tx_segwit(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, _sig) = legacy_test_utils::build_seller_psbt_and_sig_segwit(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;
    let mut witness = Witness::new();
    witness.push(witness_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = legacy_test_utils::build_signed_buyer_psbt_segwit(
        &secp,
        &buyer_address,
        &buyer_child_key,
        &attach_tx,
        &buyer_compressed_pubkey,
        &seller_address,
        &seller_psbt,
    )?;

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
    assert_eq!(witness.len(), 1, "Witness should have exactly 1 element");

    // Get the script from the witness
    let script_bytes = witness.to_vec()[0].clone();
    let script = ScriptBuf::from_bytes(script_bytes);

    // Parse the script instructions
    let instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;

    if let [
        Instruction::PushBytes(_key),
        Instruction::PushBytes(op_false),
        Instruction::Op(op_if),
        Instruction::PushBytes(kon),
        Instruction::PushBytes(op_0),
        Instruction::PushBytes(serialized_data),
        Instruction::Op(op_endif),
    ] = instructions.as_slice()
    {
        // Verify the opcodes
        assert!(op_false.is_empty(), "Expected empty push bytes");
        assert_eq!(*op_if, OP_IF, "Expected OP_IF");
        assert_eq!(kon.as_bytes(), b"kon", "Expected kon identifier");
        assert!(op_0.is_empty(), "Expected empty push bytes");
        assert_eq!(*op_endif, OP_ENDIF, "Expected OP_ENDIF");

        // Deserialize the token data
        let token_data: TokenBalance = ciborium::from_reader(serialized_data.as_bytes())?;

        // Verify the token data
        assert_eq!(
            token_data, token_balance,
            "Token data in witness doesn't match expected value"
        );

        let key_from_bytes = CompressedPublicKey::from_slice(_key.as_bytes())?;
        assert_eq!(key_from_bytes, seller_compressed_pubkey);
    } else {
        panic!("Script structure doesn't match expected pattern");
    }

    Ok(())
}

#[tokio::test]
async fn test_psbt_inscription_with_wrong_internal_key_without_checksig() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        legacy_test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        legacy_test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let token_balance = TokenBalance {
        value: 1000,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let witness_script = test_utils::build_inscription_without_checksig(
        serialized_token_balance.clone(),
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
    )?
    .into_script();

    let attach_tx = legacy_test_utils::build_signed_attach_tx_segwit(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, _sig) = legacy_test_utils::build_seller_psbt_and_sig_segwit(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;

    let malformed_witness_script = test_utils::build_inscription_without_checksig(
        serialized_token_balance.clone(),
        test_utils::PublicKey::Segwit(&buyer_compressed_pubkey),
    )?
    .into_script();

    let mut witness = Witness::new();
    witness.push(malformed_witness_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = legacy_test_utils::build_signed_buyer_psbt_segwit(
        &secp,
        &buyer_address,
        &buyer_child_key,
        &attach_tx,
        &buyer_compressed_pubkey,
        &seller_address,
        &seller_psbt,
    )?;

    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = client
        .test_mempool_accept(&[raw_attach_tx_hex, raw_swap_tx_hex])
        .await?;

    // Assert both transactions are allowed
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(!result[1].allowed, "Swap transaction was accepted");
    assert!(
        result[1]
            .reject_reason
            .as_ref()
            .unwrap_or(&String::new())
            .contains("Witness program hash mismatch"),
        "Unexpected reject reason"
    );

    let witness = final_tx.input[0].witness.clone();
    assert_eq!(witness.len(), 1, "Witness should have exactly 1 element");

    // Get the script from the witness
    let script_bytes = witness.to_vec()[0].clone();
    let script = ScriptBuf::from_bytes(script_bytes);

    // Parse the script instructions
    let instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;

    if let [
        Instruction::PushBytes(_key),
        Instruction::PushBytes(op_false),
        Instruction::Op(op_if),
        Instruction::PushBytes(kon),
        Instruction::PushBytes(op_0),
        Instruction::PushBytes(serialized_data),
        Instruction::Op(op_endif),
    ] = instructions.as_slice()
    {
        // Verify the opcodes
        assert!(op_false.is_empty(), "Expected empty push bytes");
        assert_eq!(*op_if, OP_IF, "Expected OP_IF");
        assert_eq!(kon.as_bytes(), b"kon", "Expected kon identifier");
        assert!(op_0.is_empty(), "Expected empty push bytes");
        assert_eq!(*op_endif, OP_ENDIF, "Expected OP_ENDIF");

        // Deserialize the token data
        let token_data: TokenBalance = ciborium::from_reader(serialized_data.as_bytes())?;

        // Verify the token data
        assert_eq!(
            token_data, token_balance,
            "Token data in witness doesn't match expected value"
        );

        let key_from_bytes = CompressedPublicKey::from_slice(_key.as_bytes())?;
        assert_eq!(key_from_bytes, buyer_compressed_pubkey);
    } else {
        panic!("Script structure doesn't match expected pattern");
    }

    Ok(())
}
