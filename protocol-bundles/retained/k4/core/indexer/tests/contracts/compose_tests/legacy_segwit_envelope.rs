use anyhow::Result;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF};
use bitcoin::script::Instruction;
use bitcoin::{CompressedPublicKey, ScriptBuf};
use bitcoin::{Witness, consensus::encode::serialize as serialize_tx, key::Secp256k1};

use indexer::witness_data::TokenBalance;
use indexer::{legacy_test_utils, test_utils};
use indexer_types::{deserialize, serialize};
use testlib::RegTester;
use tracing::info;

pub async fn test_legacy_segwit_envelope_psbt_inscription(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_legacy_segwit_envelope_psbt_inscription");
    let seller_identity = reg_tester.identity_p2wpkh().await?;
    let seller_address = seller_identity.address;
    let seller_private_key = seller_identity.private_key;
    let seller_compressed_pubkey = seller_identity.compressed_public_key;
    let seller_out_point = seller_identity.next_funding_utxo.0;
    let seller_utxo_for_output = seller_identity.next_funding_utxo.1;

    let buyer_identity = reg_tester.identity_p2wpkh().await?;
    let buyer_address = buyer_identity.address;
    let buyer_private_key = buyer_identity.private_key;
    let buyer_compressed_pubkey = buyer_identity.compressed_public_key;
    let buyer_out_point = buyer_identity.next_funding_utxo.0;
    let buyer_utxo_for_output = buyer_identity.next_funding_utxo.1;

    let secp = Secp256k1::new();

    let token_balance = TokenBalance {
        value: 1000,
        name: "token_name".to_string(),
    };

    let serialized_token_balance = serialize(&token_balance)?;

    let witness_script = test_utils::build_inscription(
        serialized_token_balance.clone(),
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
    )?;

    let attach_tx = legacy_test_utils::build_signed_attach_tx_segwit(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_private_key.inner,
        &witness_script,
        seller_out_point,
        &seller_utxo_for_output,
    )?;

    let (mut seller_psbt, sig) = legacy_test_utils::build_seller_psbt_and_sig_segwit(
        &secp,
        &seller_address,
        &seller_private_key.inner,
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
        &buyer_private_key.inner,
        &attach_tx,
        &buyer_compressed_pubkey,
        &seller_address,
        &seller_psbt,
        buyer_out_point,
        buyer_utxo_for_output,
    )?;

    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = reg_tester
        .mempool_accept_result(&[raw_attach_tx_hex, raw_swap_tx_hex])
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
        let token_data: TokenBalance = deserialize(serialized_data.as_bytes())?;

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

pub async fn test_legacy_segwit_psbt_inscription_invalid_token_data(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_legacy_segwit_psbt_inscription_invalid_token_data");
    let seller_identity = reg_tester.identity_p2wpkh().await?;
    let seller_address = seller_identity.address;
    let seller_private_key = seller_identity.private_key;
    let seller_compressed_pubkey = seller_identity.compressed_public_key;
    let seller_out_point = seller_identity.next_funding_utxo.0;
    let seller_utxo_for_output = seller_identity.next_funding_utxo.1;

    let buyer_identity = reg_tester.identity_p2wpkh().await?;
    let buyer_address = buyer_identity.address;
    let buyer_private_key = buyer_identity.private_key;
    let buyer_compressed_pubkey = buyer_identity.compressed_public_key;
    let buyer_out_point = buyer_identity.next_funding_utxo.0;
    let buyer_utxo_for_output = buyer_identity.next_funding_utxo.1;

    let secp = Secp256k1::new();

    let token_balance = TokenBalance {
        value: 1000,
        name: "token_name".to_string(),
    };

    let serialized_token_balance = serialize(&token_balance)?;

    let witness_script = test_utils::build_inscription(
        serialized_token_balance.clone(),
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
    )?;

    let attach_tx = legacy_test_utils::build_signed_attach_tx_segwit(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_private_key.inner,
        &witness_script,
        seller_out_point,
        &seller_utxo_for_output,
    )?;

    let (mut seller_psbt, sig) = legacy_test_utils::build_seller_psbt_and_sig_segwit(
        &secp,
        &seller_address,
        &seller_private_key.inner,
        &attach_tx,
        &witness_script,
    )?;

    let malformed_token_balance = TokenBalance {
        value: 1000,
        name: "wrong_token_name".to_string(),
    };

    let serialized_malformed_token_balance = serialize(&malformed_token_balance)?;

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
        &buyer_private_key.inner,
        &attach_tx,
        &buyer_compressed_pubkey,
        &seller_address,
        &seller_psbt,
        buyer_out_point,
        buyer_utxo_for_output,
    )?;

    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = reg_tester
        .mempool_accept_result(&[raw_attach_tx_hex, raw_swap_tx_hex])
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
        let token_data: TokenBalance = deserialize(serialized_data.as_bytes())?;

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

pub async fn test_legacy_segwit_psbt_inscription_wrong_internal_key(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_legacy_segwit_psbt_inscription_wrong_internal_key");
    let seller_identity = reg_tester.identity_p2wpkh().await?;
    let seller_address = seller_identity.address;
    let seller_private_key = seller_identity.private_key;
    let seller_compressed_pubkey = seller_identity.compressed_public_key;
    let seller_out_point = seller_identity.next_funding_utxo.0;
    let seller_utxo_for_output = seller_identity.next_funding_utxo.1;

    let buyer_identity = reg_tester.identity_p2wpkh().await?;
    let buyer_address = buyer_identity.address;
    let buyer_private_key = buyer_identity.private_key;
    let buyer_compressed_pubkey = buyer_identity.compressed_public_key;
    let buyer_out_point = buyer_identity.next_funding_utxo.0;
    let buyer_utxo_for_output = buyer_identity.next_funding_utxo.1;

    let secp = Secp256k1::new();

    let token_balance = TokenBalance {
        value: 1000,
        name: "token_name".to_string(),
    };

    let serialized_token_balance = serialize(&token_balance)?;

    let witness_script = test_utils::build_inscription(
        serialized_token_balance.clone(),
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
    )?;

    let attach_tx = legacy_test_utils::build_signed_attach_tx_segwit(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_private_key.inner,
        &witness_script,
        seller_out_point,
        &seller_utxo_for_output,
    )?;

    let (mut seller_psbt, sig) = legacy_test_utils::build_seller_psbt_and_sig_segwit(
        &secp,
        &seller_address,
        &seller_private_key.inner,
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
        &buyer_private_key.inner,
        &attach_tx,
        &buyer_compressed_pubkey,
        &seller_address,
        &seller_psbt,
        buyer_out_point,
        buyer_utxo_for_output,
    )?;

    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = reg_tester
        .mempool_accept_result(&[raw_attach_tx_hex, raw_swap_tx_hex])
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
        let token_data: TokenBalance = deserialize(serialized_data.as_bytes())?;

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

pub async fn test_legacy_segwit_psbt_inscription_without_checksig(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_legacy_segwit_psbt_inscription_without_checksig");
    let seller_identity = reg_tester.identity_p2wpkh().await?;
    let seller_address = seller_identity.address;
    let seller_private_key = seller_identity.private_key;
    let seller_compressed_pubkey = seller_identity.compressed_public_key;
    let seller_out_point = seller_identity.next_funding_utxo.0;
    let seller_utxo_for_output = seller_identity.next_funding_utxo.1;

    let buyer_identity = reg_tester.identity_p2wpkh().await?;
    let buyer_address = buyer_identity.address;
    let buyer_private_key = buyer_identity.private_key;
    let buyer_compressed_pubkey = buyer_identity.compressed_public_key;
    let buyer_out_point = buyer_identity.next_funding_utxo.0;
    let buyer_utxo_for_output = buyer_identity.next_funding_utxo.1;

    let secp = Secp256k1::new();

    let token_balance = TokenBalance {
        value: 1000,
        name: "token_name".to_string(),
    };

    let serialized_token_balance = serialize(&token_balance)?;

    let witness_script = test_utils::build_inscription_without_checksig(
        serialized_token_balance.clone(),
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
    )?
    .into_script();

    let attach_tx = legacy_test_utils::build_signed_attach_tx_segwit(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_private_key.inner,
        &witness_script,
        seller_out_point,
        &seller_utxo_for_output,
    )?;

    let (mut seller_psbt, _sig) = legacy_test_utils::build_seller_psbt_and_sig_segwit(
        &secp,
        &seller_address,
        &seller_private_key.inner,
        &attach_tx,
        &witness_script,
    )?;
    let mut witness = Witness::new();
    witness.push(witness_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = legacy_test_utils::build_signed_buyer_psbt_segwit(
        &secp,
        &buyer_address,
        &buyer_private_key.inner,
        &attach_tx,
        &buyer_compressed_pubkey,
        &seller_address,
        &seller_psbt,
        buyer_out_point,
        buyer_utxo_for_output,
    )?;

    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = reg_tester
        .mempool_accept_result(&[raw_attach_tx_hex, raw_swap_tx_hex])
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
        let token_data: TokenBalance = deserialize(serialized_data.as_bytes())?;

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

pub async fn test_legacy_segwit_psbt_inscription_with_wrong_internal_key_without_checksig(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_legacy_segwit_psbt_inscription_with_wrong_internal_key_without_checksig");
    let seller_identity = reg_tester.identity_p2wpkh().await?;
    let seller_address = seller_identity.address;
    let seller_private_key = seller_identity.private_key;
    let seller_compressed_pubkey = seller_identity.compressed_public_key;
    let seller_out_point = seller_identity.next_funding_utxo.0;
    let seller_utxo_for_output = seller_identity.next_funding_utxo.1;

    let buyer_identity = reg_tester.identity_p2wpkh().await?;
    let buyer_address = buyer_identity.address;
    let buyer_private_key = buyer_identity.private_key;
    let buyer_compressed_pubkey = buyer_identity.compressed_public_key;
    let buyer_out_point = buyer_identity.next_funding_utxo.0;
    let buyer_utxo_for_output = buyer_identity.next_funding_utxo.1;

    let secp = Secp256k1::new();

    let token_balance = TokenBalance {
        value: 1000,
        name: "token_name".to_string(),
    };

    let serialized_token_balance = serialize(&token_balance)?;

    let witness_script = test_utils::build_inscription_without_checksig(
        serialized_token_balance.clone(),
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
    )?
    .into_script();

    let attach_tx = legacy_test_utils::build_signed_attach_tx_segwit(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_private_key.inner,
        &witness_script,
        seller_out_point,
        &seller_utxo_for_output,
    )?;

    let (mut seller_psbt, _sig) = legacy_test_utils::build_seller_psbt_and_sig_segwit(
        &secp,
        &seller_address,
        &seller_private_key.inner,
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
        &buyer_private_key.inner,
        &attach_tx,
        &buyer_compressed_pubkey,
        &seller_address,
        &seller_psbt,
        buyer_out_point,
        buyer_utxo_for_output,
    )?;

    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = reg_tester
        .mempool_accept_result(&[raw_attach_tx_hex, raw_swap_tx_hex])
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
        let token_data: TokenBalance = deserialize(serialized_data.as_bytes())?;

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
