use anyhow::Result;
use bitcoin::XOnlyPublicKey;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::opcodes::all::OP_ENDIF;
use bitcoin::opcodes::all::OP_IF;
use bitcoin::script::Instruction;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{
    ScriptBuf, Witness,
    address::{Address, KnownHrp},
    consensus::encode::serialize as serialize_tx,
    key::Secp256k1,
};

use indexer::legacy_test_utils;
use indexer::test_utils;
use indexer::witness_data::TokenBalance;
use testlib::RegTester;
use tracing::info;

pub async fn test_legacy_taproot_envelope_psbt_inscription(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_legacy_taproot_envelope_psbt_inscription");
    let seller_identity = reg_tester.identity().await?;
    let seller_address = seller_identity.address;
    let seller_keypair = seller_identity.keypair;
    let (seller_internal_key, _parity) = seller_keypair.x_only_public_key();
    let (seller_out_point, seller_utxo_for_output) = seller_identity.next_funding_utxo;

    let buyer_identity = reg_tester.identity().await?;
    let buyer_address = buyer_identity.address;
    let buyer_keypair = buyer_identity.keypair;
    let (buyer_internal_key, _parity) = buyer_keypair.x_only_public_key();
    let (buyer_out_point, buyer_utxo_for_output) = buyer_identity.next_funding_utxo;

    let secp = Secp256k1::new();

    let token_value = 1000;
    let token_balance = TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let tap_script = test_utils::build_inscription(
        serialized_token_balance,
        test_utils::PublicKey::Taproot(&seller_internal_key),
    )?;

    // Build the Taproot tree with the script
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, seller_internal_key)
        .expect("Failed to finalize Taproot tree");

    // Get the output key which commits to both the internal key and the script tree
    let output_key = taproot_spend_info.output_key();

    // Create the address from the output key
    let script_spendable_address = Address::p2tr_tweaked(output_key, KnownHrp::Mainnet);

    let attach_tx = legacy_test_utils::build_signed_taproot_attach_tx(
        &secp,
        &seller_keypair,
        &seller_address,
        &script_spendable_address,
        seller_out_point,
        seller_utxo_for_output.clone(),
    )?;

    let (mut seller_psbt, signature, control_block) =
        legacy_test_utils::build_seller_psbt_and_sig_taproot(
            &secp,
            &seller_keypair,
            &seller_address,
            &attach_tx,
            &seller_internal_key,
            &taproot_spend_info,
            &tap_script,
        )?;

    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(tap_script.as_bytes());
    witness.push(control_block.serialize()); // Control block
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = legacy_test_utils::build_signed_buyer_psbt_taproot(
        &secp,
        &buyer_keypair,
        buyer_internal_key,
        &buyer_address,
        buyer_out_point,
        buyer_utxo_for_output,
        &seller_address,
        &attach_tx,
        &script_spendable_address,
        &seller_psbt,
    )?;

    // Extract the transaction (no finalize needed since we set all witnesses manually)
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

    // After your assertions on witness length
    let witness = final_tx.input[0].witness.clone();
    assert_eq!(witness.len(), 3, "Witness should have exactly 3 elements");

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

        let key_from_bytes = XOnlyPublicKey::from_slice(_key.as_bytes())?;
        assert_eq!(key_from_bytes, seller_internal_key);
    } else {
        panic!(
            "Script structure doesn't match expected pattern: {:#?}",
            instructions
        );
    }

    Ok(())
}

pub async fn test_legacy_tapscript_inscription_invalid_token_data(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_legacy_tapscript_inscription_invalid_token_data");
    let seller_identity = reg_tester.identity().await?;
    let seller_address = seller_identity.address;
    let seller_keypair = seller_identity.keypair;
    let (seller_internal_key, _parity) = seller_keypair.x_only_public_key();
    let (seller_out_point, seller_utxo_for_output) = seller_identity.next_funding_utxo;

    let buyer_identity = reg_tester.identity().await?;
    let buyer_address = buyer_identity.address;
    let buyer_keypair = buyer_identity.keypair;
    let (buyer_internal_key, _parity) = buyer_keypair.x_only_public_key();
    let (buyer_out_point, buyer_utxo_for_output) = buyer_identity.next_funding_utxo;

    let secp = Secp256k1::new();

    let token_value = 1000;
    let token_balance = TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let tap_script = test_utils::build_inscription(
        serialized_token_balance,
        test_utils::PublicKey::Taproot(&seller_internal_key),
    )?;

    // Build the Taproot tree with the script
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, seller_internal_key)
        .expect("Failed to finalize Taproot tree");

    // Get the output key which commits to both the internal key and the script tree
    let output_key = taproot_spend_info.output_key();

    // Create the address from the output key
    let script_spendable_address = Address::p2tr_tweaked(output_key, KnownHrp::Mainnet);

    let attach_tx = legacy_test_utils::build_signed_taproot_attach_tx(
        &secp,
        &seller_keypair,
        &seller_address,
        &script_spendable_address,
        seller_out_point,
        seller_utxo_for_output.clone(),
    )?;

    let (mut seller_psbt, signature, control_block) =
        legacy_test_utils::build_seller_psbt_and_sig_taproot(
            &secp,
            &seller_keypair,
            &seller_address,
            &attach_tx,
            &seller_internal_key,
            &taproot_spend_info,
            &tap_script,
        )?;

    let malformed_token_balance = TokenBalance {
        value: token_value,
        name: "wrong_token_name".to_string(),
    };

    let mut serialized_malformed_token_balance = Vec::new();
    ciborium::into_writer(
        &malformed_token_balance,
        &mut serialized_malformed_token_balance,
    )
    .unwrap();

    let malformed_tap_script = test_utils::build_inscription(
        serialized_malformed_token_balance,
        test_utils::PublicKey::Taproot(&seller_internal_key),
    )?;

    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(malformed_tap_script.as_bytes());
    witness.push(control_block.serialize());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = legacy_test_utils::build_signed_buyer_psbt_taproot(
        &secp,
        &buyer_keypair,
        buyer_internal_key,
        &buyer_address,
        buyer_out_point,
        buyer_utxo_for_output,
        &seller_address,
        &attach_tx,
        &script_spendable_address,
        &seller_psbt,
    )?;

    // Extract the transaction (no finalize needed since we set all witnesses manually)
    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = reg_tester
        .mempool_accept_result(&[raw_attach_tx_hex, raw_swap_tx_hex])
        .await?;

    // Assert both transactions are allowed
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(
        !result[1].allowed,
        "Swap transaction was unexpectedly accepted"
    );
    assert!(
        result[1]
            .reject_reason
            .as_ref()
            .unwrap_or(&String::new())
            .contains("Witness program hash mismatch"),
        "Unexpected reject reason"
    );

    // After your assertions on witness length
    let witness = final_tx.input[0].witness.clone();
    assert_eq!(witness.len(), 3, "Witness should have exactly 3 elements");

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

        let key_from_bytes = XOnlyPublicKey::from_slice(_key.as_bytes())?;
        assert_eq!(key_from_bytes, seller_internal_key);
    } else {
        panic!("Script structure doesn't match expected pattern");
    }

    Ok(())
}

pub async fn test_legacy_taproot_inscription_wrong_internal_key(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_legacy_taproot_inscription_wrong_internal_key");
    let seller_identity = reg_tester.identity().await?;
    let seller_address = seller_identity.address;
    let seller_keypair = seller_identity.keypair;
    let (seller_internal_key, _parity) = seller_keypair.x_only_public_key();
    let (seller_out_point, seller_utxo_for_output) = seller_identity.next_funding_utxo;

    let buyer_identity = reg_tester.identity().await?;
    let buyer_address = buyer_identity.address;
    let buyer_keypair = buyer_identity.keypair;
    let (buyer_internal_key, _parity) = buyer_keypair.x_only_public_key();
    let (buyer_out_point, buyer_utxo_for_output) = buyer_identity.next_funding_utxo;

    let token_value = 1000;
    let token_balance = TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let secp = Secp256k1::new();

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let tap_script = test_utils::build_inscription(
        serialized_token_balance.clone(),
        test_utils::PublicKey::Taproot(&seller_internal_key),
    )?;

    // Build the Taproot tree with the script
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, seller_internal_key)
        .expect("Failed to finalize Taproot tree");

    // Get the output key which commits to both the internal key and the script tree
    let output_key = taproot_spend_info.output_key();

    // Create the address from the output key
    let script_spendable_address = Address::p2tr_tweaked(output_key, KnownHrp::Mainnet);

    let attach_tx = legacy_test_utils::build_signed_taproot_attach_tx(
        &secp,
        &seller_keypair,
        &seller_address,
        &script_spendable_address,
        seller_out_point,
        seller_utxo_for_output.clone(),
    )?;

    let (mut seller_psbt, signature, control_block) =
        legacy_test_utils::build_seller_psbt_and_sig_taproot(
            &secp,
            &seller_keypair,
            &seller_address,
            &attach_tx,
            &seller_internal_key,
            &taproot_spend_info,
            &tap_script,
        )?;

    let malformed_tap_script = test_utils::build_inscription(
        serialized_token_balance,
        test_utils::PublicKey::Taproot(&buyer_internal_key),
    )?;

    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(malformed_tap_script.as_bytes());
    witness.push(control_block.serialize());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = legacy_test_utils::build_signed_buyer_psbt_taproot(
        &secp,
        &buyer_keypair,
        buyer_internal_key,
        &buyer_address,
        buyer_out_point,
        buyer_utxo_for_output,
        &seller_address,
        &attach_tx,
        &script_spendable_address,
        &seller_psbt,
    )?;

    // Extract the transaction (no finalize needed since we set all witnesses manually)
    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = reg_tester
        .mempool_accept_result(&[raw_attach_tx_hex, raw_swap_tx_hex])
        .await?;

    // Assert both transactions are allowed
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(
        !result[1].allowed,
        "Swap transaction was unexpectedlyaccepted"
    );
    assert!(
        result[1]
            .reject_reason
            .as_ref()
            .unwrap_or(&String::new())
            .contains("Witness program hash mismatch"),
        "Unexpected reject reason"
    );

    // After your assertions on witness length
    let witness = final_tx.input[0].witness.clone();
    assert_eq!(witness.len(), 3, "Witness should have exactly 3 elements");

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

        let key_from_bytes = XOnlyPublicKey::from_slice(_key.as_bytes())?;
        assert_eq!(key_from_bytes, buyer_internal_key);
    } else {
        panic!("Script structure doesn't match expected pattern");
    }

    Ok(())
}

pub async fn test_legacy_taproot_inscription_without_checksig(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_legacy_taproot_inscription_without_checksig");
    let seller_identity = reg_tester.identity().await?;
    let seller_address = seller_identity.address;
    let seller_keypair = seller_identity.keypair;
    let (seller_internal_key, _parity) = seller_keypair.x_only_public_key();
    let (seller_out_point, seller_utxo_for_output) = seller_identity.next_funding_utxo;

    let buyer_identity = reg_tester.identity().await?;
    let buyer_address = buyer_identity.address;
    let buyer_keypair = buyer_identity.keypair;
    let (buyer_internal_key, _parity) = buyer_keypair.x_only_public_key();
    let (buyer_out_point, buyer_utxo_for_output) = buyer_identity.next_funding_utxo;

    let token_value = 1000;
    let token_balance = TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };
    let secp = Secp256k1::new();

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let tap_script = test_utils::build_inscription_without_checksig(
        serialized_token_balance,
        test_utils::PublicKey::Taproot(&seller_internal_key),
    )?
    .into_script();

    // Build the Taproot tree with the script
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, seller_internal_key)
        .expect("Failed to finalize Taproot tree");

    // Get the output key which commits to both the internal key and the script tree
    let output_key = taproot_spend_info.output_key();

    // Create the address from the output key
    let script_spendable_address = Address::p2tr_tweaked(output_key, KnownHrp::Mainnet);

    let attach_tx = legacy_test_utils::build_signed_taproot_attach_tx(
        &secp,
        &seller_keypair,
        &seller_address,
        &script_spendable_address,
        seller_out_point,
        seller_utxo_for_output.clone(),
    )?;

    let (mut seller_psbt, _signature, control_block) =
        legacy_test_utils::build_seller_psbt_and_sig_taproot(
            &secp,
            &seller_keypair,
            &seller_address,
            &attach_tx,
            &seller_internal_key,
            &taproot_spend_info,
            &tap_script,
        )?;

    // Since checksig is missing in the tapscript, we don't need to require it here. We should not do this in production code
    let mut witness = Witness::new();
    witness.push(tap_script.as_bytes());
    witness.push(control_block.serialize()); // Control block
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = legacy_test_utils::build_signed_buyer_psbt_taproot(
        &secp,
        &buyer_keypair,
        buyer_internal_key,
        &buyer_address,
        buyer_out_point,
        buyer_utxo_for_output,
        &seller_address,
        &attach_tx,
        &script_spendable_address,
        &seller_psbt,
    )?;

    // Extract the transaction (no finalize needed since we set all witnesses manually)
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

    // After your assertions on witness length
    let witness = final_tx.input[0].witness.clone();
    assert_eq!(witness.len(), 2, "Witness should have exactly 2 elements");

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

        let key_from_bytes = XOnlyPublicKey::from_slice(_key.as_bytes())?;
        assert_eq!(key_from_bytes, seller_internal_key);
    } else {
        panic!("Script structure doesn't match expected pattern");
    }

    Ok(())
}

pub async fn test_legacy_taproot_inscription_with_wrong_internal_key_without_checksig(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_legacy_taproot_inscription_with_wrong_internal_key_without_checksig");
    let seller_identity = reg_tester.identity().await?;
    let seller_address = seller_identity.address;
    let seller_keypair = seller_identity.keypair;
    let (seller_internal_key, _parity) = seller_keypair.x_only_public_key();
    let (seller_out_point, seller_utxo_for_output) = seller_identity.next_funding_utxo;

    let buyer_identity = reg_tester.identity().await?;
    let buyer_address = buyer_identity.address;
    let buyer_keypair = buyer_identity.keypair;
    let (buyer_internal_key, _parity) = buyer_keypair.x_only_public_key();
    let (buyer_out_point, buyer_utxo_for_output) = buyer_identity.next_funding_utxo;

    let token_value = 1000;
    let token_balance = TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let tap_script = test_utils::build_inscription_without_checksig(
        serialized_token_balance.clone(),
        test_utils::PublicKey::Taproot(&seller_internal_key),
    )?
    .into_script();

    let secp = Secp256k1::new();

    // Build the Taproot tree with the script
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, seller_internal_key)
        .expect("Failed to finalize Taproot tree");

    // Get the output key which commits to both the internal key and the script tree
    let output_key = taproot_spend_info.output_key();

    // Create the address from the output key
    let script_spendable_address = Address::p2tr_tweaked(output_key, KnownHrp::Mainnet);

    let attach_tx = legacy_test_utils::build_signed_taproot_attach_tx(
        &secp,
        &seller_keypair,
        &seller_address,
        &script_spendable_address,
        seller_out_point,
        seller_utxo_for_output.clone(),
    )?;

    let (mut seller_psbt, _signature, control_block) =
        legacy_test_utils::build_seller_psbt_and_sig_taproot(
            &secp,
            &seller_keypair,
            &seller_address,
            &attach_tx,
            &seller_internal_key,
            &taproot_spend_info,
            &tap_script,
        )?;

    let malformed_tap_script = test_utils::build_inscription_without_checksig(
        serialized_token_balance,
        test_utils::PublicKey::Taproot(&buyer_internal_key),
    )?;

    // Since checksig is missing in the tapscript, we don't need to require it here. We should not do this in production code
    let mut witness = Witness::new();
    witness.push(malformed_tap_script.as_bytes());
    witness.push(control_block.serialize()); // Control block
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = legacy_test_utils::build_signed_buyer_psbt_taproot(
        &secp,
        &buyer_keypair,
        buyer_internal_key,
        &buyer_address,
        buyer_out_point,
        buyer_utxo_for_output,
        &seller_address,
        &attach_tx,
        &script_spendable_address,
        &seller_psbt,
    )?;

    // Extract the transaction (no finalize needed since we set all witnesses manually)
    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = reg_tester
        .mempool_accept_result(&[raw_attach_tx_hex, raw_swap_tx_hex])
        .await?;

    // Assert both transactions are allowed
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(
        !result[1].allowed,
        "Swap transaction was unexpectedly accepted"
    );
    assert!(
        result[1]
            .reject_reason
            .as_ref()
            .unwrap_or(&String::new())
            .contains("Witness program hash mismatch"),
        "Unexpected reject reason"
    );

    // After your assertions on witness length
    let witness = final_tx.input[0].witness.clone();
    assert_eq!(witness.len(), 2, "Witness should have exactly 2 elements");

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

        let key_from_bytes = XOnlyPublicKey::from_slice(_key.as_bytes())?;
        assert_eq!(key_from_bytes, buyer_internal_key);
    } else {
        panic!("Script structure doesn't match expected pattern");
    }

    Ok(())
}
