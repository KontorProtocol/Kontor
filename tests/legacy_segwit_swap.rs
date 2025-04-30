use anyhow::Result;

use bitcoin::hashes::{Hash, sha256};
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::Instruction;
use bitcoin::{
    Witness,
    consensus::encode::serialize as serialize_tx,
    key::Secp256k1,
    opcodes::all::{OP_CHECKSIG, OP_EQUALVERIFY, OP_SHA256},
    script::Builder,
};
use clap::Parser;
use kontor::config::TestConfig;
use kontor::test_utils;
use kontor::witness_data::TokenBalance;
use kontor::{bitcoin_client::Client, config::Config, op_return::OpReturnData};
use std::collections::HashMap;

#[tokio::test]
async fn test_psbt_with_secret() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let token_balance = TokenBalance {
        value: 1000,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let witness_script = test_utils::build_witness_script(
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
        &serialized_token_balance,
    );

    let attach_tx = test_utils::build_signed_attach_tx_segwit(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = test_utils::build_seller_psbt_and_sig_segwit(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"kon");
    witness.push(witness_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = test_utils::build_signed_buyer_psbt_segwit(
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

    // Assert deserialize attached op_return data
    let attach_op_return_script = &attach_tx.output[2].script_pubkey; // OP_RETURN is the third output

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
            destination: buyer_address.script_pubkey().as_bytes().to_vec()
        }
    );

    // Assert deserialize swap witness script
    let swap_witness_data = &final_tx.input[0].witness;
    assert_eq!(
        swap_witness_data.len(),
        4,
        "Swap witness data should have 4 elements"
    );

    let signature = swap_witness_data.nth(0).unwrap();
    let token_balance = swap_witness_data.nth(1).unwrap();
    let prefix = swap_witness_data.nth(2).unwrap();
    let final_witness_script = swap_witness_data.nth(3).unwrap();

    assert_eq!(signature, sig.to_vec(), "First element should be signature");
    assert_eq!(
        token_balance, serialized_token_balance,
        "Second element should be token balance"
    );
    assert_eq!(prefix, b"kon", "Third element should be prefix kon");
    assert_eq!(
        final_witness_script,
        witness_script.as_bytes(),
        "Fourth element should be witness script"
    );

    Ok(())
}

#[tokio::test]
async fn test_psbt_with_incorrect_prefix() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let token_balance = TokenBalance {
        value: 1000,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let witness_script = test_utils::build_witness_script(
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
        &serialized_token_balance,
    );

    let attach_tx = test_utils::build_signed_attach_tx_segwit(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = test_utils::build_seller_psbt_and_sig_segwit(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;

    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"KNR");
    witness.push(witness_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = test_utils::build_signed_buyer_psbt_segwit(
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

    // Assert attach transaction is allowed but swap is rejected
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(
        !result[1].allowed,
        "Swap transaction was unexpectedly accepted"
    );
    assert_eq!(
        result[1].reject_reason.as_ref().unwrap(),
        "mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)"
    );

    Ok(())
}

#[tokio::test]
async fn test_psbt_without_secret() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let token_balance = TokenBalance {
        value: 1000,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let witness_script = test_utils::build_witness_script(
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
        &serialized_token_balance,
    );

    let attach_tx = test_utils::build_signed_attach_tx_segwit(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = test_utils::build_seller_psbt_and_sig_segwit(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"kon");
    witness.push(seller_address.script_pubkey().as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = test_utils::build_signed_buyer_psbt_segwit(
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
    assert!(
        !result[1].allowed,
        "Swap transaction was unexpectedly accepted"
    );
    assert_eq!(
        result[1].reject_reason.as_ref().unwrap(),
        "mandatory-script-verify-flag-failed (Witness program hash mismatch)"
    );

    Ok(())
}

#[tokio::test]
async fn test_psbt_without_token_balance() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let token_balance = TokenBalance {
        value: 1000,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let witness_script = test_utils::build_witness_script(
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
        &serialized_token_balance,
    );
    let attach_tx = test_utils::build_signed_attach_tx_segwit(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = test_utils::build_seller_psbt_and_sig_segwit(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(b"kon");
    witness.push(witness_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = test_utils::build_signed_buyer_psbt_segwit(
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
    assert!(
        !result[1].allowed,
        "Swap transaction was unexpectedly accepted"
    );
    assert_eq!(
        result[1].reject_reason.as_ref().unwrap(),
        "mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)"
    );

    Ok(())
}

#[tokio::test]
async fn test_psbt_without_prefix() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let token_balance = TokenBalance {
        value: 1000,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let witness_script = test_utils::build_witness_script(
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
        &serialized_token_balance,
    );

    let attach_tx = test_utils::build_signed_attach_tx_segwit(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = test_utils::build_seller_psbt_and_sig_segwit(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(witness_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = test_utils::build_signed_buyer_psbt_segwit(
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
    assert!(
        !result[1].allowed,
        "Swap transaction was unexpectedly accepted"
    );
    assert_eq!(
        result[1].reject_reason.as_ref().unwrap(),
        "mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)"
    );

    Ok(())
}

#[tokio::test]
async fn test_psbt_with_malformed_witness_script() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let token_balance = TokenBalance {
        value: 1000,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let witness_script = test_utils::build_witness_script(
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
        &serialized_token_balance,
    );

    let attach_tx = test_utils::build_signed_attach_tx_segwit(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = test_utils::build_seller_psbt_and_sig_segwit(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;
    let malformedwitness_script = Builder::new()
        .push_slice(b"kon")
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_SHA256)
        .push_slice(sha256::Hash::hash(b"SECRET").as_byte_array())
        .push_opcode(OP_EQUALVERIFY)
        .push_slice(seller_compressed_pubkey.to_bytes())
        .push_opcode(OP_CHECKSIG)
        .into_script();

    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"kon");
    witness.push(malformedwitness_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = test_utils::build_signed_buyer_psbt_segwit(
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
    assert!(
        !result[1].allowed,
        "Swap transaction was unexpectedly accepted"
    );
    assert_eq!(
        result[1].reject_reason.as_ref().unwrap(),
        "mandatory-script-verify-flag-failed (Witness program hash mismatch)"
    );

    Ok(())
}

#[tokio::test]
async fn test_psbt_with_wrong_token_name() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let token_balance = TokenBalance {
        value: 1000,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let witness_script = test_utils::build_witness_script(
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
        &serialized_token_balance,
    );

    let attach_tx = test_utils::build_signed_attach_tx_segwit(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = test_utils::build_seller_psbt_and_sig_segwit(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;
    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(
        &TokenBalance {
            value: 1000,
            name: "wrong_token_name".to_string(),
        },
        &mut serialized_token_balance,
    )
    .unwrap();
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"kon");
    witness.push(witness_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = test_utils::build_signed_buyer_psbt_segwit(
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
    assert!(
        !result[1].allowed,
        "Swap transaction was unexpectedly accepted"
    );
    assert_eq!(
        result[1].reject_reason.as_ref().unwrap(),
        "mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)"
    );

    Ok(())
}

#[tokio::test]
async fn test_psbt_with_insufficient_funds() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let token_balance = TokenBalance {
        value: 1000,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let witness_script = test_utils::build_witness_script(
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
        &serialized_token_balance,
    );

    let attach_tx = test_utils::build_signed_attach_tx_segwit(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = test_utils::build_seller_psbt_and_sig_segwit(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;
    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(
        &TokenBalance {
            value: 900,
            name: "token_name".to_string(),
        },
        &mut serialized_token_balance,
    )
    .unwrap();
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"kon");
    witness.push(witness_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = test_utils::build_signed_buyer_psbt_segwit(
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
    assert!(
        !result[1].allowed,
        "Swap transaction was unexpectedly accepted"
    );
    assert_eq!(
        result[1].reject_reason.as_ref().unwrap(),
        "mandatory-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)"
    );

    Ok(())
}

#[tokio::test]
async fn test_psbt_with_long_witness_stack() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        test_utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let token_balances = test_utils::build_long_token_balance();

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balances, &mut serialized_token_balance).unwrap();

    let witness_script = test_utils::build_witness_script(
        test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
        &serialized_token_balance,
    );

    let attach_tx = test_utils::build_signed_attach_tx_segwit(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = test_utils::build_seller_psbt_and_sig_segwit(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"kon");
    witness.push(witness_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = test_utils::build_signed_buyer_psbt_segwit(
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
    assert!(
        !result[1].allowed,
        "Swap transaction was unexpectedly accepted"
    );
    assert!(
        result[1]
            .reject_reason
            .as_ref()
            .unwrap()
            .contains("bad-witness-nonstandard")
    );

    // Assert deserialize swap witness script
    let swap_witness_data = &final_tx.input[0].witness;
    assert_eq!(
        swap_witness_data.len(),
        4,
        "Swap witness data should have 4 elements"
    );

    let signature = swap_witness_data.nth(0).unwrap();
    let token_balance = swap_witness_data.nth(1).unwrap();
    let prefix = swap_witness_data.nth(2).unwrap();
    let final_witness_script = swap_witness_data.nth(3).unwrap();

    assert_eq!(signature, sig.to_vec(), "First element should be signature");
    assert_eq!(
        token_balance, serialized_token_balance,
        "Second element should be token balance"
    );
    assert_eq!(prefix, b"kon", "Third element should be prefix kon");
    assert_eq!(
        final_witness_script,
        witness_script.as_bytes(),
        "Fourth element should be witness script"
    );

    let token_balance_decoded: HashMap<String, i32> = ciborium::from_reader(token_balance).unwrap();
    assert_eq!(
        token_balance_decoded, token_balances,
        "Token balance in witness doesn't match expected value"
    );

    Ok(())
}
