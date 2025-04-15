use anyhow::Result;
use bitcoin::Network;
use bitcoin::bip32::Xpriv;
use bitcoin::ecdsa::Signature;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::{Instruction, PushBytesBuf};
use bitcoin::secp256k1::All;
use bitcoin::sighash::SighashCache;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Txid, Witness,
    absolute::LockTime,
    address::Address,
    consensus::encode::serialize as serialize_tx,
    key::{CompressedPublicKey, Secp256k1},
    opcodes::all::{OP_CHECKSIG, OP_EQUALVERIFY, OP_SHA256},
    psbt::{Input, Output, Psbt, PsbtSighashType},
    script::Builder,
    secp256k1::{self},
    sighash::EcdsaSighashType,
    transaction::{Transaction, TxIn, TxOut, Version},
};
use clap::Parser;
use kontor::{
    bitcoin_client::Client, config::Config, op_return::OpReturnData, witness_data::WitnessData,
};
use std::str::FromStr;
mod utils;

#[tokio::test]
async fn test_psbt_with_secret() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = Config::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let (serialized_token_balance, witness_script) =
        build_serialized_token_and_witness_script(&seller_compressed_pubkey, 1000);
    let attach_tx = build_signed_attach_tx(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = build_seller_psbt_and_sig(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"KNTR");
    witness.push(witness_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = build_signed_buyer_psbt(
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
    assert_eq!(prefix.as_bytes(), b"KNTR");
    assert_eq!(
        data.as_bytes(),
        rmp_serde::to_vec(&OpReturnData::Attach { output_index: 0 }).unwrap()
    );

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
    assert_eq!(prefix.as_bytes(), b"KNTR");
    assert_eq!(
        data.as_bytes(),
        rmp_serde::to_vec(&OpReturnData::Swap {
            destination: buyer_address.script_pubkey().to_hex_string()
        })
        .unwrap()
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
    assert_eq!(prefix, b"KNTR", "Third element should be prefix KNTR");
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
    let config = Config::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let (serialized_token_balance, witness_script) =
        build_serialized_token_and_witness_script(&seller_compressed_pubkey, 1000);

    let attach_tx = build_signed_attach_tx(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = build_seller_psbt_and_sig(
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

    let buyer_psbt = build_signed_buyer_psbt(
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
    assert_eq!(prefix.as_bytes(), b"KNTR");
    assert_eq!(
        data.as_bytes(),
        rmp_serde::to_vec(&OpReturnData::Attach { output_index: 0 }).unwrap()
    );

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
    assert_eq!(prefix.as_bytes(), b"KNTR");
    assert_eq!(
        data.as_bytes(),
        rmp_serde::to_vec(&OpReturnData::Swap {
            destination: buyer_address.script_pubkey().to_hex_string()
        })
        .unwrap()
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
    assert_eq!(
        prefix, b"KNR",
        "Third element should be incorrect prefix KNR"
    );
    assert_eq!(
        final_witness_script,
        witness_script.as_bytes(),
        "Fourth element should be witness script"
    );

    Ok(())
}

#[tokio::test]
async fn test_psbt_without_secret() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = Config::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let (serialized_token_balance, witness_script) =
        build_serialized_token_and_witness_script(&seller_compressed_pubkey, 1000);
    let attach_tx = build_signed_attach_tx(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = build_seller_psbt_and_sig(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"KNTR");
    witness.push(seller_address.script_pubkey().as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = build_signed_buyer_psbt(
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
    assert_eq!(prefix.as_bytes(), b"KNTR");
    assert_eq!(
        data.as_bytes(),
        rmp_serde::to_vec(&OpReturnData::Attach { output_index: 0 }).unwrap()
    );

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
    assert_eq!(prefix.as_bytes(), b"KNTR");
    assert_eq!(
        data.as_bytes(),
        rmp_serde::to_vec(&OpReturnData::Swap {
            destination: buyer_address.script_pubkey().to_hex_string()
        })
        .unwrap()
    );

    // In this test, we're using the seller's address script_pubkey instead of a witness script
    // So we should verify that the witness data contains the seller's address script_pubkey
    let witness = &final_tx.input[0].witness;
    assert_eq!(witness.len(), 4, "Witness data should have 4 elements");
    // The witness should contain:
    // 1. Signature
    // 2. Serialized token balance
    // 3. "KNTR" prefix
    // 4. Seller's address script_pubkey
    assert_eq!(
        witness.nth(0).unwrap(),
        sig.to_vec(),
        "First element should be signature"
    );
    assert_eq!(
        witness.nth(1).unwrap(),
        serialized_token_balance,
        "Second element should be token balance"
    );
    assert_eq!(
        witness.nth(2).unwrap(),
        b"KNTR",
        "Third element should be KNTR prefix"
    );
    assert_eq!(
        witness.nth(3).unwrap(),
        seller_address.script_pubkey().as_bytes(),
        "Fourth element should be seller's address script_pubkey"
    );

    Ok(())
}

#[tokio::test]
async fn test_psbt_without_token_balance() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = Config::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let (_serialized_token_balance, witness_script) =
        build_serialized_token_and_witness_script(&seller_compressed_pubkey, 1000);
    let attach_tx = build_signed_attach_tx(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = build_seller_psbt_and_sig(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(b"KNTR");
    witness.push(witness_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = build_signed_buyer_psbt(
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
    assert_eq!(prefix.as_bytes(), b"KNTR");
    assert_eq!(
        data.as_bytes(),
        rmp_serde::to_vec(&OpReturnData::Attach { output_index: 0 }).unwrap()
    );

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
    assert_eq!(prefix.as_bytes(), b"KNTR");
    assert_eq!(
        data.as_bytes(),
        rmp_serde::to_vec(&OpReturnData::Swap {
            destination: buyer_address.script_pubkey().to_hex_string()
        })
        .unwrap()
    );

    let witness = &final_tx.input[0].witness;
    assert_eq!(witness.len(), 3, "Witness data should have 3 elements");
    // In this test, we're using a witness without the token balance
    // So we should verify that the witness data contains:
    // 1. Signature
    // 2. "KNTR" prefix
    // 3. Witness script
    assert_eq!(
        witness.nth(0).unwrap(),
        sig.to_vec(),
        "First element should be signature"
    );
    assert_eq!(
        witness.nth(1).unwrap(),
        b"KNTR",
        "Second element should be KNTR prefix"
    );
    assert_eq!(
        witness.nth(2).unwrap(),
        witness_script.as_bytes(),
        "Third element should be witness script"
    );

    Ok(())
}

#[tokio::test]
async fn test_psbt_without_prefix() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = Config::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let (serialized_token_balance, witness_script) =
        build_serialized_token_and_witness_script(&seller_compressed_pubkey, 1000);
    let attach_tx = build_signed_attach_tx(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = build_seller_psbt_and_sig(
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

    let buyer_psbt = build_signed_buyer_psbt(
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
    assert_eq!(prefix.as_bytes(), b"KNTR");
    assert_eq!(
        data.as_bytes(),
        rmp_serde::to_vec(&OpReturnData::Attach { output_index: 0 }).unwrap()
    );

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
    assert_eq!(prefix.as_bytes(), b"KNTR");
    assert_eq!(
        data.as_bytes(),
        rmp_serde::to_vec(&OpReturnData::Swap {
            destination: buyer_address.script_pubkey().to_hex_string()
        })
        .unwrap()
    );

    let witness = &final_tx.input[0].witness;
    assert_eq!(witness.len(), 3, "Witness data should have 3 elements");
    // In this test, we're using a witness without the KNTR prefix
    // So we should verify that the witness data contains:
    // 1. Signature
    // 2. Serialized token balance
    // 3. Witness script
    assert_eq!(
        witness.nth(0).unwrap(),
        sig.to_vec(),
        "First element should be signature"
    );
    assert_eq!(
        witness.nth(1).unwrap(),
        serialized_token_balance,
        "Second element should be token balance"
    );
    assert_eq!(
        witness.nth(2).unwrap(),
        witness_script.as_bytes(),
        "Third element should be witness script"
    );

    Ok(())
}

#[tokio::test]
async fn test_psbt_with_malformed_witness_script() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = Config::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let (serialized_token_balance, witness_script) =
        build_serialized_token_and_witness_script(&seller_compressed_pubkey, 1000);
    let attach_tx = build_signed_attach_tx(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = build_seller_psbt_and_sig(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;
    let malformedwitness_script = Builder::new()
        .push_slice(b"KNTR")
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
    witness.push(b"KNTR");
    witness.push(malformedwitness_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = build_signed_buyer_psbt(
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
    assert_eq!(prefix.as_bytes(), b"KNTR");
    assert_eq!(
        data.as_bytes(),
        rmp_serde::to_vec(&OpReturnData::Attach { output_index: 0 }).unwrap()
    );

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
    assert_eq!(prefix.as_bytes(), b"KNTR");
    assert_eq!(
        data.as_bytes(),
        rmp_serde::to_vec(&OpReturnData::Swap {
            destination: buyer_address.script_pubkey().to_hex_string()
        })
        .unwrap()
    );

    let witness = &final_tx.input[0].witness;
    assert_eq!(witness.len(), 4, "Witness data should have 4 elements");
    // In this test, we're using a witness with a malformed secret
    // So we should verify that the witness data contains:
    // 1. Signature
    // 2. Serialized token balance
    // 3. "KNTR" prefix
    // 4. Witness script (with malformed secret hash)
    assert_eq!(
        witness.nth(0).unwrap(),
        sig.to_vec(),
        "First element should be signature"
    );
    assert_eq!(
        witness.nth(1).unwrap(),
        serialized_token_balance,
        "Second element should be token balance"
    );
    assert_eq!(
        witness.nth(2).unwrap(),
        b"KNTR",
        "Third element should be KNTR prefix"
    );

    // Get the witness script from the witness data
    let actual_witness_script = witness.nth(3).unwrap();
    // Create the expected witness script with malformed secret
    let expected_witness_script = Builder::new()
        .push_slice(b"KNTR")
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_SHA256)
        .push_slice(sha256::Hash::hash(b"SECRET").as_byte_array())
        .push_opcode(OP_EQUALVERIFY)
        .push_slice(seller_compressed_pubkey.to_bytes())
        .push_opcode(OP_CHECKSIG)
        .into_script();
    assert_eq!(
        actual_witness_script,
        expected_witness_script.as_bytes(),
        "Fourth element should be witness script with malformed secret"
    );

    Ok(())
}

#[tokio::test]
async fn test_psbt_with_wrong_token_name() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = Config::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let (_serialized_token_balance, witness_script) =
        build_serialized_token_and_witness_script(&seller_compressed_pubkey, 1000);
    let attach_tx = build_signed_attach_tx(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = build_seller_psbt_and_sig(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;
    let serialized_token_balance = rmp_serde::to_vec(&WitnessData::TokenBalance {
        value: 1000,
        name: "wrong_token_name".to_string(),
    })
    .unwrap();
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"KNTR");
    witness.push(witness_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = build_signed_buyer_psbt(
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
    assert_eq!(prefix.as_bytes(), b"KNTR");
    assert_eq!(
        data.as_bytes(),
        rmp_serde::to_vec(&OpReturnData::Attach { output_index: 0 }).unwrap()
    );

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
    assert_eq!(prefix.as_bytes(), b"KNTR");
    assert_eq!(
        data.as_bytes(),
        rmp_serde::to_vec(&OpReturnData::Swap {
            destination: buyer_address.script_pubkey().to_hex_string()
        })
        .unwrap()
    );

    let witness = &final_tx.input[0].witness;
    assert_eq!(witness.len(), 4, "Witness data should have 4 elements");
    // In this test, we're using a witness with a malformed token name
    // So we should verify that the witness data contains:
    // 1. Signature
    // 2. Serialized token balance with wrong token name
    // 3. "KNTR" prefix
    // 4. Witness script
    assert_eq!(
        witness.nth(0).unwrap(),
        sig.to_vec(),
        "First element should be signature"
    );

    // Create the expected malformed token balance
    let expected_token_balance = rmp_serde::to_vec(&WitnessData::TokenBalance {
        value: 1000,
        name: "wrong_token_name".to_string(),
    })
    .unwrap();
    assert_eq!(
        witness.nth(1).unwrap(),
        expected_token_balance,
        "Second element should be token balance with wrong token name"
    );
    assert_eq!(
        witness.nth(2).unwrap(),
        b"KNTR",
        "Third element should be KNTR prefix"
    );
    assert_eq!(
        witness.nth(3).unwrap(),
        witness_script.as_bytes(),
        "Fourth element should be witness script"
    );

    Ok(())
}

#[tokio::test]
async fn test_psbt_with_insufficient_funds() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = Config::try_parse()?;
    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, seller_compressed_pubkey) =
        utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.seller_key_path)?;

    let (buyer_address, buyer_child_key, buyer_compressed_pubkey) =
        utils::generate_address_from_mnemonic_p2wpkh(&secp, &config.buyer_key_path)?;

    let (_serialized_token_balance, witness_script) =
        build_serialized_token_and_witness_script(&seller_compressed_pubkey, 1000);
    let attach_tx = build_signed_attach_tx(
        &secp,
        &seller_address,
        &seller_compressed_pubkey,
        &seller_child_key,
        &witness_script,
    )?;

    let (mut seller_psbt, sig) = build_seller_psbt_and_sig(
        &secp,
        &seller_address,
        &seller_child_key,
        &attach_tx,
        &witness_script,
    )?;
    let serialized_token_balance = rmp_serde::to_vec(&WitnessData::TokenBalance {
        value: 900,
        name: "token_name".to_string(),
    })
    .unwrap();
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"KNTR");
    witness.push(witness_script.as_bytes());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = build_signed_buyer_psbt(
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
    assert_eq!(prefix.as_bytes(), b"KNTR");
    assert_eq!(
        data.as_bytes(),
        rmp_serde::to_vec(&OpReturnData::Attach { output_index: 0 }).unwrap()
    );

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
    assert_eq!(prefix.as_bytes(), b"KNTR");
    assert_eq!(
        data.as_bytes(),
        rmp_serde::to_vec(&OpReturnData::Swap {
            destination: buyer_address.script_pubkey().to_hex_string()
        })
        .unwrap()
    );

    let witness = &final_tx.input[0].witness;
    assert_eq!(witness.len(), 4, "Witness data should have 4 elements");
    // In this test, we're using a witness with insufficient funds
    // So we should verify that the witness data contains:
    // 1. Signature
    // 2. Serialized token balance with insufficient funds
    // 3. "KNTR" prefix
    // 4. Witness script
    assert_eq!(
        witness.nth(0).unwrap(),
        sig.to_vec(),
        "First element should be signature"
    );

    // Create the expected malformed token balance
    let expected_token_balance = rmp_serde::to_vec(&WitnessData::TokenBalance {
        value: 900,
        name: "token_name".to_string(),
    })
    .unwrap();
    assert_eq!(
        witness.nth(1).unwrap(),
        expected_token_balance,
        "Second element should be token balance with insufficient funds"
    );
    assert_eq!(
        witness.nth(2).unwrap(),
        b"KNTR",
        "Third element should be KNTR prefix"
    );
    assert_eq!(
        witness.nth(3).unwrap(),
        witness_script.as_bytes(),
        "Fourth element should be witness script"
    );

    Ok(())
}

fn build_signed_attach_tx(
    secp: &Secp256k1<All>,
    seller_address: &Address,
    seller_compressed_pubkey: &CompressedPublicKey,
    seller_child_key: &Xpriv,
    witness_script: &ScriptBuf,
) -> Result<Transaction> {
    // Use a known UTXO as input for create_tx
    let input_txid =
        Txid::from_str("ce18ea0cdbd14cb35eccdd0a1d551509d83516c7b3534c83b2a0adb552809caf")?;
    let input_vout = 0;
    let input_amount = Amount::from_sat(10000);

    let script_address: Address = Address::p2wsh(witness_script, Network::Bitcoin);

    let mut op_return_script = ScriptBuf::new();
    op_return_script.push_opcode(OP_RETURN);
    op_return_script.push_slice(b"KNTR");

    let op_return_data = OpReturnData::Attach { output_index: 0 };
    let s = rmp_serde::to_vec(&op_return_data).unwrap();
    op_return_script.push_slice(PushBytesBuf::try_from(s)?);

    // Create first transaction to create our special UTXO
    let mut create_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: input_txid,
                vout: input_vout,
            },
            ..Default::default()
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: script_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(8700),
                script_pubkey: seller_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: op_return_script,
            },
        ],
    };

    // Sign the input as normal P2WPKH
    let mut sighash_cache = SighashCache::new(&create_tx);
    let sighash = sighash_cache
        .p2wpkh_signature_hash(
            0,
            &seller_address.script_pubkey(),
            input_amount,
            EcdsaSighashType::All,
        )
        .expect("Failed to compute sighash");

    let msg = secp256k1::Message::from(sighash);
    let sig = secp.sign_ecdsa(&msg, &seller_child_key.private_key);
    let sig = Signature::sighash_all(sig);

    // Create witness data for P2WPKH
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(seller_compressed_pubkey.to_bytes());
    create_tx.input[0].witness = witness;

    Ok(create_tx)
}

fn build_serialized_token_and_witness_script(
    seller_compressed_pubkey: &CompressedPublicKey,
    token_value: u64,
) -> (Vec<u8>, ScriptBuf) {
    let token_balance = WitnessData::TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let serialized_token_balance = rmp_serde::to_vec(&token_balance).unwrap();
    let witness_script = Builder::new()
        .push_slice(b"KNTR")
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_SHA256)
        .push_slice(sha256::Hash::hash(&serialized_token_balance).as_byte_array())
        .push_opcode(OP_EQUALVERIFY)
        .push_slice(seller_compressed_pubkey.to_bytes())
        .push_opcode(OP_CHECKSIG)
        .into_script();

    (serialized_token_balance, witness_script)
}

fn build_seller_psbt_and_sig(
    secp: &Secp256k1<All>,
    seller_address: &Address,
    seller_child_key: &Xpriv,
    attach_tx: &Transaction,
    witness_script: &ScriptBuf,
) -> Result<(Psbt, Signature)> {
    // Create seller's PSBT
    let seller_psbt = Psbt {
        unsigned_tx: Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: attach_tx.compute_txid(),
                    vout: 0,
                },
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(600),
                script_pubkey: seller_address.script_pubkey(),
            }],
        },
        inputs: vec![Input {
            witness_script: Some(witness_script.clone()),
            witness_utxo: Some(TxOut {
                script_pubkey: attach_tx.output[0].script_pubkey.clone(),
                value: Amount::from_sat(1000), // Use the actual output amount from create_tx
            }),
            sighash_type: Some(PsbtSighashType::from(
                EcdsaSighashType::SinglePlusAnyoneCanPay,
            )),
            ..Default::default()
        }],
        outputs: vec![Output::default()],
        version: 0,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
    };

    // Sign seller's PSBT with the witness script and secret data
    let mut sighash_cache = SighashCache::new(&seller_psbt.unsigned_tx);
    let (msg, sighash_type) = seller_psbt.sighash_ecdsa(0, &mut sighash_cache)?;

    let sig = secp.sign_ecdsa(&msg, &seller_child_key.private_key);
    let sig = Signature {
        signature: sig,
        sighash_type,
    };

    Ok((seller_psbt, sig))
}

fn build_signed_buyer_psbt(
    secp: &Secp256k1<All>,
    buyer_address: &Address,
    buyer_child_key: &Xpriv,
    attach_tx: &Transaction,
    buyer_compressed_pubkey: &CompressedPublicKey,
    seller_address: &Address,
    seller_psbt: &Psbt,
) -> Result<Psbt> {
    let mut buyer_op_return_script = ScriptBuf::new();
    buyer_op_return_script.push_opcode(bitcoin::opcodes::all::OP_RETURN);
    buyer_op_return_script.push_slice(b"KNTR");

    let buyer_op_return_data = OpReturnData::Swap {
        destination: buyer_address.script_pubkey().to_hex_string(),
    };

    let s = rmp_serde::to_vec(&buyer_op_return_data).unwrap();
    buyer_op_return_script.push_slice(PushBytesBuf::try_from(s)?);

    // Create buyer's PSBT
    let mut buyer_psbt = Psbt {
        unsigned_tx: Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![
                // Seller's signed input
                TxIn {
                    previous_output: OutPoint {
                        txid: attach_tx.compute_txid(),
                        vout: 0,
                    },
                    ..Default::default()
                },
                // Buyer's UTXO input
                TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_str(
                            "ca346e6fd745c138eee30f1dbe93ab269231cfb46e5ac945d028cbcc9dd2dea2",
                        )?,
                        vout: 0,
                    },
                    ..Default::default()
                },
            ],
            output: vec![
                // Seller receives payment
                TxOut {
                    value: Amount::from_sat(600),
                    script_pubkey: seller_address.script_pubkey(),
                },
                // Buyer receives the asset
                TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: buyer_op_return_script, // OP_RETURN with data pointing to the attached UTXO
                },
                // Buyer's change
                TxOut {
                    value: Amount::from_sat(9100), // 10000 - 600 - 300 fee
                    script_pubkey: buyer_address.script_pubkey(),
                },
            ],
        },
        inputs: vec![
            // Seller's signed input
            seller_psbt.inputs[0].clone(),
            // Buyer's UTXO input
            Input {
                witness_utxo: Some(TxOut {
                    script_pubkey: buyer_address.script_pubkey(),
                    value: Amount::from_sat(10000),
                }),
                sighash_type: Some(PsbtSighashType::from(EcdsaSighashType::All)),
                ..Default::default()
            },
        ],
        outputs: vec![Output::default(), Output::default(), Output::default()],
        version: 0,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
    };

    // Sign buyer's input
    let mut sighash_cache = SighashCache::new(&buyer_psbt.unsigned_tx);
    let (msg, sighash_type) = buyer_psbt.sighash_ecdsa(1, &mut sighash_cache)?;

    let sig = secp.sign_ecdsa(&msg, &buyer_child_key.private_key);
    let sig = Signature {
        signature: sig,
        sighash_type,
    };

    // Create witness data for buyer's input
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(buyer_compressed_pubkey.to_bytes());
    buyer_psbt.inputs[1].final_script_witness = Some(witness);

    Ok(buyer_psbt)
}
