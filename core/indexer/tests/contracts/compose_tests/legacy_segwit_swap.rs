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

use indexer::legacy_test_utils::{self, LegacyOpReturnData};
use indexer::witness_data::TokenBalance;
use indexer_types::{deserialize, serialize};
use std::collections::HashMap;
use testlib::RegTester;
use tracing::info;

pub async fn test_legacy_segwit_swap_psbt_with_secret(reg_tester: &mut RegTester) -> Result<()> {
    info!("test_legacy_segwit_swap_psbt_with_secret");
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

    let witness_script = legacy_test_utils::build_witness_script(
        legacy_test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
        &serialized_token_balance,
    );

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
    witness.push(&serialized_token_balance);
    witness.push(b"kon");
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
    let attach_op_return_data: LegacyOpReturnData = deserialize(data.as_bytes())?;
    assert_eq!(
        attach_op_return_data,
        LegacyOpReturnData::A { output_index: 0 }
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
    assert_eq!(prefix.as_bytes(), b"kon");
    let swap_op_return_data: LegacyOpReturnData = deserialize(data.as_bytes())?;
    assert_eq!(
        swap_op_return_data,
        LegacyOpReturnData::S {
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

pub async fn test_legacy_segwit_swap_psbt_with_incorrect_prefix(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_legacy_segwit_swap_psbt_with_incorrect_prefix");
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

    let witness_script = legacy_test_utils::build_witness_script(
        legacy_test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
        &serialized_token_balance,
    );

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
    witness.push(&serialized_token_balance);
    witness.push(b"KNR");
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

    // Assert attach transaction is allowed but swap is rejected
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(
        !result[1].allowed,
        "Swap transaction was unexpectedly accepted"
    );
    assert_eq!(
        result[1].reject_reason.as_ref().unwrap(),
        "mempool-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)"
    );

    Ok(())
}

pub async fn test_legacy_segwit_swap_psbt_without_secret(reg_tester: &mut RegTester) -> Result<()> {
    info!("test_legacy_segwit_swap_psbt_without_secret");
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

    let witness_script = legacy_test_utils::build_witness_script(
        legacy_test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
        &serialized_token_balance,
    );

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
    witness.push(&serialized_token_balance);
    witness.push(b"kon");
    witness.push(seller_address.script_pubkey().as_bytes());
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
    assert!(
        !result[1].allowed,
        "Swap transaction was unexpectedly accepted"
    );
    assert_eq!(
        result[1].reject_reason.as_ref().unwrap(),
        "mempool-script-verify-flag-failed (Witness program hash mismatch)"
    );

    Ok(())
}

pub async fn test_legacy_segwit_swap_psbt_without_token_balance(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_legacy_segwit_swap_psbt_without_token_balance");
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

    let witness_script = legacy_test_utils::build_witness_script(
        legacy_test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
        &serialized_token_balance,
    );
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
    witness.push(b"kon");
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
    assert!(
        !result[1].allowed,
        "Swap transaction was unexpectedly accepted"
    );
    assert_eq!(
        result[1].reject_reason.as_ref().unwrap(),
        "mempool-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)"
    );

    Ok(())
}

pub async fn test_legacy_segwit_swap_psbt_without_prefix(reg_tester: &mut RegTester) -> Result<()> {
    info!("test_legacy_segwit_swap_psbt_without_prefix");
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

    let witness_script = legacy_test_utils::build_witness_script(
        legacy_test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
        &serialized_token_balance,
    );

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
    witness.push(&serialized_token_balance);
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
    assert!(
        !result[1].allowed,
        "Swap transaction was unexpectedly accepted"
    );
    assert_eq!(
        result[1].reject_reason.as_ref().unwrap(),
        "mempool-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)"
    );

    Ok(())
}

pub async fn test_legacy_segwit_swap_psbt_with_malformed_witness_script(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_legacy_segwit_swap_psbt_with_malformed_witness_script");
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

    let witness_script = legacy_test_utils::build_witness_script(
        legacy_test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
        &serialized_token_balance,
    );

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
    assert!(
        !result[1].allowed,
        "Swap transaction was unexpectedly accepted"
    );
    assert_eq!(
        result[1].reject_reason.as_ref().unwrap(),
        "mempool-script-verify-flag-failed (Witness program hash mismatch)"
    );

    Ok(())
}

pub async fn test_legacy_segwit_swap_psbt_with_wrong_token_name(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_legacy_segwit_swap_psbt_with_wrong_token_name");
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

    let witness_script = legacy_test_utils::build_witness_script(
        legacy_test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
        &serialized_token_balance,
    );

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
    let serialized_token_balance = serialize(&TokenBalance {
        value: 1000,
        name: "wrong_token_name".to_string(),
    })?;
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"kon");
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
    assert!(
        !result[1].allowed,
        "Swap transaction was unexpectedly accepted"
    );
    assert_eq!(
        result[1].reject_reason.as_ref().unwrap(),
        "mempool-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)"
    );

    Ok(())
}

pub async fn test_legacy_segwit_swap_psbt_with_insufficient_funds(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_legacy_segwit_swap_psbt_with_insufficient_funds");
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

    let witness_script = legacy_test_utils::build_witness_script(
        legacy_test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
        &serialized_token_balance,
    );

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
    let serialized_token_balance = serialize(&TokenBalance {
        value: 900,
        name: "token_name".to_string(),
    })?;
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"kon");
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
    assert!(
        !result[1].allowed,
        "Swap transaction was unexpectedly accepted"
    );
    assert_eq!(
        result[1].reject_reason.as_ref().unwrap(),
        "mempool-script-verify-flag-failed (Script failed an OP_EQUALVERIFY operation)"
    );

    Ok(())
}

pub async fn test_legacy_segwit_swap_psbt_with_long_witness_stack(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_legacy_segwit_swap_psbt_with_long_witness_stack");
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

    let token_balances = legacy_test_utils::build_long_token_balance();

    let serialized_token_balance = serialize(&token_balances)?;

    let witness_script = legacy_test_utils::build_witness_script(
        legacy_test_utils::PublicKey::Segwit(&seller_compressed_pubkey),
        &serialized_token_balance,
    );

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
    witness.push(&serialized_token_balance);
    witness.push(b"kon");
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

    let token_balance_decoded: HashMap<String, i32> = deserialize(token_balance).unwrap();
    assert_eq!(
        token_balance_decoded, token_balances,
        "Token balance in witness doesn't match expected value"
    );

    Ok(())
}
