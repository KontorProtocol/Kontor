use std::str::FromStr;

use anyhow::Result;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::Sequence;
use bitcoin::TapLeafHash;
use bitcoin::TapSighashType;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::XOnlyPublicKey;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::key::rand;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::opcodes::all::OP_ENDIF;
use bitcoin::opcodes::all::OP_IF;
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::Instruction;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::Keypair;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::transaction::Version;
use bitcoin::{
    ScriptBuf, Witness,
    address::{Address, KnownHrp},
    consensus::encode::serialize as serialize_tx,
    key::Secp256k1,
};
use clap::Parser;
use kontor::config::TestConfig;
use kontor::op_return::OpReturnData;
use kontor::test_utils;
use kontor::witness_data::WitnessData;
use kontor::{bitcoin_client::Client, config::Config};

#[tokio::test]
async fn test_commit_reveal_ordinals() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;
    let secp = Secp256k1::new();

    let random_keypair = Keypair::new(&secp, &mut rand::thread_rng());
    let (random_xonly_pubkey, _parity) = random_keypair.x_only_public_key();

    let (sender_address, sender_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 0)?;

    let token_value = 1000;
    let token_balance = WitnessData::TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    // Build the inscription script using the random key
    let reveal_script = test_utils::build_inscription(
        serialized_token_balance,
        test_utils::PublicKey::Taproot(&random_xonly_pubkey),
    )?;

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, reveal_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, random_xonly_pubkey)
        .expect("Failed to finalize Taproot tree");

    let output_key = taproot_spend_info.output_key();

    let commit_address = Address::p2tr_tweaked(output_key, KnownHrp::Mainnet);

    let sender_keypair = Keypair::from_secret_key(&secp, &sender_child_key.private_key);

    let commit_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(
                    "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8",
                )?,
                vout: 0,
            },
            script_sig: ScriptBuf::default(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![
            // Output containing the inscription
            TxOut {
                value: Amount::from_sat(5000),
                script_pubkey: commit_address.script_pubkey(),
            },
            // Change back to sender
            TxOut {
                value: Amount::from_sat(3500), // 9000 - 5000 - 500 fee
                script_pubkey: sender_address.script_pubkey(),
            },
        ],
    };

    // Create the reveal transaction - simple spend back to sender's address
    let reveal_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: commit_tx.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::default(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(4500), // 5000 - 500 fee
                script_pubkey: sender_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: {
                    let mut op_return_script = ScriptBuf::new();
                    op_return_script.push_opcode(OP_RETURN);
                    op_return_script.push_slice(b"KON");

                    let reveal_data = OpReturnData::A { output_index: 0 };
                    let mut reveal_bytes = Vec::new();
                    ciborium::into_writer(&reveal_data, &mut reveal_bytes).unwrap();
                    op_return_script.push_slice(PushBytesBuf::try_from(reveal_bytes)?);

                    op_return_script
                },
            },
        ],
    };

    // Sign the reveal transaction using script path spending
    let control_block = taproot_spend_info
        .control_block(&(reveal_script.clone(), LeafVersion::TapScript))
        .expect("Failed to create control block");

    let mut sighasher = SighashCache::new(&reveal_tx);
    let sighash = sighasher
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[commit_tx.output[0].clone()]),
            TapLeafHash::from_script(&reveal_script, LeafVersion::TapScript),
            TapSighashType::Default,
        )
        .expect("Failed to create sighash");

    // Sign with the random key
    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, &random_keypair);

    let signature = bitcoin::taproot::Signature {
        signature,
        sighash_type: TapSighashType::Default,
    };

    // Create the final reveal transaction with witness
    let mut final_reveal_tx = reveal_tx.clone();
    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(reveal_script.as_bytes());
    witness.push(control_block.serialize());
    final_reveal_tx.input[0].witness = witness;

    // Then, sign the commit transaction
    let sighash_type = TapSighashType::Default;
    let prevouts = vec![TxOut {
        value: Amount::from_sat(9000), // seller's utxo value
        script_pubkey: sender_address.script_pubkey(),
    }];

    let mut sighasher = SighashCache::new(&commit_tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(0, &Prevouts::All(&prevouts), sighash_type)
        .expect("Failed to construct sighash");

    // Sign with sender's key
    let tweaked_sender = sender_keypair.tap_tweak(&secp, None);
    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, &tweaked_sender.to_inner());

    let mut final_commit_tx = commit_tx.clone();
    let signature = bitcoin::taproot::Signature {
        signature,
        sighash_type,
    };
    final_commit_tx.input[0].witness.push(signature.to_vec());

    let raw_commit_tx_hex = hex::encode(serialize_tx(&final_commit_tx));
    let raw_reveal_tx_hex = hex::encode(serialize_tx(&final_reveal_tx));

    let result = client
        .test_mempool_accept(&[raw_commit_tx_hex, raw_reveal_tx_hex])
        .await?;

    // Assert both transactions are allowed
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Commit transaction was rejected");
    assert!(result[1].allowed, "Reveal transaction was rejected");

    // Verify the witness structure in the reveal transaction
    let witness = final_reveal_tx.input[0].witness.clone();
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
        assert_eq!(kon.as_bytes(), b"KON", "Expected KON identifier");
        assert!(op_0.is_empty(), "Expected empty push bytes");
        assert_eq!(*op_endif, OP_ENDIF, "Expected OP_ENDIF");
        assert_eq!(*op_checksig, OP_CHECKSIG, "Expected OP_CHECKSIG");

        // Deserialize the token data
        let token_data: WitnessData = ciborium::from_reader(serialized_data.as_bytes())?;

        // Verify the token data
        assert_eq!(
            token_data, token_balance,
            "Token data in witness doesn't match expected value"
        );

        // Verify the key in the script matches our random key
        let key_from_bytes = XOnlyPublicKey::from_slice(_key.as_bytes())?;
        assert_eq!(key_from_bytes, random_xonly_pubkey);
    } else {
        panic!("Script structure doesn't match expected pattern");
    }

    Ok(())
}
