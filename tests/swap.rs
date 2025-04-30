use std::str::FromStr;

use anyhow::Result;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::Psbt;
use bitcoin::Sequence;
use bitcoin::TapLeafHash;
use bitcoin::TapSighash;
use bitcoin::TapSighashType;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::absolute::LockTime;
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::key::TweakedKeypair;
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::psbt::Input;
use bitcoin::psbt::Output;
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
use kontor::witness_data::TokenBalance;
use kontor::witness_data::WitnessData;
use kontor::{bitcoin_client::Client, config::Config};

#[tokio::test]
async fn test_psbt_inscription() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;

    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 0)?;

    let (buyer_address, buyer_child_key, _) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 1)?;

    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    let token_value = 1000;
    let attach_witness_data = WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: token_value,
            name: "token_name".to_string(),
        },
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&attach_witness_data, &mut serialized_token_balance).unwrap();

    let attach_tap_script = test_utils::build_inscription(
        serialized_token_balance,
        test_utils::PublicKey::Taproot(&internal_key),
    )?;

    // Build the Taproot tree with the script
    let attach_taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, attach_tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, internal_key)
        .expect("Failed to finalize Taproot tree");

    // Get the output key which commits to both the internal key and the script tree
    let output_key = attach_taproot_spend_info.output_key();

    // Create the address from the output key
    let script_spendable_address = Address::p2tr_tweaked(output_key, KnownHrp::Mainnet);

    // Create the transaction
    let mut attach_commit_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(
                    "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8",
                )?,
                vout: 0,
            }, // The output we are spending
            script_sig: ScriptBuf::default(), // For a p2tr script_sig is empty
            sequence: Sequence::MAX,
            witness: Witness::default(), // Filled in after signing
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(546),
                script_pubkey: script_spendable_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(8154), // 9000 - 546 - 300 fee
                script_pubkey: seller_address.script_pubkey(),
            },
        ],
    };
    let input_index = 0;

    // Sign the transaction
    let sighash_type = TapSighashType::Default;
    let prevouts = vec![TxOut {
        value: Amount::from_sat(9000), // existing utxo with 9000 sats
        script_pubkey: seller_address.script_pubkey(),
    }];
    let prevouts = Prevouts::All(&prevouts);

    let mut sighasher = SighashCache::new(&attach_commit_tx);
    let sighash: TapSighash = sighasher
        .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
        .expect("failed to construct sighash");

    // Sign the sighash
    let tweaked: TweakedKeypair = keypair.tap_tweak(&secp, None);
    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, &tweaked.to_inner());

    // Update the witness stack
    let signature = bitcoin::taproot::Signature {
        signature,
        sighash_type,
    };
    attach_commit_tx.input[input_index]
        .witness
        .push(signature.to_vec());

    let detach_data = WitnessData::Detach {
        output_index: 0,
        token_balance: TokenBalance {
            value: token_value,
            name: "token_name".to_string(),
        },
    };
    let mut serialized_detach_data = Vec::new();
    ciborium::into_writer(&detach_data, &mut serialized_detach_data).unwrap();

    let detach_tap_script = test_utils::build_inscription(
        serialized_detach_data,
        test_utils::PublicKey::Taproot(&internal_key),
    )?;

    let detach_tapscript_spend_info = TaprootBuilder::new()
        .add_leaf(0, detach_tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, internal_key)
        .expect("Failed to finalize Taproot tree");

    let detach_script_address =
        Address::p2tr_tweaked(detach_tapscript_spend_info.output_key(), KnownHrp::Mainnet);

    let mut attach_reveal_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![
            TxIn {
                previous_output: OutPoint {
                    txid: attach_commit_tx.compute_txid(),
                    vout: 1,
                },
                script_sig: ScriptBuf::default(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            },
            TxIn {
                previous_output: OutPoint {
                    txid: attach_commit_tx.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::default(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            },
        ],
        output: vec![
            TxOut {
                value: Amount::from_sat(546),
                script_pubkey: detach_script_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(7854), // 8154 - 300
                script_pubkey: seller_address.script_pubkey(),
            },
        ],
    };

    let mut reveal_sighasher = SighashCache::new(&attach_reveal_tx);
    let prevout = vec![
        attach_commit_tx.output[1].clone(),
        attach_commit_tx.output[0].clone(),
    ];
    let prevouts = Prevouts::All(&prevout);
    let reveal_sighash: TapSighash = reveal_sighasher
        .taproot_key_spend_signature_hash(0, &prevouts, sighash_type)
        .expect("failed to construct sighash");

    let tweaked: TweakedKeypair = keypair.tap_tweak(&secp, None);
    let msg = Message::from_digest(reveal_sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, &tweaked.to_inner());

    // Update the witness stack
    let signature = bitcoin::taproot::Signature {
        signature,
        sighash_type,
    };
    attach_reveal_tx.input[0].witness.push(signature.to_vec());

    let mut attach_reveal_sigasher = SighashCache::new(&attach_reveal_tx);

    let attach_reveal_sighash: TapSighash = attach_reveal_sigasher
        .taproot_script_spend_signature_hash(
            1,
            &prevouts,
            TapLeafHash::from_script(&attach_tap_script, LeafVersion::TapScript),
            sighash_type,
        )
        .expect("Failed to create sighash");

    let msg = Message::from_digest(attach_reveal_sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, &keypair);
    let signature = bitcoin::taproot::Signature {
        signature,
        sighash_type,
    };
    attach_reveal_tx.input[1].witness.push(signature.to_vec());
    attach_reveal_tx.input[1]
        .witness
        .push(attach_tap_script.as_bytes());

    let attach_control_block = attach_taproot_spend_info
        .control_block(&(attach_tap_script.clone(), LeafVersion::TapScript))
        .expect("Failed to create control block");
    attach_reveal_tx.input[1]
        .witness
        .push(attach_control_block.serialize());

    let attach_reveal_witness = attach_reveal_tx.input[1].witness.clone();
    // Get the script from the witness
    let script_bytes = attach_reveal_witness.to_vec()[1].clone();
    let script = ScriptBuf::from_bytes(script_bytes);

    // Parse the script instructions
    let instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;

    if let [
        Instruction::PushBytes(_key),
        _,
        _,
        _,
        _,
        _,
        Instruction::PushBytes(serialized_data),
        _,
    ] = instructions.as_slice()
    {
        let witness_data: WitnessData = ciborium::from_reader(serialized_data.as_bytes())?;
        assert_eq!(witness_data, attach_witness_data);

        if let WitnessData::Attach {
            token_balance,
            output_index,
        } = witness_data
        {
            let detach_data = WitnessData::Detach {
                output_index,
                token_balance,
            };
            let secp = Secp256k1::new();
            let mut serialized_detach_data = Vec::new();
            ciborium::into_writer(&detach_data, &mut serialized_detach_data).unwrap();

            let detach_tap_script = test_utils::build_inscription(
                serialized_detach_data,
                test_utils::PublicKey::Taproot(&internal_key),
            )?;

            let detach_spend_info = TaprootBuilder::new()
                .add_leaf(0, detach_tap_script)
                .expect("Failed to add leaf")
                .finalize(&secp, internal_key)
                .expect("Failed to finalize Taproot tree");

            let detach_script_address_2 =
                Address::p2tr_tweaked(detach_spend_info.output_key(), KnownHrp::Mainnet);

            assert_eq!(detach_script_address_2, detach_script_address);
        } else {
            panic!("Invalid witness data");
        }
    } else {
        panic!("Invalid script instructions");
    }

    let detach_control_block = detach_tapscript_spend_info
        .control_block(&(detach_tap_script.clone(), LeafVersion::TapScript))
        .expect("Failed to create control block");

    let mut seller_detach_psbt = Psbt {
        unsigned_tx: Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: attach_reveal_tx.compute_txid(),
                    vout: 0,
                },
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(600), // price
                script_pubkey: seller_address.script_pubkey(),
            }],
        },
        inputs: vec![Input {
            witness_utxo: Some(attach_reveal_tx.output[0].clone()),
            tap_internal_key: Some(internal_key),
            tap_merkle_root: Some(detach_tapscript_spend_info.merkle_root().unwrap()),
            tap_scripts: {
                let mut scripts = std::collections::BTreeMap::new();
                scripts.insert(
                    detach_control_block.clone(),
                    (detach_tap_script.clone(), LeafVersion::TapScript),
                );
                scripts
            },
            ..Default::default()
        }],
        outputs: vec![Output::default()], // No outputs
        version: 0,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
    };

    let seller_sighash = SighashCache::new(&seller_detach_psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[attach_reveal_tx.output[0].clone()]),
            TapLeafHash::from_script(&detach_tap_script, LeafVersion::TapScript),
            TapSighashType::SinglePlusAnyoneCanPay,
        )
        .expect("Failed to create sighash");

    let msg = Message::from_digest(seller_sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, &keypair);
    let signature = bitcoin::taproot::Signature {
        signature,
        sighash_type: TapSighashType::SinglePlusAnyoneCanPay,
    };
    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(detach_tap_script.as_bytes());
    witness.push(detach_control_block.serialize());
    seller_detach_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_keypair = Keypair::from_secret_key(&secp, &buyer_child_key.private_key);
    let (buyer_internal_key, _) = buyer_keypair.x_only_public_key();

    // Create buyer's PSBT that combines with seller's PSBT
    let mut buyer_psbt = Psbt {
        unsigned_tx: Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![
                // Seller's signed input (from the unspendable output)
                TxIn {
                    previous_output: OutPoint {
                        txid: attach_reveal_tx.compute_txid(),
                        vout: 0,
                    },
                    script_sig: ScriptBuf::default(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                },
                // Buyer's UTXO input
                TxIn {
                    previous_output: OutPoint {
                        txid: Txid::from_str(
                            "ffb32fce7a4ce109ed2b4b02de910ea1a08b9017d88f1da7f49b3d2f79638cc3",
                        )?,
                        vout: 0,
                    },
                    script_sig: ScriptBuf::default(),
                    sequence: Sequence::MAX,
                    witness: Witness::default(),
                },
            ],
            output: vec![
                // Seller receives payment
                TxOut {
                    value: Amount::from_sat(600),
                    script_pubkey: seller_address.script_pubkey(),
                },
                // Buyer receives the token (create a new OP_RETURN with transfer data)
                TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: {
                        let mut op_return_script = ScriptBuf::new();
                        op_return_script.push_opcode(OP_RETURN);
                        op_return_script.push_slice(b"kon");

                        // Create transfer data pointing to output 2 (buyer's address)
                        let transfer_data = OpReturnData::D {
                            destination: buyer_internal_key,
                        };
                        let mut transfer_bytes = Vec::new();
                        ciborium::into_writer(&transfer_data, &mut transfer_bytes).unwrap();
                        op_return_script.push_slice(PushBytesBuf::try_from(transfer_bytes)?);

                        op_return_script
                    },
                },
                // Buyer's change
                TxOut {
                    value: Amount::from_sat(9546), // 10000 - 600 - 400 + 546
                    script_pubkey: buyer_address.script_pubkey(),
                },
            ],
        },
        inputs: vec![
            // Seller's input (copy from seller's PSBT)
            seller_detach_psbt.inputs[0].clone(),
            // Buyer's input
            Input {
                witness_utxo: Some(TxOut {
                    script_pubkey: buyer_address.script_pubkey(),
                    value: Amount::from_sat(10000),
                }),
                tap_internal_key: Some(buyer_internal_key),
                ..Default::default()
            },
        ],
        outputs: vec![Output::default(), Output::default(), Output::default()],
        version: 0,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
    };

    // Sign the buyer's input (key path spending)
    let buyer_sighash = {
        // Create a new SighashCache for the transaction
        let mut sighasher = SighashCache::new(&buyer_psbt.unsigned_tx);

        // Define the prevouts explicitly in the same order as inputs
        let prevouts = [
            attach_reveal_tx.output[0].clone(),
            TxOut {
                value: Amount::from_sat(10000), // The value of the second input (buyer's UTXO)
                script_pubkey: buyer_address.script_pubkey(),
            },
        ];

        // Calculate the sighash for key path spending
        let sighash = sighasher
            .taproot_key_spend_signature_hash(
                1, // Buyer's input index (back to 1)
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )
            .expect("Failed to create sighash");

        sighash
    };

    // Sign with the buyer's tweaked key
    let msg = Message::from_digest(buyer_sighash.to_byte_array());

    // Create the tweaked keypair
    let buyer_tweaked = buyer_keypair.tap_tweak(&secp, None);
    // Sign with the tweaked keypair since we're doing key path spending
    let buyer_signature = secp.sign_schnorr(&msg, &buyer_tweaked.to_inner());

    let buyer_signature = bitcoin::taproot::Signature {
        signature: buyer_signature,
        sighash_type: TapSighashType::Default,
    };

    // Add the signature to the PSBT
    buyer_psbt.inputs[1].tap_key_sig = Some(buyer_signature);

    // Construct the witness stack for key path spending
    let mut buyer_witness = Witness::new();
    buyer_witness.push(buyer_signature.to_vec());
    buyer_psbt.inputs[1].final_script_witness = Some(buyer_witness);

    let final_tx = buyer_psbt.extract_tx()?;
    let attach_commit_tx_hex = hex::encode(serialize_tx(&attach_commit_tx));
    let raw_attach_reveal_tx_hex = hex::encode(serialize_tx(&attach_reveal_tx));
    let raw_psbt_hex = hex::encode(serialize_tx(&final_tx));

    let result = client
        .test_mempool_accept(&[attach_commit_tx_hex, raw_attach_reveal_tx_hex, raw_psbt_hex])
        .await?;

    assert_eq!(
        result.len(),
        3,
        "Expected exactly three transaction results"
    );
    assert!(result[0].reject_reason.is_none());
    assert!(result[1].reject_reason.is_none());
    assert!(result[2].reject_reason.is_none());
    assert!(result[0].allowed);
    assert!(result[1].allowed);
    assert!(result[2].allowed);

    Ok(())
}
