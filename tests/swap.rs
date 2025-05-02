use std::str::FromStr;

use anyhow::Result;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::Psbt;
use bitcoin::Sequence;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::Txid;
use bitcoin::XOnlyPublicKey;
use bitcoin::absolute::LockTime;
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::psbt::Input;
use bitcoin::psbt::Output;
use bitcoin::script::Instruction;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::Keypair;
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
    let prevouts = vec![TxOut {
        value: Amount::from_sat(9000), // existing utxo with 9000 sats
        script_pubkey: seller_address.script_pubkey(),
    }];

    test_utils::sign_key_spend(&secp, &mut attach_commit_tx, &prevouts, &keypair, 0)?;

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

    let prevouts = vec![
        attach_commit_tx.output[1].clone(),
        attach_commit_tx.output[0].clone(),
    ];

    test_utils::sign_key_spend(&secp, &mut attach_reveal_tx, &prevouts, &keypair, 0)?;

    test_utils::sign_script_spend(
        &secp,
        &attach_taproot_spend_info,
        &attach_tap_script,
        &mut attach_reveal_tx,
        &prevouts,
        &keypair,
        1,
    )?;

    let attach_reveal_witness = attach_reveal_tx.input[1].witness.clone();
    // Get the script from the witness
    let script_bytes = attach_reveal_witness.to_vec()[1].clone();
    let script = ScriptBuf::from_bytes(script_bytes);

    // Parse the script instructions
    let instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;

    if let [
        Instruction::PushBytes(key),
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

            let x_only_public_key = XOnlyPublicKey::from_slice(key.as_bytes())?;
            let detach_tap_script = test_utils::build_inscription(
                serialized_detach_data,
                test_utils::PublicKey::Taproot(&x_only_public_key),
            )?;

            let detach_spend_info = TaprootBuilder::new()
                .add_leaf(0, detach_tap_script)
                .expect("Failed to add leaf")
                .finalize(&secp, x_only_public_key)
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
    let prevouts = vec![attach_reveal_tx.output[0].clone()];
    test_utils::sign_seller_side_psbt(
        &secp,
        &mut seller_detach_psbt,
        &detach_tap_script,
        internal_key,
        detach_control_block,
        &keypair,
        &prevouts,
    );

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

    // Define the prevouts explicitly in the same order as inputs
    let prevouts = [
        attach_reveal_tx.output[0].clone(),
        TxOut {
            value: Amount::from_sat(10000), // The value of the second input (buyer's UTXO)
            script_pubkey: buyer_address.script_pubkey(),
        },
    ];

    test_utils::sign_buyer_side_psbt(&secp, &mut buyer_psbt, &buyer_keypair, &prevouts);

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
