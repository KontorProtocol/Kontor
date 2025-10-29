use anyhow::Result;
use bitcoin::absolute::LockTime;
use bitcoin::psbt::{Input, Output};
use bitcoin::script::Instruction;
use bitcoin::secp256k1::Keypair;
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{
    Address, FeeRate, KnownHrp, Network, Psbt, ScriptBuf, TapSighashType, Transaction, TxIn,
    Witness, XOnlyPublicKey,
};
use bitcoin::{
    Amount, OutPoint, Txid, consensus::encode::serialize as serialize_tx, key::Secp256k1,
    transaction::TxOut,
};
use clap::Parser;
use indexer::api::compose::{
    ComposeInputs, InstructionInputs, RevealInputs, RevealParticipantInputs, compose,
    compose_reveal,
};
use indexer::config::TestConfig;
use indexer::op_return::OpReturnData;
use indexer::test_utils;
use indexer::witness_data::{TokenBalance, WitnessData};
use indexer::{bitcoin_client::Client, config::Config};
use std::str::FromStr;

#[tokio::test]
async fn test_signature_replay_failse() -> Result<()> {
    let client = Client::new_from_config(&Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;

    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) = test_utils::generate_taproot_address_from_mnemonic(
        &secp,
        Network::Bitcoin,
        &config.taproot_key_path,
        0,
    )?;

    let seller_keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (seller_internal_key, _parity) = seller_keypair.x_only_public_key();

    // UTXO loaded with 9000 sats
    let out_point = OutPoint {
        txid: Txid::from_str("dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8")?,
        vout: 0,
    };

    let utxo_for_output = TxOut {
        value: Amount::from_sat(9000),
        script_pubkey: seller_address.script_pubkey(),
    };

    // Create token balance data
    let token_value = 1000;
    let token_balance = TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let compose_params = ComposeInputs::builder()
        .instructions(vec![InstructionInputs {
            address: seller_address.clone(),
            x_only_public_key: seller_internal_key,
            funding_utxos: vec![(out_point, utxo_for_output.clone())],
            script_data: serialized_token_balance.clone(),
        }])
        .fee_rate(FeeRate::from_sat_per_vb(5).unwrap())
        .envelope(546)
        .build();

    let compose_outputs = compose(compose_params)?;

    let mut commit_tx = compose_outputs.commit_transaction;
    let tap_script = compose_outputs.per_participant[0].commit.tap_script.clone();
    let mut reveal_tx = compose_outputs.reveal_transaction;

    // 1. SIGN THE ORIGINAL COMMIT
    test_utils::sign_key_spend(
        &secp,
        &mut commit_tx,
        &[utxo_for_output],
        &seller_keypair,
        0,
        Some(TapSighashType::All),
    )?;

    let spend_tx_prevouts = vec![commit_tx.output[0].clone()];

    // 2. SIGN THE REVEAL

    // sign the script_spend input for the reveal transaction
    let reveal_taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, seller_internal_key)
        .expect("Failed to finalize Taproot tree");

    test_utils::sign_script_spend(
        &secp,
        &reveal_taproot_spend_info,
        &tap_script,
        &mut reveal_tx,
        &spend_tx_prevouts,
        &seller_keypair,
        0,
    )?;

    let commit_tx_hex = hex::encode(serialize_tx(&commit_tx));
    let reveal_tx_hex = hex::encode(serialize_tx(&reveal_tx));

    let result = client
        .test_mempool_accept(&[commit_tx_hex, reveal_tx_hex])
        .await?;

    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Commit transaction was rejected");
    assert!(result[1].allowed, "Reveal transaction was rejected");

    let (buyer_address, _, _) = test_utils::generate_taproot_address_from_mnemonic(
        &secp,
        Network::Bitcoin,
        &config.taproot_key_path,
        1,
    )?;

    let buyer_out_point = OutPoint {
        txid: Txid::from_str("ffb32fce7a4ce109ed2b4b02de910ea1a08b9017d88f1da7f49b3d2f79638cc3")?,
        vout: 0,
    };

    let buyer_utxo_for_output = TxOut {
        value: Amount::from_sat(10000),
        script_pubkey: buyer_address.script_pubkey(),
    };

    let compose_params = ComposeInputs::builder()
        .instructions(vec![InstructionInputs {
            address: seller_address.clone(),
            x_only_public_key: seller_internal_key,
            funding_utxos: vec![(buyer_out_point, buyer_utxo_for_output.clone())],
            script_data: serialized_token_balance,
        }])
        .fee_rate(FeeRate::from_sat_per_vb(5).unwrap())
        .envelope(546)
        .build();

    let buyer_compose = compose(compose_params)?;

    let mut buyer_commit_tx = buyer_compose.commit_transaction;
    let mut buyer_reveal_tx = buyer_compose.reveal_transaction;

    buyer_commit_tx.input[0].witness = commit_tx.input[0].witness.clone();

    buyer_reveal_tx.input[0].witness = reveal_tx.input[0].witness.clone();

    let buyer_commit_tx_hex = hex::encode(serialize_tx(&buyer_commit_tx));
    let buyer_reveal_tx_hex = hex::encode(serialize_tx(&buyer_reveal_tx));

    let result = client
        .test_mempool_accept(&[buyer_commit_tx_hex, buyer_reveal_tx_hex])
        .await?;

    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(
        !result[0].allowed,
        "Commit transaction was unexpectedly accepted"
    );
    assert!(
        result[0]
            .reject_reason
            .as_ref()
            .unwrap()
            .contains("Invalid Schnorr signature"),
        "Commit transaction was unexpectedly rejected for reason other than invalid witness"
    );
    assert!(
        !result[1].allowed,
        "Reveal transaction was unexpectedly accepted"
    );

    Ok(())
}

#[tokio::test]
async fn test_psbt_signature_replay_fails() -> Result<()> {
    let client = Client::new_from_config(&Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;

    let secp = Secp256k1::new();

    let (seller_address, seller_child_key, _) = test_utils::generate_taproot_address_from_mnemonic(
        &secp,
        Network::Bitcoin,
        &config.taproot_key_path,
        0,
    )?;

    let (buyer_address, buyer_child_key, _) = test_utils::generate_taproot_address_from_mnemonic(
        &secp,
        Network::Bitcoin,
        &config.taproot_key_path,
        1,
    )?;

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

    let detach_data = WitnessData::Detach {
        output_index: 0,
        token_balance: TokenBalance {
            value: token_value,
            name: "token_name".to_string(),
        },
    };
    let mut serialized_detach_data = Vec::new();
    ciborium::into_writer(&detach_data, &mut serialized_detach_data).unwrap();

    let outpoint = OutPoint {
        txid: Txid::from_str("dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8")?,
        vout: 0,
    };

    let txout = TxOut {
        value: Amount::from_sat(9000),
        script_pubkey: seller_address.script_pubkey(),
    };

    let compose_params = ComposeInputs::builder()
        .instructions(vec![InstructionInputs {
            address: seller_address.clone(),
            x_only_public_key: internal_key,
            funding_utxos: vec![(outpoint, txout)],
            script_data: serialized_token_balance,
        }])
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .chained_script_data(serialized_detach_data.clone())
        .envelope(546)
        .build();

    let compose_outputs = compose(compose_params)?;
    let mut attach_commit_tx = compose_outputs.commit_transaction;
    let mut attach_reveal_tx = compose_outputs.reveal_transaction;
    let attach_tap_script = compose_outputs.per_participant[0].commit.tap_script.clone();
    let detach_tap_script = compose_outputs.per_participant[0]
        .chained
        .as_ref()
        .unwrap()
        .tap_script
        .clone();

    let prevouts = vec![TxOut {
        value: Amount::from_sat(9000),
        script_pubkey: seller_address.script_pubkey(),
    }];

    test_utils::sign_key_spend(
        &secp,
        &mut attach_commit_tx,
        &prevouts,
        &keypair,
        0,
        Some(TapSighashType::All),
    )?;

    let attach_taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, attach_tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, internal_key)
        .expect("Failed to finalize Taproot tree");

    let prevouts = vec![attach_commit_tx.output[0].clone()];

    test_utils::sign_script_spend(
        &secp,
        &attach_taproot_spend_info,
        &attach_tap_script,
        &mut attach_reveal_tx,
        &prevouts,
        &keypair,
        0,
    )?;

    let attach_reveal_witness = attach_reveal_tx.input[0].witness.clone();
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

            assert_eq!(
                detach_script_address_2.script_pubkey(),
                attach_reveal_tx.output[0].script_pubkey
            );
        } else {
            panic!("Invalid witness data");
        }
    } else {
        panic!("Invalid script instructions");
    }
    let detach_tapscript_spend_info = TaprootBuilder::new()
        .add_leaf(0, detach_tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, internal_key)
        .expect("Failed to finalize Taproot tree");

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
        outputs: vec![Output::default()],
        version: 0,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
    };

    let prev_sig = &attach_reveal_tx.input[0].witness[0];

    // buyer attempts to use the script spend sig from prev tx to sign the psbt
    let mut witness = Witness::new();
    witness.push(prev_sig);
    witness.push(detach_tap_script.as_bytes());
    witness.push(detach_control_block.serialize());
    seller_detach_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_keypair = Keypair::from_secret_key(&secp, &buyer_child_key.private_key);
    let (buyer_internal_key, _) = buyer_keypair.x_only_public_key();

    // Create transfer data pointing to output 2 (buyer's address)
    let transfer_data = OpReturnData::D {
        destination: buyer_internal_key,
    };
    let mut transfer_bytes = Vec::new();
    ciborium::into_writer(&transfer_data, &mut transfer_bytes).unwrap();

    let reveal_inputs = RevealInputs::builder()
        .commit_txid(attach_reveal_tx.compute_txid())
        .fee_rate(FeeRate::from_sat_per_vb(5).unwrap())
        .participants(vec![RevealParticipantInputs {
            address: seller_address.clone(),
            x_only_public_key: internal_key,
            commit_outpoint: OutPoint {
                txid: attach_reveal_tx.compute_txid(),
                vout: 0,
            },
            commit_prevout: attach_reveal_tx.output[0].clone(),
            commit_script_data: serialized_detach_data,
        }])
        .op_return_data(transfer_bytes)
        .envelope(546)
        .build();
    let buyer_reveal_outputs = compose_reveal(reveal_inputs)?;

    // Create buyer's PSBT that combines with seller's PSBT
    let mut buyer_psbt = buyer_reveal_outputs.psbt;

    buyer_psbt.inputs[0] = seller_detach_psbt.inputs[0].clone();
    // Add buyer funding input as a second input
    buyer_psbt.unsigned_tx.input.push(TxIn {
        previous_output: OutPoint {
            txid: Txid::from_str(
                "ffb32fce7a4ce109ed2b4b02de910ea1a08b9017d88f1da7f49b3d2f79638cc3",
            )?,
            vout: 0,
        },
        ..Default::default()
    });
    buyer_psbt.inputs.push(Input {
        witness_utxo: Some(TxOut {
            script_pubkey: buyer_address.script_pubkey(),
            value: Amount::from_sat(10000),
        }),
        tap_internal_key: Some(buyer_internal_key),
        ..Default::default()
    });
    // Ensure seller is paid 600 sats as in original test
    buyer_psbt.unsigned_tx.output.push(TxOut {
        value: Amount::from_sat(600),
        script_pubkey: seller_address.script_pubkey(),
    });

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
    assert!(result[2].reject_reason.is_some());
    assert!(result[0].allowed);
    assert!(result[1].allowed);
    assert!(!result[2].allowed);
    assert!(
        result[2]
            .reject_reason
            .as_ref()
            .unwrap()
            .contains("Invalid Schnorr signature"),
        "Reveal transaction was unexpectedly rejected for reason other than invalid witness"
    );

    Ok(())
}
