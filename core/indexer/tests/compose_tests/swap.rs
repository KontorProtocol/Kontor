use anyhow::Result;
use bitcoin::Amount;
use bitcoin::FeeRate;
use bitcoin::OutPoint;
use bitcoin::Psbt;
use bitcoin::TapSighashType;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::XOnlyPublicKey;
use bitcoin::absolute::LockTime;
use bitcoin::psbt::Input;
use bitcoin::psbt::Output;
use bitcoin::script::Instruction;
use bitcoin::script::PushBytesBuf;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::transaction::Version;
use bitcoin::{
    ScriptBuf,
    address::{Address, KnownHrp},
    consensus::encode::serialize as serialize_tx,
    key::Secp256k1,
};
use indexer::api::compose::compose;
use indexer::api::compose::compose_reveal;
use indexer::api::compose::{ComposeInputs, InstructionInputs};
use indexer::api::compose::{RevealInputs, RevealParticipantInputs};
use indexer::test_utils;
use indexer_types::OpReturnData;
use indexer_types::{ContractAddress, Inst, deserialize, serialize};
use testlib::RegTester;
use tracing::info;

pub async fn test_swap_psbt(reg_tester: &mut RegTester) -> Result<()> {
    info!("test_swap_psbt");
    let secp = Secp256k1::new();

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

    let instruction = Inst::Call {
        gas_limit: 50_000,
        contract: ContractAddress {
            name: "attach".to_string(),
            height: 0,
            tx_index: 1,
        },
        expr: "attach(0)".to_string(),
    };

    let serialized_instruction = serialize(&instruction)?;

    let chained_instructions = Inst::Call {
        gas_limit: 50_000,
        contract: ContractAddress {
            name: "detach".to_string(),
            height: 0,
            tx_index: 1,
        },
        expr: "detach()".to_string(),
    };
    let serialized_detach_data = serialize(&chained_instructions)?;

    let compose_params = ComposeInputs::builder()
        .instructions(vec![InstructionInputs {
            address: seller_address.clone(),
            x_only_public_key: seller_internal_key,
            funding_utxos: vec![(seller_out_point, seller_utxo_for_output.clone())],
            script_data: serialized_instruction,
        }])
        .fee_rate(FeeRate::from_sat_per_vb(5).unwrap())
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
        value: seller_utxo_for_output.clone().value,
        script_pubkey: seller_address.script_pubkey(),
    }];

    test_utils::sign_key_spend(
        &secp,
        &mut attach_commit_tx,
        &prevouts,
        &seller_keypair,
        0,
        Some(TapSighashType::All),
    )?;

    let attach_taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, attach_tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, seller_internal_key)
        .expect("Failed to finalize Taproot tree");

    let prevouts = vec![attach_commit_tx.output[0].clone()];

    test_utils::sign_script_spend(
        &secp,
        &attach_taproot_spend_info,
        &attach_tap_script,
        &mut attach_reveal_tx,
        &prevouts,
        &seller_keypair,
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
        let decoded_instruction: Inst = deserialize(serialized_data.as_bytes())?;
        assert_eq!(decoded_instruction, instruction);

        let serialized_detach_data = serialize(&chained_instructions)?;
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
        panic!("Invalid script instructions");
    }
    let detach_tapscript_spend_info = TaprootBuilder::new()
        .add_leaf(0, detach_tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, seller_internal_key)
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
            tap_internal_key: Some(seller_internal_key),
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
    let prevouts = vec![attach_reveal_tx.output[0].clone()];
    test_utils::sign_seller_side_psbt(
        &secp,
        &mut seller_detach_psbt,
        &detach_tap_script,
        seller_internal_key,
        detach_control_block,
        &seller_keypair,
        &prevouts,
    );

    // Create transfer data pointing to output 2 (buyer's address)
    let transfer_data = OpReturnData::PubKey(buyer_internal_key);
    let transfer_bytes = serialize(&transfer_data)?;

    let reveal_inputs = RevealInputs::builder()
        .commit_tx(attach_reveal_tx.clone())
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .participants(vec![RevealParticipantInputs {
            address: seller_address.clone(),
            x_only_public_key: seller_internal_key,
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
    buyer_psbt.unsigned_tx.input.push(TxIn {
        previous_output: buyer_out_point,
        ..Default::default()
    });
    buyer_psbt.inputs.push(Input {
        witness_utxo: Some(TxOut {
            script_pubkey: buyer_address.script_pubkey(),
            value: buyer_utxo_for_output.value,
        }),
        tap_internal_key: Some(buyer_internal_key),
        ..Default::default()
    });

    // Ensure seller is paid 600 sats at output index 0 to satisfy SIGHASH_SINGLE
    buyer_psbt.unsigned_tx.output.insert(
        0,
        TxOut {
            value: Amount::from_sat(600),
            script_pubkey: seller_address.script_pubkey(),
        },
    );

    // Add buyer change so the remainder of the buyer input is not treated as fee
    buyer_psbt.unsigned_tx.output.push(TxOut {
        value: buyer_utxo_for_output.value - Amount::from_sat(600) - Amount::from_sat(546),
        script_pubkey: buyer_address.script_pubkey(),
    });

    // Define the prevouts explicitly in the same order as inputs
    let prevouts = [
        attach_reveal_tx.output[0].clone(),
        TxOut {
            value: buyer_utxo_for_output.value,
            script_pubkey: buyer_address.script_pubkey(),
        },
    ];

    test_utils::sign_buyer_side_psbt(&secp, &mut buyer_psbt, &buyer_keypair, &prevouts);

    let final_tx = buyer_psbt.extract_tx()?;
    let attach_commit_tx_hex = hex::encode(serialize_tx(&attach_commit_tx));
    let raw_attach_reveal_tx_hex = hex::encode(serialize_tx(&attach_reveal_tx));
    let raw_psbt_hex = hex::encode(serialize_tx(&final_tx));

    let result = reg_tester
        .mempool_accept_result(&[attach_commit_tx_hex, raw_attach_reveal_tx_hex, raw_psbt_hex])
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

pub async fn test_swap_integrity(reg_tester: &mut RegTester) -> Result<()> {
    info!("test_swap_integrity");
    let secp = Secp256k1::new();

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

    let instruction = Inst::Call {
        gas_limit: 50_000,
        contract: ContractAddress {
            name: "attach".to_string(),
            height: 0,
            tx_index: 1,
        },
        expr: "attach(0)".to_string(),
    };

    let serialized_instruction = serialize(&instruction)?;

    let chained_instructions = Inst::Call {
        gas_limit: 50_000,
        contract: ContractAddress {
            name: "detach".to_string(),
            height: 0,
            tx_index: 1,
        },
        expr: "detach()".to_string(),
    };
    let serialized_detach_data = serialize(&chained_instructions)?;

    let compose_params = ComposeInputs::builder()
        .instructions(vec![InstructionInputs {
            address: seller_address.clone(),
            x_only_public_key: seller_internal_key,
            funding_utxos: vec![(seller_out_point, seller_utxo_for_output.clone())],
            script_data: serialized_instruction,
        }])
        .fee_rate(FeeRate::from_sat_per_vb(5).unwrap())
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
        value: seller_utxo_for_output.clone().value,
        script_pubkey: seller_address.script_pubkey(),
    }];

    test_utils::sign_key_spend(
        &secp,
        &mut attach_commit_tx,
        &prevouts,
        &seller_keypair,
        0,
        Some(TapSighashType::All),
    )?;

    let attach_taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, attach_tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, seller_internal_key)
        .expect("Failed to finalize Taproot tree");

    let prevouts = vec![attach_commit_tx.output[0].clone()];

    test_utils::sign_script_spend(
        &secp,
        &attach_taproot_spend_info,
        &attach_tap_script,
        &mut attach_reveal_tx,
        &prevouts,
        &seller_keypair,
        0,
    )?;

    let detach_tapscript_spend_info = TaprootBuilder::new()
        .add_leaf(0, detach_tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, seller_internal_key)
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
            tap_internal_key: Some(seller_internal_key),
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
    let prevouts = vec![attach_reveal_tx.output[0].clone()];
    test_utils::sign_seller_side_psbt(
        &secp,
        &mut seller_detach_psbt,
        &detach_tap_script,
        seller_internal_key,
        detach_control_block,
        &seller_keypair,
        &prevouts,
    );

    // Create transfer data pointing to output 2 (buyer's address)
    let transfer_data = OpReturnData::PubKey(buyer_internal_key);
    let transfer_bytes = serialize(&transfer_data)?;

    let reveal_inputs = RevealInputs::builder()
        .commit_tx(attach_reveal_tx.clone())
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .participants(vec![RevealParticipantInputs {
            address: seller_address.clone(),
            x_only_public_key: seller_internal_key,
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
    buyer_psbt.unsigned_tx.input.push(TxIn {
        previous_output: buyer_out_point,
        ..Default::default()
    });
    buyer_psbt.inputs.push(Input {
        witness_utxo: Some(TxOut {
            script_pubkey: buyer_address.script_pubkey(),
            value: buyer_utxo_for_output.value,
        }),
        tap_internal_key: Some(buyer_internal_key),
        ..Default::default()
    });

    // Ensure seller is paid 600 sats at output index 0 to satisfy SIGHASH_SINGLE
    buyer_psbt.unsigned_tx.output.insert(
        0,
        TxOut {
            value: Amount::from_sat(600),
            script_pubkey: seller_address.script_pubkey(),
        },
    );

    // Add buyer change so the remainder of the buyer input is not treated as fee
    buyer_psbt.unsigned_tx.output.push(TxOut {
        value: buyer_utxo_for_output.value - Amount::from_sat(600) - Amount::from_sat(546),
        script_pubkey: buyer_address.script_pubkey(),
    });

    // Define the prevouts explicitly in the same order as inputs
    let prevouts = [
        attach_reveal_tx.output[0].clone(),
        TxOut {
            value: buyer_utxo_for_output.value,
            script_pubkey: buyer_address.script_pubkey(),
        },
    ];

    test_utils::sign_buyer_side_psbt(&secp, &mut buyer_psbt, &buyer_keypair, &prevouts);

    let final_tx = buyer_psbt.extract_tx()?;
    let attach_commit_tx_hex = hex::encode(serialize_tx(&attach_commit_tx));
    let raw_attach_reveal_tx_hex = hex::encode(serialize_tx(&attach_reveal_tx));
    let raw_psbt_hex = hex::encode(serialize_tx(&final_tx));

    // Verify valid tx is accepted
    let result = reg_tester
        .mempool_accept_result(&[
            attach_commit_tx_hex.clone(),
            raw_attach_reveal_tx_hex.clone(),
            raw_psbt_hex,
        ])
        .await?;

    assert_eq!(result.len(), 3);
    assert!(result[0].allowed);
    assert!(result[1].allowed);
    assert!(result[2].allowed);

    // Create malicious tx (Seller tries to redirect asset to themselves)
    let mut malicious_tx = final_tx.clone();

    // Maliciously change the OP_RETURN destination to seller's key
    let malicious_transfer_data = OpReturnData::PubKey(seller_internal_key);
    let malicious_transfer_bytes = serialize(&malicious_transfer_data)?;

    // Verify index 1 is OP_RETURN
    assert!(malicious_tx.output[1].script_pubkey.is_op_return());

    // Overwrite the OP_RETURN
    malicious_tx.output[1].script_pubkey =
        ScriptBuf::new_op_return(PushBytesBuf::try_from(malicious_transfer_bytes)?);

    let malicious_hex = hex::encode(serialize_tx(&malicious_tx));
    let result_malicious = reg_tester
        .mempool_accept_result(&[
            attach_commit_tx_hex,
            raw_attach_reveal_tx_hex,
            malicious_hex,
        ])
        .await?;

    assert!(
        !result_malicious[2].allowed,
        "Malicious transaction should be rejected"
    );
    // Reject reason should indicate signature validation failed
    // reject-reason: mempool-script-verify-flag-failed (Invalid Schnorr signature)
    if let Some(reason) = &result_malicious[2].reject_reason {
        assert!(
            reason.contains("mempool-script-verify-flag-failed")
                || reason.contains("Invalid Schnorr signature"),
            "Unexpected reject reason: {}",
            reason
        );
    } else {
        panic!("Expected reject reason");
    }

    Ok(())
}
