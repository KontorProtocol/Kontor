use anyhow::Result;
use bitcoin::Address;
use bitcoin::Amount;
use bitcoin::FeeRate;
use bitcoin::OutPoint;
use bitcoin::Psbt;
use bitcoin::Sequence;
use bitcoin::TapSighashType;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::XOnlyPublicKey;
use bitcoin::absolute::LockTime;
use bitcoin::key::Keypair;
use bitcoin::psbt::Input;
use bitcoin::psbt::Output;
use bitcoin::script::PushBytesBuf;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::transaction::Version;
use bitcoin::{ScriptBuf, consensus::encode::serialize as serialize_tx, key::Secp256k1};
use indexer::api::compose::compose;
use indexer::api::compose::compose_reveal;
use indexer::api::compose::{ComposeInputs, InstructionInputs};
use indexer::api::compose::{RevealInputs, RevealParticipantInputs};
use indexer::test_utils;
use indexer_types::OpReturnData;
use indexer_types::{ContractAddress, Inst, serialize};
use testlib::RegTester;
use tracing::info;

struct SwapTestContext {
    attach_commit_tx_hex: String,
    raw_attach_reveal_tx_hex: String,
    raw_psbt_hex: String,
    final_tx: Transaction,
}

struct SwapTestParams {
    seller_address: Address,
    seller_keypair: Keypair,
    seller_internal_key: XOnlyPublicKey,
    seller_out_point: OutPoint,
    seller_utxo_for_output: TxOut,
    buyer_address: Address,
    buyer_keypair: Keypair,
    buyer_internal_key: XOnlyPublicKey,
    buyer_out_point: OutPoint,
    buyer_utxo_for_output: TxOut,
}

async fn setup_swap_test(params: SwapTestParams) -> Result<SwapTestContext> {
    let secp = Secp256k1::new();
    let seller_address = params.seller_address;
    let seller_keypair = params.seller_keypair;
    let seller_internal_key = params.seller_internal_key;
    let seller_out_point = params.seller_out_point;
    let seller_utxo_for_output = params.seller_utxo_for_output;
    let buyer_address = params.buyer_address;
    let buyer_keypair = params.buyer_keypair;
    let buyer_internal_key = params.buyer_internal_key;
    let buyer_out_point = params.buyer_out_point;
    let buyer_utxo_for_output = params.buyer_utxo_for_output;
    let instruction = Inst::Call {
        gas_limit: 50_000,
        contract: ContractAddress {
            name: "token".to_string(),
            height: 0,
            tx_index: 0,
        },
        expr: "attach(0)".to_string(),
    };

    let serialized_instruction = serialize(&instruction)?;

    let chained_instructions = Inst::Call {
        gas_limit: 50_000,
        contract: ContractAddress {
            name: "token".to_string(),
            height: 0,
            tx_index: 0,
        },
        expr: "detach()".to_string(),
    };
    let serialized_detach_data = serialize(&chained_instructions)?;

    let compose_params = ComposeInputs::builder()
        .instructions(vec![
            InstructionInputs::builder()
                .address(seller_address.clone())
                .x_only_public_key(seller_internal_key)
                .funding_utxos(vec![(seller_out_point, seller_utxo_for_output.clone())])
                .script_data(serialized_instruction)
                .chained_script_data(serialized_detach_data.clone())
                .build(),
        ])
        .fee_rate(FeeRate::from_sat_per_vb(5).unwrap())
        .envelope(546)
        .build();

    let compose_outputs = compose(compose_params)?;
    let mut attach_commit_tx = compose_outputs.commit_transaction;
    let mut attach_reveal_tx = compose_outputs.reveal_transaction;
    let attach_tap_script = compose_outputs.per_participant[0]
        .commit_tap_leaf_script
        .tap_script
        .clone();
    let detach_tap_script = compose_outputs.per_participant[0]
        .chained_tap_leaf_script
        .as_ref()
        .unwrap()
        .tap_script
        .clone();

    let prevouts = vec![seller_utxo_for_output.clone()];

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
        detach_control_block.clone(),
        &seller_keypair,
        &prevouts,
    );

    // Create transfer data pointing to output 2 (buyer's address)
    let transfer_data = OpReturnData::PubKey(buyer_internal_key);
    let transfer_bytes = serialize(&transfer_data)?;

    // Use the chained TapScriptPair from compose_outputs as the commit script for the detach reveal
    let detach_tap_script_pair = compose_outputs.per_participant[0]
        .chained_tap_leaf_script
        .as_ref()
        .unwrap()
        .clone();

    let reveal_inputs = RevealInputs::builder()
        .commit_tx(attach_reveal_tx.clone())
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .participants(vec![
            RevealParticipantInputs::builder()
                .address(seller_address.clone())
                .x_only_public_key(seller_internal_key)
                .commit_outpoint(OutPoint {
                    txid: attach_reveal_tx.compute_txid(),
                    vout: 0,
                })
                .commit_prevout(attach_reveal_tx.output[0].clone())
                .commit_tap_leaf_script(detach_tap_script_pair)
                .build(),
        ])
        .op_return_data(transfer_bytes)
        .envelope(546)
        .build();
    let buyer_reveal_outputs = compose_reveal(reveal_inputs)?;

    // Create buyer's PSBT that combines with seller's PSBT
    let mut buyer_psbt =
        Psbt::deserialize(&hex::decode(&buyer_reveal_outputs.psbt_hex).unwrap()).unwrap();

    buyer_psbt.inputs[0] = seller_detach_psbt.inputs[0].clone(); // seller's signed input

    // Ensure seller is paid 600 sats at output index 0 to satisfy SIGHASH_SINGLE
    buyer_psbt
        .unsigned_tx
        .output
        .insert(0, seller_detach_psbt.unsigned_tx.output[0].clone());
    buyer_psbt.unsigned_tx.input.push(TxIn {
        previous_output: buyer_out_point,
        ..Default::default()
    });
    buyer_psbt.inputs.push(Input {
        witness_utxo: Some(buyer_utxo_for_output.clone()),
        tap_internal_key: Some(buyer_internal_key),
        ..Default::default()
    });
    // Opt-in RBF on buyer input (must be set before signing)
    buyer_psbt.unsigned_tx.input[1].sequence = Sequence::from_consensus(0xFFFFFFFD);

    // Add buyer change so the remainder of the buyer input is not treated as fee
    buyer_psbt.unsigned_tx.output.push(TxOut {
        value: buyer_utxo_for_output.value - Amount::from_sat(600) - Amount::from_sat(546),
        script_pubkey: buyer_address.script_pubkey(),
    });

    // Define the prevouts explicitly in the same order as inputs
    let prevouts = [
        attach_reveal_tx.output[0].clone(),
        buyer_utxo_for_output.clone(),
    ];

    test_utils::sign_buyer_side_psbt(&secp, &mut buyer_psbt, &buyer_keypair, &prevouts);

    let final_tx = buyer_psbt.extract_tx().expect("failed to extract tx");
    let attach_commit_tx_hex = hex::encode(serialize_tx(&attach_commit_tx));
    let raw_attach_reveal_tx_hex = hex::encode(serialize_tx(&attach_reveal_tx));
    let raw_psbt_hex = hex::encode(serialize_tx(&final_tx));

    Ok(SwapTestContext {
        attach_commit_tx_hex,
        raw_attach_reveal_tx_hex,
        raw_psbt_hex,
        final_tx,
    })
}

pub async fn test_swap_psbt(reg_tester: &mut RegTester) -> Result<()> {
    info!("test_swap_psbt");

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
    let params = SwapTestParams {
        seller_address,
        seller_keypair,
        seller_internal_key,
        seller_out_point,
        seller_utxo_for_output,
        buyer_address,
        buyer_keypair,
        buyer_internal_key,
        buyer_out_point,
        buyer_utxo_for_output,
    };
    let context = setup_swap_test(params).await?;

    let result = reg_tester
        .mempool_accept_result(&[
            context.attach_commit_tx_hex,
            context.raw_attach_reveal_tx_hex,
            context.raw_psbt_hex,
        ])
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
    let params = SwapTestParams {
        seller_address,
        seller_keypair,
        seller_internal_key,
        seller_out_point,
        seller_utxo_for_output,
        buyer_address,
        buyer_keypair,
        buyer_internal_key,
        buyer_out_point,
        buyer_utxo_for_output: buyer_utxo_for_output.clone(),
    };
    let context = setup_swap_test(params).await?;

    // Validate original flow (commit, reveal, original final)
    let result_original = reg_tester
        .mempool_accept_result(&[
            context.attach_commit_tx_hex.clone(),
            context.raw_attach_reveal_tx_hex.clone(),
            context.raw_psbt_hex.clone(),
        ])
        .await?;
    assert_eq!(
        result_original.len(),
        3,
        "Expected commit, reveal, and original final"
    );
    assert!(result_original[0].allowed, "Commit should be allowed");
    assert!(result_original[1].allowed, "Reveal should be allowed");
    assert!(
        result_original[2].allowed,
        "Original final tx should be allowed"
    );

    // Create malicious tx (Seller tries to redirect asset to themselves)
    let mut malicious_tx = context.final_tx.clone();

    // Maliciously change the OP_RETURN destination to seller's key
    let malicious_transfer_data = OpReturnData::PubKey(seller_internal_key);
    let malicious_transfer_bytes = serialize(&malicious_transfer_data)?;

    // make a new psbt with everything the same except

    // Verify index 1 is OP_RETURN (index 0 is payment to seller)
    assert!(malicious_tx.output[1].script_pubkey.is_op_return());

    // Overwrite the OP_RETURN
    malicious_tx.output[1].script_pubkey =
        ScriptBuf::new_op_return(PushBytesBuf::try_from(malicious_transfer_bytes)?);

    let malicious_hex = hex::encode(serialize_tx(&malicious_tx));
    // Replacement attempt (commit, reveal, malicious replacement)
    let result_malicious = reg_tester
        .mempool_accept_result(&[
            context.attach_commit_tx_hex.clone(),
            context.raw_attach_reveal_tx_hex.clone(),
            malicious_hex,
        ])
        .await?;
    assert_eq!(
        result_malicious.len(),
        3,
        "Expected commit, reveal, and replacement attempt"
    );
    assert!(result_malicious[0].allowed, "Commit should be allowed");
    assert!(result_malicious[1].allowed, "Reveal should be allowed");
    assert!(
        !result_malicious[2].allowed,
        "Malicious replacement should be rejected"
    );

    // Reject reason should indicate signature validation failed on input 1 (buyer's input)
    // because buyer's signature covers all outputs (SIGHASH_DEFAULT/ALL) and we changed output 1.
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
