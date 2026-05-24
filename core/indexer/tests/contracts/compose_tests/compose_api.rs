use anyhow::{Result, anyhow};
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF};
use bitcoin::opcodes::{OP_0, OP_FALSE};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{Address, KnownHrp, OutPoint, TapSighashType, TxOut};
use bitcoin::{consensus::encode::serialize as serialize_tx, key::Secp256k1};
use indexer::test_utils;
use indexer::witness_data::{TokenBalance, WitnessData};
use indexer_types::{
    CommitSource, Inst, InstKind, Insts, Reveal, RevealOutput, RevealOutputInfo, RevealParticipant,
    serialize,
};
use testlib::RegTester;

pub async fn test_compose(reg_tester: &mut RegTester) -> Result<()> {
    let secp = Secp256k1::new();
    let identity = reg_tester.identity().await?;
    let seller_address = identity.address;
    let keypair = identity.keypair;
    let (internal_key, _parity) = keypair.x_only_public_key();
    let (out_point, utxo_for_output) = identity.next_funding_utxo;

    let token_data = WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    };

    let token_data_bytes = serialize(&token_data)?;
    let instruction = Inst {
        gas_limit: 50_000,
        kind: InstKind::Publish {
            name: "test".to_string(),
            bytes: token_data_bytes.clone(),
        },
    };

    // v2 Reveal: single Build participant w/ paired Change to seller.
    // (No chained envelope or extras — this is the simple "commit + reveal
    // that just runs the inst and returns change" case.)
    let reveal = Reveal::builder()
        .sat_per_vbyte(2)
        .participants(vec![
            RevealParticipant::builder()
                .x_only_public_key(internal_key.to_string())
                .commit_insts(Insts::single(instruction.clone()))
                .output(RevealOutput::change(&seller_address.script_pubkey()))
                .commit_source(CommitSource::build(&seller_address, [out_point]))
                .build(),
        ])
        .build();

    let compose_outputs = reg_tester.compose(reveal).await?;

    let mut commit_transaction = compose_outputs.commits[0].transaction.clone();

    let tap_script = compose_outputs.reveal.commit_tap_leaf_scripts[0]
        .script
        .clone();

    let derived_token_data = serialize(&Insts::single(instruction.clone()))?;

    let derived_tap_script = Builder::new()
        .push_slice(internal_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0)
        .push_slice(PushBytesBuf::try_from(derived_token_data)?)
        .push_opcode(OP_ENDIF)
        .into_script();

    assert_eq!(derived_tap_script, tap_script);

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .map_err(|e| anyhow!("Failed to add leaf: {}", e))?
        .finalize(&secp, internal_key)
        .map_err(|e| anyhow!("Failed to finalize Taproot tree: {:?}", e))?;
    let script_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), KnownHrp::Mainnet);

    assert_eq!(commit_transaction.input.len(), 1);
    assert_eq!(commit_transaction.output.len(), 2);
    assert_eq!(
        commit_transaction.output[0].script_pubkey,
        script_address.script_pubkey()
    );
    assert!(commit_transaction.output[0].value.to_sat() >= 330);

    let mut reveal_transaction = compose_outputs.reveal.transaction.clone();

    assert_eq!(reveal_transaction.input.len(), 1);
    assert_eq!(
        reveal_transaction.input[0].previous_output.txid,
        commit_transaction.compute_txid()
    );
    assert_eq!(reveal_transaction.input[0].previous_output.vout, 0);

    assert_eq!(reveal_transaction.output.len(), 1);
    assert_eq!(
        reveal_transaction.output[0].script_pubkey,
        seller_address.script_pubkey()
    );

    let commit_previous_output = TxOut {
        value: utxo_for_output.value,
        script_pubkey: seller_address.script_pubkey(),
    };

    test_utils::sign_key_spend(
        &secp,
        &mut commit_transaction,
        &[commit_previous_output],
        &keypair,
        0,
        Some(TapSighashType::All),
    )?;

    let reveal_previous_output = commit_transaction.output[0].clone();

    test_utils::sign_script_spend(
        &secp,
        &taproot_spend_info,
        &tap_script,
        &mut reveal_transaction,
        &[reveal_previous_output],
        &keypair,
        0,
    )?;

    let commit_tx_hex = hex::encode(serialize_tx(&commit_transaction));
    let reveal_tx_hex = hex::encode(serialize_tx(&reveal_transaction));

    let result = reg_tester
        .mempool_accept_result(&[commit_tx_hex, reveal_tx_hex])
        .await?;

    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Commit transaction was rejected");
    assert!(result[1].allowed, "Reveal transaction was rejected");
    Ok(())
}

pub async fn test_compose_all_fields(reg_tester: &mut RegTester) -> Result<()> {
    let secp = Secp256k1::new();

    let identity = reg_tester.identity().await?;
    let seller_address = identity.address;
    let keypair = identity.keypair;
    let (internal_key, _parity) = keypair.x_only_public_key();
    let (out_point, utxo_for_output) = identity.next_funding_utxo;

    let token_data = WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    };

    let token_data_bytes = serialize(&token_data)?;

    let instruction = Inst {
        gas_limit: 50_000,
        kind: InstKind::Publish {
            name: "test".to_string(),
            bytes: token_data_bytes.clone(),
        },
    };

    let chained_token_data_bytes = serialize(b"Hello, World!")?;

    let chained_instructions = Inst {
        gas_limit: 50_000,
        kind: InstKind::Publish {
            name: "chained".to_string(),
            bytes: chained_token_data_bytes.clone(),
        },
    };

    // v2: chained leaf is declared via ChainedEnvelope output in extras.
    let reveal = Reveal::builder()
        .sat_per_vbyte(2)
        .participants(vec![
            RevealParticipant::builder()
                .x_only_public_key(internal_key.to_string())
                .commit_insts(Insts::single(instruction.clone()))
                .commit_source(CommitSource::build(&seller_address, [out_point]))
                .build(),
        ])
        .extra_outputs(vec![
            RevealOutput::chained_envelope(
                Insts::single(chained_instructions.clone()),
                600,
                internal_key,
            ),
            RevealOutput::change(&seller_address.script_pubkey()),
        ])
        .build();

    let compose_outputs = reg_tester.compose(reveal).await?;

    let mut commit_transaction = compose_outputs.commits[0].transaction.clone();

    let tap_script = compose_outputs.reveal.commit_tap_leaf_scripts[0]
        .script
        .clone();

    let derived_token_data = serialize(&Insts::single(instruction.clone()))?;

    let derived_tap_script = Builder::new()
        .push_slice(internal_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0)
        .push_slice(PushBytesBuf::try_from(derived_token_data)?)
        .push_opcode(OP_ENDIF)
        .into_script();

    assert_eq!(derived_tap_script, tap_script);

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, derived_tap_script.clone())
        .map_err(|e| anyhow!("Failed to add leaf: {}", e))?
        .finalize(&secp, internal_key)
        .map_err(|e| anyhow!("Failed to finalize Taproot tree: {:?}", e))?;
    let script_address = Address::p2tr_tweaked(taproot_spend_info.output_key(), KnownHrp::Mainnet);

    assert_eq!(commit_transaction.input.len(), 1);
    assert_eq!(commit_transaction.output.len(), 2);
    assert!(commit_transaction.output[0].value.to_sat() >= 600);
    assert_eq!(
        commit_transaction.output[0].script_pubkey,
        script_address.script_pubkey()
    );
    if commit_transaction.output.len() > 1 {
        assert_eq!(
            commit_transaction.output[1].script_pubkey,
            seller_address.script_pubkey()
        );
    }

    let mut reveal_transaction = compose_outputs.reveal.transaction.clone();

    // The chained leaf lives in the reveal's output_info: position 0 of
    // the reveal tx is the ChainedEnvelope we declared in extra_outputs.
    let RevealOutputInfo::ChainedEnvelope { tap_leaf_script } =
        &compose_outputs.reveal.output_info[0]
    else {
        panic!("output 0 should be ChainedEnvelope");
    };
    let chained_tap_script = tap_leaf_script.script.clone();

    let derived_chained_tap_script = serialize(b"Hello, World!")?;

    let derived_chained_instruction = Inst {
        gas_limit: 50_000,
        kind: InstKind::Publish {
            name: "chained".to_string(),
            bytes: derived_chained_tap_script.clone(),
        },
    };

    let derived_chained_tap_script = Builder::new()
        .push_slice(internal_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0)
        .push_slice(PushBytesBuf::try_from(serialize(&Insts::single(
            derived_chained_instruction,
        ))?)?)
        .push_opcode(OP_ENDIF)
        .into_script();

    assert_eq!(derived_chained_tap_script, chained_tap_script);

    let chained_taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, derived_chained_tap_script.clone())
        .map_err(|e| anyhow!("Failed to add leaf: {}", e))?
        .finalize(&secp, internal_key)
        .map_err(|e| anyhow!("Failed to finalize Taproot tree: {:?}", e))?;
    let chained_script_address =
        Address::p2tr_tweaked(chained_taproot_spend_info.output_key(), KnownHrp::Mainnet);

    assert_eq!(reveal_transaction.input.len(), 1);
    assert_eq!(
        reveal_transaction.input[0].previous_output.txid,
        commit_transaction.compute_txid()
    );
    assert_eq!(reveal_transaction.input[0].previous_output.vout, 0);

    assert_eq!(reveal_transaction.output.len(), 2);
    assert_eq!(reveal_transaction.output[0].value.to_sat(), 600);
    assert_eq!(
        reveal_transaction.output[0].script_pubkey,
        chained_script_address.script_pubkey()
    );
    if reveal_transaction.output.len() > 1 {
        assert_eq!(
            reveal_transaction.output[1].script_pubkey,
            seller_address.script_pubkey()
        );
    }

    let commit_previous_output = TxOut {
        value: utxo_for_output.value,
        script_pubkey: seller_address.script_pubkey(),
    };

    test_utils::sign_key_spend(
        &secp,
        &mut commit_transaction,
        &[commit_previous_output],
        &keypair,
        0,
        Some(TapSighashType::All),
    )?;

    let reveal_previous_outputs = [commit_transaction.output[0].clone()];

    test_utils::sign_script_spend(
        &secp,
        &taproot_spend_info,
        &tap_script,
        &mut reveal_transaction,
        &reveal_previous_outputs,
        &keypair,
        0,
    )?;

    // Reveal only spends the script output now

    let commit_tx_hex = hex::encode(serialize_tx(&commit_transaction));
    let reveal_tx_hex = hex::encode(serialize_tx(&reveal_transaction));

    let result = reg_tester
        .mempool_accept_result(&[commit_tx_hex, reveal_tx_hex])
        .await?;

    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Commit transaction was rejected");
    assert!(result[1].allowed, "Reveal transaction was rejected");
    Ok(())
}

pub async fn test_compose_missing_params(reg_tester: &mut RegTester) -> Result<()> {
    // Empty participants is rejected by compose — there's nothing to
    // build a commit/reveal for. v2 rejects with "must have at least
    // one participant".
    let reveal = Reveal::builder()
        .sat_per_vbyte(2)
        .participants(vec![])
        .build();

    match reg_tester.compose(reveal).await {
        Ok(_) => panic!("Expected error, got success"),
        Err(e) => assert!(
            e.to_string().contains("at least one input"),
            "expected 'at least one input' error, got: {}",
            e
        ),
    }
    Ok(())
}

pub async fn test_compose_duplicate_address_and_duplicate_utxo(
    reg_tester: &mut RegTester,
) -> Result<()> {
    let identity = reg_tester.identity().await?;
    let seller_address = identity.address;
    let keypair = identity.keypair;
    let (internal_key, _parity) = keypair.x_only_public_key();
    let (out_point1, _utxo_for_output1) = identity.next_funding_utxo;

    let token_data = WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1,
            name: "T".to_string(),
        },
    };
    let token_data_bytes = serialize(&token_data)?;

    let instruction = Inst {
        gas_limit: 50_000,
        kind: InstKind::Publish {
            name: "test".to_string(),
            bytes: token_data_bytes.clone(),
        },
    };

    // Two Build participants both funded by the same outpoint.
    let reveal_cross = Reveal::builder()
        .sat_per_vbyte(2)
        .participants(vec![
            RevealParticipant::builder()
                .x_only_public_key(internal_key.to_string())
                .commit_insts(Insts::single(instruction.clone()))
                .commit_source(CommitSource::build(&seller_address, [out_point1]))
                .build(),
            RevealParticipant::builder()
                .x_only_public_key(internal_key.to_string())
                .commit_insts(Insts::single(instruction.clone()))
                .commit_source(CommitSource::build(&seller_address, [out_point1]))
                .build(),
        ])
        .build();

    match reg_tester.compose(reveal_cross).await {
        Ok(_) => panic!("Expected error, got success"),
        Err(e) => assert!(
            e.to_string()
                .contains("duplicate funding outpoint provided across participants"),
            "got: {e}"
        ),
    }

    // Same outpoint listed twice within a single Build participant.
    let reveal_within = Reveal::builder()
        .sat_per_vbyte(2)
        .participants(vec![
            RevealParticipant::builder()
                .x_only_public_key(internal_key.to_string())
                .commit_insts(Insts::single(instruction))
                .commit_source(CommitSource::build(
                    &seller_address,
                    [out_point1, out_point1],
                ))
                .build(),
        ])
        .build();

    match reg_tester.compose(reveal_within).await {
        Ok(_) => panic!("Expected error, got success"),
        Err(e) => assert!(
            e.to_string()
                .contains("duplicate funding outpoint provided for participant"),
            "got: {e}"
        ),
    }
    Ok(())
}

pub async fn test_compose_param_bounds_and_fee_rate(reg_tester: &mut RegTester) -> Result<()> {
    let identity = reg_tester.identity().await?;
    let seller_address = identity.address;
    let keypair = identity.keypair;
    let (internal_key, _parity) = keypair.x_only_public_key();
    let (out_point, _utxo_for_output) = identity.next_funding_utxo;

    // Oversized Build participant inst
    let oversized_inst = Inst {
        gas_limit: 50_000,
        kind: InstKind::Publish {
            name: "oversized".to_string(),
            bytes: vec![0u8; 387 * 1024 + 1],
        },
    };
    let reveal = Reveal::builder()
        .sat_per_vbyte(2)
        .participants(vec![
            RevealParticipant::builder()
                .x_only_public_key(internal_key.to_string())
                .commit_insts(Insts::single(oversized_inst))
                .commit_source(CommitSource::build(&seller_address, [out_point]))
                .build(),
        ])
        .build();

    match reg_tester.compose(reveal).await {
        Ok(_) => panic!("Expected error, got success"),
        Err(e) => assert!(
            e.to_string()
                .contains("Build participant leaf data size invalid"),
            "got: {e}"
        ),
    }

    // Oversized ChainedEnvelope inst
    let chained_oversized_inst = Inst {
        gas_limit: 50_000,
        kind: InstKind::Publish {
            name: "chain-oversized".to_string(),
            bytes: vec![0u8; 387 * 1024 + 1],
        },
    };
    let small_inst = Inst {
        gas_limit: 50_000,
        kind: InstKind::Publish {
            name: "chain-oversized".to_string(),
            bytes: b"x".to_vec(),
        },
    };
    let reveal2 = Reveal::builder()
        .sat_per_vbyte(2)
        .participants(vec![
            RevealParticipant::builder()
                .x_only_public_key(internal_key.to_string())
                .commit_insts(Insts::single(small_inst))
                .commit_source(CommitSource::build(&seller_address, [out_point]))
                .build(),
        ])
        .extra_outputs(vec![RevealOutput::chained_envelope(
            Insts::single(chained_oversized_inst),
            600,
            internal_key,
        )])
        .build();

    match reg_tester.compose(reveal2).await {
        Ok(_) => panic!("Expected error, got success"),
        Err(e) => assert!(
            e.to_string()
                .contains("ChainedEnvelope leaf data size invalid"),
            "got: {e}"
        ),
    }

    // Invalid fee rate (0)
    let fee_inst = Inst {
        gas_limit: 50_000,
        kind: InstKind::Publish {
            name: "fee-rate".to_string(),
            bytes: b"x".to_vec(),
        },
    };
    let reveal3 = Reveal::builder()
        .sat_per_vbyte(0)
        .participants(vec![
            RevealParticipant::builder()
                .x_only_public_key(internal_key.to_string())
                .commit_insts(Insts::single(fee_inst))
                .commit_source(CommitSource::build(&seller_address, [out_point]))
                .build(),
        ])
        .build();
    match reg_tester.compose(reveal3).await {
        Ok(_) => panic!("Expected error, got success"),
        Err(e) => assert!(e.to_string().contains("Invalid fee rate"), "got: {e}"),
    }

    Ok(())
}

pub async fn test_reveal_with_op_return_mempool_accept(reg_tester: &mut RegTester) -> Result<()> {
    let identity = reg_tester.identity().await?;
    let seller_address = identity.address;
    let keypair = identity.keypair;
    let (internal_key, _parity) = keypair.x_only_public_key();
    let (out_point, utxo_for_output) = identity.next_funding_utxo;

    let secp = Secp256k1::new();

    let instruction = Inst {
        gas_limit: 50_000,
        kind: InstKind::Publish {
            name: "op-return".to_string(),
            bytes: b"Hello, world!".to_vec(),
        },
    };

    let reveal = Reveal::builder()
        .sat_per_vbyte(2)
        .participants(vec![
            RevealParticipant::builder()
                .x_only_public_key(internal_key.to_string())
                .commit_insts(Insts::single(instruction))
                .commit_source(CommitSource::build(&seller_address, [out_point]))
                .build(),
        ])
        .extra_outputs(vec![
            RevealOutput::op_return(vec![0xAB; 10]),
            RevealOutput::change(&seller_address.script_pubkey()),
        ])
        .build();

    let compose_outputs = reg_tester.compose(reveal).await?;

    let mut commit_tx = compose_outputs.commits[0].transaction.clone();
    let mut reveal_tx_signed = compose_outputs.reveal.transaction.clone();
    let tap_script = compose_outputs.reveal.commit_tap_leaf_scripts[0]
        .script
        .clone();

    let commit_prevout = TxOut {
        value: utxo_for_output.value,
        script_pubkey: seller_address.script_pubkey(),
    };
    test_utils::sign_key_spend(
        &secp,
        &mut commit_tx,
        &[commit_prevout],
        &keypair,
        0,
        Some(TapSighashType::All),
    )?;

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .map_err(|e| anyhow!("Failed to add leaf: {}", e))?
        .finalize(&secp, internal_key)
        .map_err(|e| anyhow!("Failed to finalize Taproot tree: {:?}", e))?;
    test_utils::sign_script_spend(
        &secp,
        &taproot_spend_info,
        &tap_script,
        &mut reveal_tx_signed,
        &[commit_tx.output[0].clone()],
        &keypair,
        0,
    )?;

    let commit_tx_hex = hex::encode(serialize_tx(&commit_tx));
    let reveal_tx_hex = hex::encode(serialize_tx(&reveal_tx_signed));

    let result = reg_tester
        .mempool_accept_result(&[commit_tx_hex, reveal_tx_hex])
        .await?;
    assert_eq!(result.len(), 2);
    assert!(result[0].allowed);
    assert!(result[1].allowed);

    Ok(())
}

pub async fn test_compose_nonexistent_utxo(reg_tester: &mut RegTester) -> Result<()> {
    let identity = reg_tester.identity().await?;
    let seller_address = identity.address;
    let keypair = identity.keypair;
    let (internal_key, _parity) = keypair.x_only_public_key();

    let token_data = WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    };
    let token_data_bytes = serialize(&token_data)?;

    let instruction = Inst {
        gas_limit: 50_000,
        kind: InstKind::Publish {
            name: "nonexistent-utxo".to_string(),
            bytes: token_data_bytes,
        },
    };

    // Guaranteed-nonexistent outpoint in regtest
    let nonexistent_outpoint = OutPoint {
        txid: "0000000000000000000000000000000000000000000000000000000000000001"
            .parse()
            .unwrap(),
        vout: 0,
    };

    let reveal = Reveal::builder()
        .sat_per_vbyte(2)
        .participants(vec![
            RevealParticipant::builder()
                .x_only_public_key(internal_key.to_string())
                .commit_insts(Insts::single(instruction))
                .commit_source(CommitSource::build(&seller_address, [nonexistent_outpoint]))
                .build(),
        ])
        .build();

    match reg_tester.compose(reveal).await {
        Ok(_) => panic!("Expected error, got success"),
        Err(e) => assert!(
            e.to_string()
                .contains("No such mempool or blockchain transaction"),
            "got: {e}"
        ),
    }
    Ok(())
}

pub async fn test_compose_invalid_address(reg_tester: &mut RegTester) -> Result<()> {
    // Use a non-taproot address (p2wpkh) to trigger the P2TR-only check
    let secp = bitcoin::key::Secp256k1::new();
    let keypair = bitcoin::key::Keypair::new(&secp, &mut bitcoin::key::rand::thread_rng());
    let (internal_key, _parity) = keypair.x_only_public_key();
    let secret_key = bitcoin::secp256k1::SecretKey::new(&mut bitcoin::key::rand::thread_rng());
    let private_key = bitcoin::PrivateKey::new(secret_key, bitcoin::Network::Regtest);
    let public_key = bitcoin::key::PublicKey::from_private_key(&secp, &private_key);
    let compressed = bitcoin::CompressedPublicKey(public_key.inner);
    let seller_address = bitcoin::Address::p2wpkh(&compressed, bitcoin::Network::Regtest);
    let out_point = bitcoin::OutPoint::null();

    let token_data = WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    };
    let token_data_bytes = serialize(&token_data)?;
    let instruction = Inst {
        gas_limit: 50_000,
        kind: InstKind::Publish {
            name: "invalid-address".to_string(),
            bytes: token_data_bytes,
        },
    };

    let reveal = Reveal::builder()
        .sat_per_vbyte(2)
        .participants(vec![
            RevealParticipant::builder()
                .x_only_public_key(internal_key.to_string())
                .commit_insts(Insts::single(instruction))
                .commit_source(CommitSource::build(&seller_address, [out_point]))
                .build(),
        ])
        .build();

    match reg_tester.compose(reveal).await {
        Ok(_) => panic!("Expected error, got success"),
        Err(e) => assert!(
            e.to_string()
                .contains("Build participant address must be P2TR"),
            "got: {e}"
        ),
    }
    Ok(())
}

pub async fn test_compose_insufficient_funds(reg_tester: &mut RegTester) -> Result<()> {
    let identity = reg_tester.identity().await?;
    let seller_address = identity.address;
    let keypair = identity.keypair;
    let (internal_key, _parity) = keypair.x_only_public_key();
    let (out_point, _utxo_for_output) = identity.next_funding_utxo;

    let token_data = WitnessData::Attach {
        output_index: 0,
        token_balance: TokenBalance {
            value: 1000,
            name: "Test Token".to_string(),
        },
    };
    let token_data_bytes = serialize(&token_data)?;
    let instruction = Inst {
        gas_limit: 50_000,
        kind: InstKind::Publish {
            name: "insufficient-funds".to_string(),
            bytes: token_data_bytes,
        },
    };

    // A Fixed output far exceeding any single regtest funding UTXO drives
    // the Build participant to fail UTXO selection with insufficient funds.
    let reveal = Reveal::builder()
        .sat_per_vbyte(4)
        .participants(vec![
            RevealParticipant::builder()
                .x_only_public_key(internal_key.to_string())
                .commit_insts(Insts::single(instruction))
                .commit_source(CommitSource::build(&seller_address, [out_point]))
                .build(),
        ])
        .extra_outputs(vec![RevealOutput::fixed(
            &seller_address.script_pubkey(),
            5_000_000_001,
        )])
        .build();

    match reg_tester.compose(reveal).await {
        Ok(_) => panic!("Expected error, got success"),
        Err(e) => assert!(e.to_string().contains("Insufficient"), "got: {e}"),
    }

    Ok(())
}
