use anyhow::{Result, anyhow};
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF};
use bitcoin::opcodes::{OP_0, OP_FALSE};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{Address, FeeRate, KnownHrp, OutPoint, TapSighashType, TxOut};
use bitcoin::{consensus::encode::serialize as serialize_tx, key::Secp256k1};
use indexer::api::compose::{
    ComposeInputs, InstructionInputs, build_tap_script_and_script_address, compose, compose_reveal,
};
use indexer::test_utils;
use indexer::witness_data::{TokenBalance, WitnessData};
use indexer_types::{
    CommitSource, ComposeQuery, ContractAddress, Inst, InstKind, InstructionQuery, Insts,
    OpReturnEntry, Reveal, RevealInputs, RevealOutput, RevealParticipant,
    RevealParticipantInputs, RevealParticipantQuery, RevealQuery, SignerRef, serialize,
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

    let compose_outputs = reg_tester.compose_v2(reveal).await?;

    let mut commit_transaction = compose_outputs.commits[0].transaction.clone();

    let tap_script = compose_outputs.reveal.participants[0]
        .commit_tap_leaf_script
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

    let compose_outputs = reg_tester.compose_v2(reveal).await?;

    let mut commit_transaction = compose_outputs.commits[0].transaction.clone();

    let tap_script = compose_outputs.reveal.participants[0]
        .commit_tap_leaf_script
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

    // Under v2, the chained leaf isn't surfaced on the response — it's
    // an output of the reveal. Rebuild the leaf script locally from the
    // same Insts the ChainedEnvelope output committed to.
    let (chained_tap_script, _, _) = build_tap_script_and_script_address(
        internal_key,
        serialize(&Insts::single(chained_instructions.clone()))?,
    )?;

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

    match reg_tester.compose_v2(reveal).await {
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

    // duplicate address provided twice
    let query = ComposeQuery::builder()
        .instructions(vec![
            InstructionQuery {
                address: seller_address.to_string(),
                x_only_public_key: internal_key.to_string(),
                funding_utxo_ids: format!("{}:{}", out_point1.txid, out_point1.vout).to_string(),
                insts: Insts::single(instruction.clone()),
                chained_insts: None,
            },
            InstructionQuery {
                address: seller_address.to_string(),
                x_only_public_key: internal_key.to_string(),
                funding_utxo_ids: format!("{}:{}", out_point1.txid, out_point1.vout).to_string(),
                insts: Insts::single(instruction.clone()),
                chained_insts: None,
            },
        ])
        .sat_per_vbyte(2)
        .build();

    match reg_tester.compose(query).await {
        Ok(_) => panic!("Expected error, got success"),
        Err(e) => assert!(
            e.to_string()
                .contains("duplicate funding outpoint provided across participants")
        ),
    }

    // duplicate utxo within a participant
    let query2 = ComposeQuery::builder()
        .instructions(vec![InstructionQuery {
            address: seller_address.to_string(),
            x_only_public_key: internal_key.to_string(),
            funding_utxo_ids: format!(
                "{}:{},{}:{}",
                out_point1.txid, out_point1.vout, out_point1.txid, out_point1.vout
            ),
            insts: Insts::single(instruction),
            chained_insts: None,
        }])
        .sat_per_vbyte(2)
        .build();

    match reg_tester.compose(query2).await {
        Ok(_) => panic!("Expected error, got success"),
        Err(e) => assert!(
            e.to_string()
                .contains("duplicate funding outpoint provided for participant")
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

    // Oversized instruction
    let oversized_inst = Inst {
        gas_limit: 50_000,
        kind: InstKind::Publish {
            name: "oversized".to_string(),
            bytes: vec![0u8; 387 * 1024 + 1],
        },
    };
    let query = ComposeQuery::builder()
        .instructions(vec![InstructionQuery {
            address: seller_address.to_string(),
            x_only_public_key: internal_key.to_string(),
            funding_utxo_ids: format!("{}:{}", out_point.txid, out_point.vout).to_string(),
            insts: Insts::single(oversized_inst),
            chained_insts: None,
        }])
        .sat_per_vbyte(2)
        .build();

    match reg_tester.compose(query).await {
        Ok(_) => panic!("Expected error, got success"),
        Err(e) => assert!(e.to_string().contains("script data size invalid")),
    }

    // Oversized chained_instruction
    let chained_oversized_inst = Inst {
        gas_limit: 50_000,
        kind: InstKind::Publish {
            name: "chain-oversized".to_string(),
            bytes: vec![0u8; 387 * 1024 + 1],
        },
    };
    let query2 = ComposeQuery::builder()
        .instructions(vec![InstructionQuery {
            address: seller_address.to_string(),
            x_only_public_key: internal_key.to_string(),
            funding_utxo_ids: format!("{}:{}", out_point.txid, out_point.vout),
            insts: Insts::single(Inst {
                gas_limit: 50_000,
                kind: InstKind::Publish {
                    name: "chain-oversized".to_string(),
                    bytes: b"x".to_vec(),
                },
            }),
            chained_insts: Some(Insts::single(chained_oversized_inst)),
        }])
        .sat_per_vbyte(2)
        .build();

    match reg_tester.compose(query2).await {
        Ok(_) => panic!("Expected error, got success"),
        Err(e) => assert!(e.to_string().contains("chained script data size invalid")),
    }

    // Invalid fee rate (0)
    let query3 = ComposeQuery::builder()
        .instructions(vec![InstructionQuery {
            address: seller_address.to_string(),
            x_only_public_key: internal_key.to_string(),
            funding_utxo_ids: format!("{}:{}", out_point.txid, out_point.vout),
            insts: Insts::single(Inst {
                gas_limit: 50_000,
                kind: InstKind::Publish {
                    name: "fee-rate".to_string(),
                    bytes: b"x".to_vec(),
                },
            }),
            chained_insts: None,
        }])
        .sat_per_vbyte(0)
        .build();
    match reg_tester.compose(query3).await {
        Ok(_) => panic!("Expected error, got success"),
        Err(e) => assert!(e.to_string().contains("Invalid fee rate")),
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

    // Build compose with small script and one UTXO

    let compose_params = ComposeInputs::builder()
        .instructions(vec![InstructionInputs {
            address: seller_address.clone(),
            x_only_public_key: internal_key,
            funding_utxos: vec![(out_point, utxo_for_output.clone())],
            instruction: b"Hello, world!".to_vec(),
            chained_instruction: None,
        }])
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .envelope(546)
        .build();

    let compose_outputs = compose(compose_params)?;

    let mut commit_tx = compose_outputs.commit_transaction;
    let tap_script = compose_outputs.per_participant[0]
        .commit_tap_leaf_script
        .script
        .clone();
    // Initial reveal tx (unused after recomposition with OP_RETURN)
    let _initial_reveal_tx = compose_outputs.reveal_transaction;

    // Add OP_RETURN data (within 77 bytes total payload minus tag)
    let inputs = RevealInputs::builder()
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .participants(vec![
            RevealParticipantInputs::builder()
                .address(seller_address.clone())
                .x_only_public_key(internal_key)
                .commit_outpoint(OutPoint {
                    txid: commit_tx.compute_txid(),
                    vout: 0,
                })
                .commit_prevout(commit_tx.output[0].clone())
                .commit_tap_leaf_script(
                    compose_outputs.per_participant[0]
                        .commit_tap_leaf_script
                        .clone(),
                )
                .build(),
        ])
        .op_return_data(vec![0xAB; 10])
        .envelope(546)
        .build();

    let reveal_outputs = compose_reveal(inputs)?;

    // Sign commit
    test_utils::sign_key_spend(
        &secp,
        &mut commit_tx,
        &[utxo_for_output],
        &keypair,
        0,
        Some(TapSighashType::All),
    )?;

    // Sign reveal
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .map_err(|e| anyhow!("Failed to add leaf: {}", e))?
        .finalize(&secp, internal_key)
        .map_err(|e| anyhow!("Failed to finalize Taproot tree: {:?}", e))?;
    let mut reveal_tx_signed = reveal_outputs.transaction.clone();
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

    let query = ComposeQuery::builder()
        .instructions(vec![InstructionQuery {
            address: seller_address.to_string(),
            x_only_public_key: internal_key.to_string(),
            // Ensure a guaranteed-nonexistent txid in regtest
            funding_utxo_ids: "0000000000000000000000000000000000000000000000000000000000000001:0"
                .to_string(),
            insts: Insts::single(instruction),
            chained_insts: None,
        }])
        .sat_per_vbyte(2)
        .build();

    match reg_tester.compose(query).await {
        Ok(_) => panic!("Expected error, got success"),
        Err(e) => assert!(
            e.to_string()
                .contains("No such mempool or blockchain transaction")
        ),
    }
    Ok(())
}

pub async fn test_compose_invalid_address(reg_tester: &mut RegTester) -> Result<()> {
    // Use a non-taproot address (p2wpkh) to trigger Invalid address type
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

    let query = ComposeQuery::builder()
        .instructions(vec![InstructionQuery {
            address: seller_address.to_string(),
            x_only_public_key: internal_key.to_string(),
            funding_utxo_ids: format!("{}:{}", out_point.txid, out_point.vout),
            insts: Insts::single(instruction),
            chained_insts: None,
        }])
        .sat_per_vbyte(2)
        .build();
    match reg_tester.compose(query).await {
        Ok(_) => panic!("Expected error, got success"),
        Err(e) => assert!(e.to_string().contains("Invalid address type")),
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

    let query = ComposeQuery::builder()
        .instructions(vec![InstructionQuery {
            address: seller_address.to_string(),
            x_only_public_key: internal_key.to_string(),
            funding_utxo_ids: format!("{}:{}", out_point.txid, out_point.vout),
            insts: Insts::single(instruction),
            chained_insts: None,
        }])
        .sat_per_vbyte(4)
        .envelope(5_000_000_001)
        .build();

    match reg_tester.compose(query).await {
        Ok(_) => panic!("Expected error, got success"),
        Err(e) => assert!(
            e.to_string().contains("Insufficient inputs")
                || e.to_string().contains("Insufficient")
                || e.to_string().contains("Change amount is negative")
        ),
    }

    Ok(())
}

pub async fn test_compose_attach_and_detach(reg_tester: &mut RegTester) -> Result<()> {
    let secp = Secp256k1::new();

    let identity = reg_tester.identity().await?;
    let seller_address = identity.address;
    let keypair = identity.keypair;
    let (internal_key, _parity) = keypair.x_only_public_key();
    let (out_point, utxo_for_output) = identity.next_funding_utxo;

    let instruction = Inst {
        gas_limit: 50_000,
        kind: InstKind::Call {
            contract: ContractAddress {
                name: "attach".to_string(),
                height: 0,
                tx_index: 1,
            },
            expr: "attach(0)".to_string(), // token data??
        },
    };

    let chained_instructions = Inst {
        gas_limit: 50_000,
        kind: InstKind::Call {
            contract: ContractAddress {
                name: "detach".to_string(),
                height: 0,
                tx_index: 1,
            },
            expr: "detach()".to_string(),
        },
    };

    let query = ComposeQuery::builder()
        .instructions(vec![InstructionQuery {
            address: seller_address.to_string(),
            x_only_public_key: internal_key.to_string(),
            funding_utxo_ids: format!("{}:{}", out_point.txid, out_point.vout),
            insts: Insts::single(instruction.clone()),
            chained_insts: Some(Insts::single(chained_instructions.clone())),
        }])
        .sat_per_vbyte(2)
        .envelope(600)
        .build();

    let compose_outputs = reg_tester.compose(query).await?;

    let mut commit_transaction = compose_outputs.commit_transaction;

    let tap_script = compose_outputs.per_participant[0]
        .commit_tap_leaf_script
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

    let mut reveal_transaction = compose_outputs.reveal_transaction;

    let chained_tap_script = compose_outputs.per_participant[0]
        .chained_tap_leaf_script
        .as_ref()
        .unwrap()
        .script
        .clone();

    let derived_chained_instruction = Inst {
        gas_limit: 50_000,
        kind: InstKind::Call {
            contract: ContractAddress {
                name: "detach".to_string(),
                height: 0,
                tx_index: 1,
            },
            expr: "detach()".to_string(),
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

    // Second reveal (detach)
    let chained_script_data_bytes = serialize(&Insts::single(chained_instructions))?;

    let reveal_query = RevealQuery {
        sat_per_vbyte: Some(2),
        participants: vec![RevealParticipantQuery {
            address: seller_address.to_string(),
            x_only_public_key: internal_key.to_string(),
            commit_outpoint: bitcoin::OutPoint {
                txid: reveal_transaction.compute_txid(),
                vout: 0,
            },
            commit_prevout: reveal_transaction.output[0].clone(),
            commit_script_data: chained_script_data_bytes,
            chained_instruction: None,
        }],
        op_return_data: Some(serialize(&vec![OpReturnEntry {
            input_index: 0,
            recipient: SignerRef::XOnlyPubkey(internal_key),
        }])?),
        envelope: None,
    };

    let detach_outputs = reg_tester.compose_reveal(reveal_query).await?;
    let mut detach_transaction = detach_outputs.transaction;

    assert_eq!(detach_transaction.input.len(), 1);
    assert_eq!(
        detach_transaction.input[0].previous_output.txid,
        reveal_transaction.compute_txid()
    );

    test_utils::sign_script_spend(
        &secp,
        &chained_taproot_spend_info,
        &chained_tap_script,
        &mut detach_transaction,
        &[reveal_transaction.output[0].clone()],
        &keypair,
        0,
    )?;

    let detach_tx_hex = hex::encode(serialize_tx(&detach_transaction));

    let result = reg_tester
        .mempool_accept_result(&[commit_tx_hex, reveal_tx_hex, detach_tx_hex])
        .await?;

    assert_eq!(
        result.len(),
        3,
        "Expected exactly three transaction results"
    );
    assert!(result[0].allowed, "Commit transaction was rejected");
    assert!(result[1].allowed, "Reveal transaction was rejected");
    assert!(result[2].allowed, "Detach transaction was rejected");
    Ok(())
}
