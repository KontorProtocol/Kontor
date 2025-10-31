use anyhow::Result;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{FeeRate, TapSighashType};
use bitcoin::{OutPoint, consensus::encode::serialize as serialize_tx, key::Secp256k1};
use indexer::api::compose::{RevealInputs, RevealParticipantInputs, compose, compose_reveal};

use bitcoin::Psbt;
use indexer::api::compose::{ComposeInputs, InstructionInputs};
use indexer::test_utils;
use indexer::witness_data::TokenBalance;

use testlib::*;

async fn test_taproot_transaction(reg_tester: &mut RegTester) -> Result<()> {
    let secp = Secp256k1::new();

    let identity = reg_tester.identity().await?;
    let seller_address = identity.address;
    let keypair = identity.keypair;
    let (internal_key, _parity) = keypair.x_only_public_key();
    let (out_point, utxo_for_output) = identity.next_funding_utxo;

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
            x_only_public_key: internal_key,
            funding_utxos: vec![(out_point, utxo_for_output.clone())],
            script_data: b"Hello, world!".to_vec(),
        }])
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .envelope(546)
        .chained_script_data(serialized_token_balance.clone())
        .build();

    let compose_outputs = compose(compose_params)?;

    let mut commit_tx = compose_outputs.commit_transaction;
    let tap_script = compose_outputs.per_participant[0].commit.tap_script.clone();
    let mut reveal_tx = compose_outputs.reveal_transaction;
    let chained_pair = compose_outputs.per_participant[0].chained.clone().unwrap();
    let chained_tap_script = chained_pair.tap_script.clone();

    let chained_reveal_tx = compose_reveal(
        RevealInputs::builder()
            .commit_txid(reveal_tx.compute_txid())
            .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
            .participants(vec![RevealParticipantInputs {
                address: seller_address.clone(),
                x_only_public_key: internal_key,
                commit_outpoint: OutPoint {
                    txid: reveal_tx.compute_txid(),
                    vout: 0,
                },
                commit_prevout: reveal_tx.output[0].clone(),
                commit_script_data: chained_pair.script_data_chunk.clone(),
            }])
            .envelope(546)
            .build(),
    )?;

    // 1. SIGN THE ORIGINAL COMMIT
    test_utils::sign_key_spend(
        &secp,
        &mut commit_tx,
        &[utxo_for_output],
        &keypair,
        0,
        Some(TapSighashType::All),
    )?;

    let spend_tx_prevouts = vec![commit_tx.output[0].clone()];

    // 2. SIGN THE REVEAL

    // sign the script_spend input for the reveal transaction
    let reveal_taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, internal_key)
        .expect("Failed to finalize Taproot tree");

    test_utils::sign_script_spend(
        &secp,
        &reveal_taproot_spend_info,
        &tap_script,
        &mut reveal_tx,
        &spend_tx_prevouts,
        &keypair,
        0,
    )?;

    let mut chained_reveal_tx = chained_reveal_tx.transaction;

    // 3. SIGN THE CHAINED REVEAL
    let reveal_tx_prevouts = vec![reveal_tx.output[0].clone()];

    // sign the script_spend input for the chained reveal transaction
    let chained_taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, chained_tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, internal_key)
        .expect("Failed to finalize Taproot tree");

    test_utils::sign_script_spend(
        &secp,
        &chained_taproot_spend_info,
        &chained_tap_script,
        &mut chained_reveal_tx,
        &reveal_tx_prevouts,
        &keypair,
        0,
    )?;

    let commit_tx_hex = hex::encode(serialize_tx(&commit_tx));
    let reveal_tx_hex = hex::encode(serialize_tx(&reveal_tx));
    let chained_reveal_tx_hex = hex::encode(serialize_tx(&chained_reveal_tx));

    let result = reg_tester
        .mempool_accept_result(&[commit_tx_hex, reveal_tx_hex, chained_reveal_tx_hex])
        .await?;

    assert_eq!(
        result.len(),
        3,
        "Expected exactly three transaction results"
    );
    assert!(result[0].allowed, "Commit transaction was rejected");
    assert!(result[1].allowed, "Reveal transaction was rejected");
    assert!(result[2].allowed, "Chained reveal transaction was rejected");

    Ok(())
}

async fn test_compose_end_to_end_mapping_and_reveal_psbt_hex_decodes(
    reg_tester: &mut RegTester,
) -> Result<()> {
    let (nodes, _secrets) =
        indexer::multi_psbt_test_utils::get_node_addresses(&mut reg_tester.clone()).await?;

    let mut instructions = Vec::new();
    for n in nodes.iter() {
        instructions.push(indexer::api::compose::InstructionInputs {
            address: n.address.clone(),
            x_only_public_key: n.internal_key,
            funding_utxos: vec![n.next_funding_utxo.clone()],
            script_data: b"hello-world".to_vec(),
        });
    }

    let params = ComposeInputs::builder()
        .instructions(instructions.clone())
        .fee_rate(bitcoin::FeeRate::from_sat_per_vb(2).unwrap())
        .envelope(600)
        .build();

    let outputs = compose(params)?;

    assert_eq!(outputs.per_participant.len(), instructions.len());
    for (i, p) in outputs.per_participant.iter().enumerate() {
        assert_eq!(p.index as usize, i);
        assert_eq!(p.address, instructions[i].address.to_string());
        assert_eq!(
            p.x_only_public_key,
            instructions[i].x_only_public_key.to_string()
        );
    }

    // Decode PSBTs
    let commit_psbt: Psbt = Psbt::deserialize(&hex::decode(&outputs.commit_psbt_hex)?)?;
    let reveal_psbt: Psbt = Psbt::deserialize(&hex::decode(&outputs.reveal_psbt_hex)?)?;

    // Txids match between PSBTs and returned transactions
    assert_eq!(
        commit_psbt.unsigned_tx.compute_txid(),
        outputs.commit_transaction.compute_txid()
    );
    assert_eq!(
        reveal_psbt.unsigned_tx.compute_txid(),
        outputs.reveal_transaction.compute_txid()
    );

    // Inputs/outputs counts are consistent
    assert_eq!(
        commit_psbt.inputs.len(),
        outputs.commit_transaction.input.len()
    );
    assert_eq!(
        commit_psbt.outputs.len(),
        outputs.commit_transaction.output.len()
    );
    assert_eq!(
        reveal_psbt.inputs.len(),
        outputs.reveal_transaction.input.len()
    );
    assert_eq!(
        reveal_psbt.outputs.len(),
        outputs.reveal_transaction.output.len()
    );

    // Required PSBT metadata is present
    assert!(commit_psbt.inputs.iter().all(|i| i.witness_utxo.is_some()));
    assert!(
        commit_psbt
            .inputs
            .iter()
            .all(|i| i.tap_internal_key.is_some())
    );
    assert!(reveal_psbt.inputs.iter().all(|i| i.witness_utxo.is_some()));
    assert!(
        reveal_psbt
            .inputs
            .iter()
            .all(|i| i.tap_internal_key.is_some())
    );
    assert!(
        reveal_psbt
            .inputs
            .iter()
            .all(|i| i.tap_merkle_root.is_some())
    );

    Ok(())
}

#[runtime(contracts_dir = "../../contracts", mode = "regtest")]
async fn test_compose_end_to_end_mapping_and_reveal_psbt_hex_decodes_regtest() -> Result<()> {
    test_taproot_transaction(&mut reg_tester.clone()).await?;
    test_compose_end_to_end_mapping_and_reveal_psbt_hex_decodes(&mut reg_tester.clone()).await?;
    Ok(())
}
