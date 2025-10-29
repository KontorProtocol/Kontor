use anyhow::Result;
use bitcoin::{
    FeeRate, TapSighashType,
    consensus::encode::serialize as serialize_tx,
    key::Secp256k1,
    taproot::{LeafVersion, TaprootBuilder},
};
use indexer::{
    api::compose::{ComposeInputs, InstructionInputs, compose},
    test_utils,
    witness_data::TokenBalance,
};

use testlib::*;

#[runtime(contracts_dir = "../../contracts", mode = "regtest")]
async fn test_taproot_transaction_regtest() -> Result<()> {
    let identity = reg_tester.identity().await?;
    let seller_address = identity.address;
    let keypair = identity.keypair;
    let (internal_key, _parity) = keypair.x_only_public_key();
    let (out_point, utxo_for_output) = identity.next_funding_utxo; // Create token balance data
    let token_value = 500;
    let secp = Secp256k1::new();

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
            script_data: serialized_token_balance,
        }])
        .fee_rate(FeeRate::from_sat_per_vb(1).unwrap()) // Lower fee rate for regtest
        .envelope(546)
        .build();

    let compose_outputs = compose(compose_params)?;

    let mut attach_tx = compose_outputs.commit_transaction;
    let mut spend_tx = compose_outputs.reveal_transaction;
    let tap_script = compose_outputs.per_participant[0].commit.tap_script.clone();

    // Sign the attach transaction
    test_utils::sign_key_spend(
        &secp,
        &mut attach_tx,
        &[utxo_for_output],
        &keypair,
        0,
        Some(TapSighashType::All),
    )?;

    let spend_tx_prevouts = vec![attach_tx.output[0].clone()];

    // Sign the script_spend input for the spend transaction
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, internal_key)
        .expect("Failed to finalize Taproot tree");

    test_utils::sign_script_spend(
        &secp,
        &taproot_spend_info,
        &tap_script,
        &mut spend_tx,
        &spend_tx_prevouts,
        &keypair,
        0,
    )?;

    let attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let spend_tx_hex = hex::encode(serialize_tx(&spend_tx));

    let result = reg_tester
        .mempool_accept_result(&[attach_tx_hex, spend_tx_hex])
        .await?;

    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(
        result[0].allowed,
        "Attach transaction was rejected: {}",
        result[0].reject_reason.as_ref().unwrap_or(&"".to_string())
    );
    assert!(
        result[1].allowed,
        "Spend transaction was rejected: {}",
        result[1].reject_reason.as_ref().unwrap_or(&"".to_string())
    );

    // Verify witness structure
    let witness = spend_tx.input[0].witness.clone();
    assert_eq!(witness.len(), 3, "Witness should have exactly 3 elements");

    let signature = witness.to_vec()[0].clone();
    assert!(!signature.is_empty(), "Signature should not be empty");

    let script_bytes = witness.to_vec()[1].clone();
    assert_eq!(
        script_bytes,
        tap_script.as_bytes().to_vec(),
        "Script in witness doesn't match expected script"
    );

    let control_block_bytes = witness.to_vec()[2].clone();
    assert_eq!(
        control_block_bytes,
        taproot_spend_info
            .control_block(&(tap_script.clone(), LeafVersion::TapScript))
            .expect("Failed to create control block")
            .serialize(),
        "Control block in witness doesn't match expected control block"
    );

    Ok(())
}
