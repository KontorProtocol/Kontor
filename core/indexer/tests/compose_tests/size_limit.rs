use anyhow::Result;
use bitcoin::FeeRate;

use bitcoin::taproot::TaprootBuilder;
use bitcoin::{consensus::encode::serialize as serialize_tx, key::Secp256k1, transaction::TxOut};
use indexer::api::compose::compose;
use indexer::api::compose::{ComposeInputs, InstructionInputs};
use indexer::test_utils;
use testlib::RegTester;
use tracing::info;

pub async fn test_compose_progressive_size_limit_testnet(reg_tester: &mut RegTester) -> Result<()> {
    info!("test_compose_progressive_size_limit_testnet");

    let secp = Secp256k1::new();

    let identity = reg_tester.identity().await?;
    let seller_address = identity.address;
    let keypair = identity.keypair;
    let (internal_key, _parity) = keypair.x_only_public_key();
    let available_utxos = reg_tester.fund_address(&seller_address, 2).await?;

    // Test progression: 10KB -> 20KB -> ... -> 390KB -> 397KB -> 400KB
    let mut current_size = 10_000;
    let increment = 10_000;

    while current_size <= 400_000 {
        let data = vec![0xFF; current_size];

        // Compose transaction
        let compose_params = ComposeInputs::builder()
            .instructions(vec![
                InstructionInputs::builder()
                    .address(seller_address.clone())
                    .x_only_public_key(internal_key)
                    .funding_utxos(available_utxos.clone())
                    .script_data(data)
                    .build(),
            ])
            .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
            .envelope(546)
            .build();
        let compose_outputs = compose(compose_params)?;

        let mut attach_tx = compose_outputs.commit_transaction;
        let mut spend_tx = compose_outputs.reveal_transaction;
        let tap_script = compose_outputs.per_participant[0]
            .commit_tap_leaf_script
            .tap_script
            .clone();

        // Sign commit inputs with correctly ordered prevouts matching the selected inputs
        let commit_prevouts: Vec<TxOut> = attach_tx
            .input
            .iter()
            .map(|txin| {
                let op = txin.previous_output;
                available_utxos
                    .iter()
                    .find(|(outpoint, _)| outpoint.txid == op.txid && outpoint.vout == op.vout)
                    .map(|(_, utxo)| utxo.clone())
                    .expect("matching prevout for commit input")
            })
            .collect();
        test_utils::sign_multiple_key_spend(&secp, &mut attach_tx, &commit_prevouts, &keypair)?;

        // Sign the script_spend input for the reveal transaction
        let spend_tx_prevouts = vec![attach_tx.output[0].clone()];
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

        // Test mempool acceptance
        let attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
        let spend_tx_hex = hex::encode(serialize_tx(&spend_tx));
        let result = reg_tester
            .mempool_accept_result(&[attach_tx_hex, spend_tx_hex])
            .await?;

        assert_eq!(result.len(), 2, "Expected exactly two transaction results");

        let commit_accepted = result[0].allowed;
        let reveal_accepted = result[1].allowed;
        let status = if commit_accepted && reveal_accepted {
            "accepted"
        } else {
            "rejected"
        };

        info!(
            "{}KB data {} - Commit TX: {} bytes, Reveal TX: {} bytes",
            current_size / 1000,
            status,
            serialize_tx(&attach_tx).len(),
            serialize_tx(&spend_tx).len(),
        );

        // Handle 400KB limit test - should be rejected due to tx-size
        if current_size == 400_000 {
            assert!(
                !result[1].allowed,
                "400KB reveal transaction should be rejected"
            );
            assert_eq!(
                result[1].reject_reason.as_deref(),
                Some("tx-size"),
                "400KB reveal transaction should be rejected due to tx-size, got: {:?}",
                result[1].reject_reason
            );
            assert!(
                !result[0].allowed,
                "400KB commit transaction should be rejected: {}",
                result[0].reject_reason.as_deref().unwrap_or("none")
            );
            info!("400KB correctly rejected due to Bitcoin's tx-size limit");
            break;
        }

        // For all other sizes, transactions should be accepted
        assert!(
            result[1].allowed,
            "{}KB reveal transaction was rejected: {}",
            current_size / 1000,
            result[1].reject_reason.as_deref().unwrap_or("none")
        );
        assert!(
            result[0].allowed,
            "{}KB commit transaction was rejected: {}",
            current_size / 1000,
            result[0].reject_reason.as_deref().unwrap_or("none")
        );

        // Determine next test size
        current_size = match current_size {
            390_000 => 397_150,            // Test near the limit after 390KB
            397_150 => 400_000,            // Test the exact limit after 397KB
            _ => current_size + increment, // Regular increment
        };
    }

    Ok(())
}
