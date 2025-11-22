use anyhow::Result;
use bitcoin::Amount;
use bitcoin::OutPoint;
use bitcoin::Sequence;
use bitcoin::TapSighashType;
use bitcoin::Transaction;
use bitcoin::TxIn;
use bitcoin::TxOut;
use bitcoin::XOnlyPublicKey;
use bitcoin::absolute::LockTime;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::opcodes::all::OP_ENDIF;
use bitcoin::opcodes::all::OP_IF;
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::script::Instruction;
use bitcoin::script::PushBytesBuf;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::transaction::Version;
use bitcoin::{
    ScriptBuf, Witness,
    address::{Address, KnownHrp},
    consensus::encode::serialize as serialize_tx,
    key::Secp256k1,
};

use indexer::op_return::OpReturnData;
use indexer::test_utils;
use indexer::witness_data::TokenBalance;
use indexer_types::{deserialize, serialize};
use testlib::RegTester;
use tracing::info;

pub async fn test_commit_reveal_ordinals(reg_tester: &mut RegTester) -> Result<()> {
    info!("test_commit_reveal_ordinals random keypair");
    let identity = reg_tester.identity().await?;
    let seller_address = identity.address;
    let seller_keypair = identity.keypair;
    let (seller_out_point, seller_utxo_for_output) = identity.next_funding_utxo;

    let secp = Secp256k1::new();

    // let random_keypair = Keypair::new(&secp, &mut rand::thread_rng());
    // let (random_xonly_pubkey, _parity) = random_keypair.x_only_public_key();
    let random_address = reg_tester.identity().await?;

    let random_keypair = random_address.keypair;
    let (random_xonly_pubkey, _parity) = random_keypair.x_only_public_key();

    let token_value = 1000;
    let token_balance = TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let serialized_token_balance = serialize(&token_balance)?;

    // Build the inscription script using the random key
    let reveal_script = test_utils::build_inscription(
        serialized_token_balance,
        test_utils::PublicKey::Taproot(&random_xonly_pubkey),
    )?;

    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, reveal_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, random_xonly_pubkey)
        .expect("Failed to finalize Taproot tree");

    let output_key = taproot_spend_info.output_key();

    let commit_address = Address::p2tr_tweaked(output_key, KnownHrp::Regtest);

    let mut commit_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: seller_out_point,
            script_sig: ScriptBuf::default(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![
            // Output containing the inscription
            TxOut {
                value: Amount::from_sat(5000),
                script_pubkey: commit_address.script_pubkey(),
            },
            // Change back to sender
            TxOut {
                value: seller_utxo_for_output.value
                    - Amount::from_sat(5000)
                    - Amount::from_sat(500), // full seller utxo amount - inscription output amount (5000) - 500 fee
                script_pubkey: seller_address.script_pubkey(),
            },
        ],
    };

    // Create the reveal transaction - simple spend back to sender's address
    let mut reveal_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: commit_tx.compute_txid(),
                vout: 0,
            },
            script_sig: ScriptBuf::default(),
            sequence: Sequence::MAX,
            witness: Witness::default(),
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(4500), // 5000 from commit input - 500 fee
                script_pubkey: seller_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: {
                    let mut op_return_script = ScriptBuf::new();
                    op_return_script.push_opcode(OP_RETURN);
                    op_return_script.push_slice(b"kon");

                    let reveal_data = OpReturnData::A { output_index: 0 };
                    op_return_script.push_slice(PushBytesBuf::try_from(serialize(&reveal_data)?)?);
                    op_return_script
                },
            },
        ],
    };
    // Sign the commit transaction
    test_utils::sign_key_spend(
        &secp,
        &mut commit_tx,
        &[TxOut {
            value: seller_utxo_for_output.value,
            script_pubkey: seller_address.script_pubkey(),
        }],
        &seller_keypair,
        0,
        Some(TapSighashType::All),
    )?;

    // Sign the reveal transaction using script path spending
    test_utils::sign_script_spend(
        &secp,
        &taproot_spend_info,
        &reveal_script,
        &mut reveal_tx,
        &[commit_tx.output[0].clone()],
        &random_keypair,
        0,
    )?;

    let raw_commit_tx_hex = hex::encode(serialize_tx(&commit_tx));
    let raw_reveal_tx_hex = hex::encode(serialize_tx(&reveal_tx));

    let result = reg_tester
        .mempool_accept_result(&[raw_commit_tx_hex, raw_reveal_tx_hex])
        .await?;
    // Assert both transactions are allowed
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Commit transaction was rejected");
    assert!(result[1].allowed, "Reveal transaction was rejected");

    // Verify the witness structure in the reveal transaction
    let witness = reveal_tx.input[0].witness.clone();
    assert_eq!(witness.len(), 3, "Witness should have exactly 3 elements");

    // Get the script from the witness
    let script_bytes = witness.to_vec()[1].clone();
    let script = ScriptBuf::from_bytes(script_bytes);

    // Parse the script instructions
    let instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;

    if let [
        Instruction::PushBytes(_key),
        Instruction::Op(op_checksig),
        Instruction::PushBytes(op_false),
        Instruction::Op(op_if),
        Instruction::PushBytes(kon),
        Instruction::PushBytes(op_0),
        Instruction::PushBytes(serialized_data),
        Instruction::Op(op_endif),
    ] = instructions.as_slice()
    {
        // Verify the opcodes
        assert!(op_false.is_empty(), "Expected empty push bytes");
        assert_eq!(*op_if, OP_IF, "Expected OP_IF");
        assert_eq!(kon.as_bytes(), b"kon", "Expected kon identifier");
        assert!(op_0.is_empty(), "Expected empty push bytes");
        assert_eq!(*op_endif, OP_ENDIF, "Expected OP_ENDIF");
        assert_eq!(*op_checksig, OP_CHECKSIG, "Expected OP_CHECKSIG");

        // Deserialize the token data
        let token_data: TokenBalance = deserialize(serialized_data.as_bytes())?;

        // Verify the token data
        assert_eq!(
            token_data, token_balance,
            "Token data in witness doesn't match expected value"
        );

        // Verify the key in the script matches our random key
        let key_from_bytes = XOnlyPublicKey::from_slice(_key.as_bytes())?;
        assert_eq!(key_from_bytes, random_xonly_pubkey);
    } else {
        panic!("Script structure doesn't match expected pattern");
    }

    Ok(())
}
