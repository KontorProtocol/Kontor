use anyhow::Result;
use bitcoin::Psbt;
use bitcoin::TapLeafHash;
use bitcoin::TapSighashType;
use bitcoin::XOnlyPublicKey;
use bitcoin::bip32::Xpriv;
use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::opcodes::OP_FALSE;
use bitcoin::opcodes::all::OP_CHECKSIG;
use bitcoin::opcodes::all::OP_ENDIF;
use bitcoin::opcodes::all::OP_IF;
use bitcoin::opcodes::all::OP_PUSHNUM_1;
use bitcoin::psbt::Input;
use bitcoin::psbt::Output;
use bitcoin::script::Builder;
use bitcoin::script::Instruction;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::Keypair;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::ControlBlock;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::Signature;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::taproot::TaprootSpendInfo;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Txid, Witness,
    absolute::LockTime,
    address::{Address, KnownHrp},
    consensus::encode::serialize as serialize_tx,
    key::Secp256k1,
    secp256k1::{self},
    transaction::{Transaction, TxIn, TxOut, Version},
};
use clap::Parser;
use kontor::config::TestConfig;
use kontor::test_utils;
use kontor::witness_data::WitnessData;
use kontor::{bitcoin_client::Client, config::Config};
use std::str::FromStr;

#[tokio::test]
async fn test_taproot_transaction() -> Result<()> {
    let client = Client::new_from_config(Config::try_parse()?)?;
    let config = TestConfig::try_parse()?;

    let secp = Secp256k1::new();

    let (seller_address, seller_child_key) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 0)?;

    let (buyer_address, buyer_child_key) =
        test_utils::generate_taproot_address_from_mnemonic(&secp, &config.taproot_key_path, 1)?;

    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    let token_value = 1000;
    let token_balance = WitnessData::TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let mut serialized_token_balance = Vec::new();
    ciborium::into_writer(&token_balance, &mut serialized_token_balance).unwrap();

    let tap_script = build_tapscript(serialized_token_balance, &internal_key)?;

    // Build the Taproot tree with the script
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .expect("Failed to add leaf")
        .finalize(&secp, internal_key)
        .expect("Failed to finalize Taproot tree");

    // Get the output key which commits to both the internal key and the script tree
    let output_key = taproot_spend_info.output_key();

    // Create the address from the output key
    let script_spendable_address = Address::p2tr_tweaked(output_key, KnownHrp::Mainnet);

    let attach_tx = test_utils::build_signed_taproot_attach_tx(
        &secp,
        &keypair,
        &seller_address,
        &script_spendable_address,
    )?;

    let (mut seller_psbt, signature, control_block) = build_seller_psbt_and_sig(
        &secp,
        &keypair,
        &seller_address,
        &attach_tx,
        &internal_key,
        &taproot_spend_info,
        &tap_script,
    )?;

    let mut witness = Witness::new();
    witness.push(signature.to_vec()); // Signature -- test wihtout checksig
    witness.push(tap_script.as_bytes()); // Script - change here - witness script mismatch
    witness.push(control_block.serialize()); // Control block
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    let buyer_psbt = build_signed_buyer_psbt(
        &secp,
        &buyer_child_key,
        &buyer_address,
        &seller_address,
        &attach_tx,
        &script_spendable_address,
        &seller_psbt,
    )?;

    // Extract the transaction (no finalize needed since we set all witnesses manually)
    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));

    let result = client
        .test_mempool_accept(&[raw_attach_tx_hex, raw_swap_tx_hex])
        .await?;

    // Assert both transactions are allowed
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(result[1].allowed, "Swap transaction was rejected");

    // After your assertions on witness length
    let witness = final_tx.input[0].witness.clone();
    assert_eq!(witness.len(), 3, "Witness should have exactly 3 elements");

    // Get the script from the witness
    let script_bytes = witness.to_vec()[1].clone();
    let script = ScriptBuf::from_bytes(script_bytes);

    // Parse the script instructions
    let instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;

    if let [
        Instruction::PushBytes(empty),
        Instruction::Op(op_if),
        Instruction::PushBytes(kntr),
        Instruction::Op(op_pushnum_1),
        Instruction::PushBytes(serialized_data),
        Instruction::Op(op_endif),
        Instruction::PushBytes(_key),
        Instruction::Op(op_checksig),
    ] = instructions.as_slice()
    {
        // Verify the opcodes
        assert_eq!(*op_if, OP_IF, "Expected OP_IF");
        assert_eq!(*op_pushnum_1, OP_PUSHNUM_1, "Expected OP_PUSHNUM_1");
        assert_eq!(*op_endif, OP_ENDIF, "Expected OP_ENDIF");
        assert_eq!(*op_checksig, OP_CHECKSIG, "Expected OP_CHECKSIG");

        // Verify the KNTR identifier
        assert_eq!(kntr.as_bytes(), b"KNTR", "Expected KNTR identifier");

        // The first push is empty instead of OP_FALSE
        assert!(empty.is_empty(), "Expected empty push bytes");

        // Deserialize the token data
        let token_data: WitnessData = ciborium::from_reader(serialized_data.as_bytes())?;

        // Verify the token data
        assert_eq!(
            token_data, token_balance,
            "Token data in witness doesn't match expected value"
        );

        println!("Successfully extracted token data: {:?}", token_data);
    } else {
        // Print the actual instructions for debugging
        println!("Script instructions didn't match expected pattern:");
        for (i, instr) in instructions.iter().enumerate() {
            println!("  {}: {:?}", i, instr);
        }
        panic!("Script structure doesn't match expected pattern");
    }

    Ok(())
}

fn build_seller_psbt_and_sig(
    secp: &Secp256k1<secp256k1::All>,
    keypair: &Keypair,
    seller_address: &Address,
    attach_tx: &Transaction,
    seller_internal_key: &XOnlyPublicKey,
    taproot_spend_info: &TaprootSpendInfo,
    tap_script: &ScriptBuf,
) -> Result<(Psbt, Signature, ControlBlock)> {
    let seller_internal_key = *seller_internal_key;

    // Create the control block for the script
    let control_block = taproot_spend_info
        .control_block(&(tap_script.clone(), LeafVersion::TapScript))
        .expect("Failed to create control block");

    // Create seller's PSBT for atomic swap
    let mut seller_psbt = Psbt {
        unsigned_tx: Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: attach_tx.compute_txid(),
                    vout: 0,
                },
                script_sig: ScriptBuf::default(),
                sequence: Sequence::MAX,
                witness: Witness::default(),
            }],
            output: vec![TxOut {
                value: Amount::from_sat(600),
                script_pubkey: seller_address.script_pubkey(),
            }],
        },
        inputs: vec![Input {
            witness_utxo: Some(attach_tx.output[0].clone()),
            tap_internal_key: Some(seller_internal_key),
            tap_merkle_root: taproot_spend_info.merkle_root(),
            tap_scripts: {
                let mut scripts = std::collections::BTreeMap::new();
                scripts.insert(
                    control_block.clone(),
                    (tap_script.clone(), LeafVersion::TapScript),
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

    // Sign the PSBT with seller's key for script path spending
    let sighash = SighashCache::new(&seller_psbt.unsigned_tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::All(&[attach_tx.output[0].clone()]),
            TapLeafHash::from_script(tap_script, LeafVersion::TapScript),
            TapSighashType::SinglePlusAnyoneCanPay,
        )
        .expect("Failed to create sighash");

    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, keypair);
    let signature = bitcoin::taproot::Signature {
        signature,
        sighash_type: TapSighashType::SinglePlusAnyoneCanPay,
    };

    // Store the signature in the PSBT -- This is not necessary here, but will be used to store the sig in the market
    seller_psbt.inputs[0].tap_script_sigs.insert(
        (
            seller_internal_key,
            TapLeafHash::from_script(tap_script, LeafVersion::TapScript),
        ),
        signature,
    );

    Ok((seller_psbt, signature, control_block))
}

fn build_signed_buyer_psbt(
    secp: &Secp256k1<secp256k1::All>,
    buyer_child_key: &Xpriv,
    buyer_address: &Address,
    seller_address: &Address,
    attach_tx: &Transaction,
    script_spendable_address: &Address,
    seller_psbt: &Psbt,
) -> Result<Psbt> {
    // Create buyer's keypair
    let buyer_keypair = Keypair::from_secret_key(secp, &buyer_child_key.private_key);
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
                        txid: attach_tx.compute_txid(),
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
                // Buyer's address to receive the token
                TxOut {
                    value: Amount::from_sat(546), // Minimum dust limit for the token
                    script_pubkey: buyer_address.script_pubkey(),
                },
                // Buyer's change
                TxOut {
                    value: Amount::from_sat(8854), // 10000 - 600 - 546
                    script_pubkey: buyer_address.script_pubkey(),
                },
            ],
        },
        inputs: vec![
            // Seller's input (copy from seller's PSBT)
            seller_psbt.inputs[0].clone(),
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
        outputs: vec![
            Output::default(),
            Output::default(),
            Output::default(),
            Output::default(),
        ],
        version: 0,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
    };

    // Sign the buyer's input (key path spending)
    let sighash = {
        // Create a new SighashCache for the transaction
        let mut sighasher = SighashCache::new(&buyer_psbt.unsigned_tx);

        // Define the prevouts explicitly in the same order as inputs
        let prevouts = [
            TxOut {
                value: Amount::from_sat(1000), // The value of the first input (unspendable output)
                script_pubkey: script_spendable_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(10000), // The value of the second input (buyer's UTXO)
                script_pubkey: buyer_address.script_pubkey(),
            },
        ];

        // Calculate the sighash for key path spending
        let sighash = sighasher
            .taproot_key_spend_signature_hash(
                1, // Buyer's input index (back to 1)
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )
            .expect("Failed to create sighash");

        sighash
    };

    // Sign with the buyer's tweaked key
    let msg = Message::from_digest(sighash.to_byte_array());

    // Create the tweaked keypair
    let buyer_tweaked = buyer_keypair.tap_tweak(secp, None);
    // Sign with the tweaked keypair since we're doing key path spending
    let buyer_signature = secp.sign_schnorr(&msg, &buyer_tweaked.to_inner());

    let buyer_signature = bitcoin::taproot::Signature {
        signature: buyer_signature,
        sighash_type: TapSighashType::Default,
    };

    // Add the signature to the PSBT
    buyer_psbt.inputs[1].tap_key_sig = Some(buyer_signature);

    // Construct the witness stack for key path spending
    let mut buyer_witness = Witness::new();
    buyer_witness.push(buyer_signature.to_vec());
    buyer_psbt.inputs[1].final_script_witness = Some(buyer_witness);

    Ok(buyer_psbt)
}

fn build_tapscript(
    serialized_token_balance: Vec<u8>,
    internal_key: &XOnlyPublicKey,
) -> Result<ScriptBuf> {
    let tap_script = Builder::new()
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"KNTR")
        .push_opcode(OP_PUSHNUM_1)
        .push_slice(PushBytesBuf::try_from(serialized_token_balance)?)
        .push_opcode(OP_ENDIF)
        .push_x_only_key(internal_key)
        .push_opcode(OP_CHECKSIG)
        .into_script();

    Ok(tap_script)
}
