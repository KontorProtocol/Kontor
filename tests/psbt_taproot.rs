use anyhow::Result;
use bip39::Mnemonic;
use bitcoin::Network;
use bitcoin::PrivateKey;
use bitcoin::Psbt;
use bitcoin::TapLeafHash;
use bitcoin::TapSighashType;
use bitcoin::bip32::{DerivationPath, Xpriv};
use bitcoin::hashes::{Hash, sha256};
use bitcoin::key::{PublicKey as BitcoinPublicKey, TapTweak, TweakedKeypair};
use bitcoin::opcodes::all::OP_RETURN;
use bitcoin::psbt::Input;
use bitcoin::psbt::Output;
use bitcoin::script::PushBytesBuf;
use bitcoin::secp256k1::Keypair;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::Prevouts;
use bitcoin::sighash::SighashCache;
use bitcoin::taproot::LeafVersion;
use bitcoin::taproot::TaprootBuilder;
use bitcoin::{
    Amount, OutPoint, ScriptBuf, Sequence, Txid, Witness,
    absolute::LockTime,
    address::{Address, KnownHrp},
    consensus::encode::serialize as serialize_tx,
    key::Secp256k1,
    opcodes::all::{OP_CHECKSIG, OP_EQUALVERIFY, OP_SHA256},
    script::Builder,
    secp256k1::{self},
    transaction::{Transaction, TxIn, TxOut, Version},
};
use clap::Parser;
use kontor::witness_data::WitnessData;
use kontor::{bitcoin_client::Client, config::Config, op_return::OpReturnData};
use std::fs;
use std::path::Path;
use std::str::FromStr;

#[tokio::test]
async fn test_taproot_transaction() -> Result<()> {
    let config = Config::try_parse()?;
    let client = Client::new_from_config(config.clone())?;

    let secp = Secp256k1::new();

    let (seller_address, seller_child_key) =
        generate_address_from_mnemonic(&secp, &config.taproot_key_path, 0)?;

    let (buyer_address, _buyer_child_key) =
        generate_address_from_mnemonic(&secp, &config.taproot_key_path, 1)?;

    let keypair = Keypair::from_secret_key(&secp, &seller_child_key.private_key);
    let (internal_key, _parity) = keypair.x_only_public_key();

    // Create token balance data
    let token_value = 1000;
    let token_balance = WitnessData::TokenBalance {
        value: token_value,
        name: "token_name".to_string(),
    };

    let serialized_token_balance = rmp_serde::to_vec(&token_balance).unwrap();

    // Create the tapscript with x-only public key
    let tap_script = Builder::new()
        .push_slice(b"KNTR")
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_SHA256)
        .push_slice(sha256::Hash::hash(&serialized_token_balance).as_byte_array())
        .push_opcode(OP_EQUALVERIFY)
        .push_x_only_key(&internal_key)
        // .push_slice(internal_key.serialize()) // Use x-only public key  //.push_x_only_public_key(entire keypair!!!!) look at implementation
        .push_opcode(OP_CHECKSIG)
        .into_script();

    // Build the Taproot tree with the script
    let taproot_spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone()) // Add script at depth 0
        .expect("Failed to add leaf")
        .finalize(&secp, internal_key) // does this need to be the whole keypair then?
        .expect("Failed to finalize Taproot tree");

    // Get the output key which commits to both the internal key and the script tree
    let output_key = taproot_spend_info.output_key();

    // Create the address from the output key
    let script_spendable_address = Address::p2tr_tweaked(output_key, KnownHrp::Mainnet);

    let mut op_return_script = ScriptBuf::new();
    op_return_script.push_opcode(OP_RETURN);
    op_return_script.push_slice(b"KNTR");

    let op_return_data = OpReturnData::Attach { output_index: 0 };
    let s = rmp_serde::to_vec(&op_return_data).unwrap();
    op_return_script.push_slice(PushBytesBuf::try_from(s)?);

    // Create the transaction
    let mut attach_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint {
                txid: Txid::from_str(
                    "dd3d962f95741f2f5c3b87d6395c325baa75c4f3f04c7652e258f6005d70f3e8",
                )?,
                vout: 0,
            }, // The output we are spending
            script_sig: ScriptBuf::default(), // For a p2tr script_sig is empty
            sequence: Sequence::MAX,
            witness: Witness::default(), // Filled in after signing
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: script_spendable_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: op_return_script,
            },
            TxOut {
                value: Amount::from_sat(7700), // 9000 - 1000 - 300 fee
                script_pubkey: seller_address.script_pubkey(),
            },
        ],
    };
    let input_index = 0;

    // Sign the transaction
    let sighash_type = TapSighashType::Default;
    let prevouts = vec![TxOut {
        value: Amount::from_sat(9000), // existing utxo with 9000 sats
        script_pubkey: seller_address.script_pubkey(),
    }];
    let prevouts = Prevouts::All(&prevouts);

    let mut sighasher = SighashCache::new(&attach_tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
        .expect("failed to construct sighash");

    // Sign the sighash
    let tweaked: TweakedKeypair = keypair.tap_tweak(&secp, None);
    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, &tweaked.to_inner());

    // Update the witness stack
    let signature = bitcoin::taproot::Signature {
        signature,
        sighash_type,
    };
    attach_tx.input[input_index]
        .witness
        .push(signature.to_vec());

    // Create the control block for the script
    let control_block = taproot_spend_info
        .control_block(&(tap_script.clone(), LeafVersion::TapScript))
        .expect("Failed to create control block");

    // Create seller's PSBT for atomic swap - with transaction inline and no outputs
    let mut seller_psbt = Psbt {
        unsigned_tx: Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: attach_tx.compute_txid(),
                    vout: 0, // The unspendable output
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
            tap_internal_key: Some(internal_key),
            tap_merkle_root: Some(taproot_spend_info.merkle_root().unwrap()),
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
        outputs: vec![Output::default()], // No outputs
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
            TapLeafHash::from_script(&tap_script, LeafVersion::TapScript),
            TapSighashType::SinglePlusAnyoneCanPay,
        )
        .expect("Failed to create sighash");

    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, &keypair);
    let signature = bitcoin::taproot::Signature {
        signature,
        sighash_type: TapSighashType::SinglePlusAnyoneCanPay,
    };

    // Add the signature to the PSBT
    seller_psbt.inputs[0].tap_script_sigs.insert(
        (
            internal_key,
            TapLeafHash::from_script(&tap_script, LeafVersion::TapScript),
        ),
        signature,
    );
    // Add the witness script to the PSBT from taproot transaction
    // Build the witness stack for script path spending
    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(&serialized_token_balance);
    witness.push(b"KNTR");
    witness.push(tap_script.as_bytes());
    witness.push(control_block.serialize());
    seller_psbt.inputs[0].final_script_witness = Some(witness);

    // After creating the seller's PSBT, build the buyer side

    // Create buyer's keypair
    let buyer_keypair = Keypair::from_secret_key(&secp, &_buyer_child_key.private_key);
    let (buyer_internal_key, _) = buyer_keypair.x_only_public_key();
    println!("[DEBUG] Buyer's internal key: {:?}", hex::encode(buyer_internal_key.serialize()));
    
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
                // Buyer receives the token (create a new OP_RETURN with transfer data)
                TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: {
                        let mut op_return_script = ScriptBuf::new();
                        op_return_script.push_opcode(OP_RETURN);
                        op_return_script.push_slice(b"KNTR");

                        // Create transfer data pointing to output 2 (buyer's address)
                        let transfer_data = OpReturnData::Swap {
                            destination: buyer_address.script_pubkey().as_bytes().to_vec(),
                        };
                        let transfer_bytes = rmp_serde::to_vec(&transfer_data).unwrap();
                        op_return_script.push_slice(PushBytesBuf::try_from(transfer_bytes)?);
                        op_return_script
                    },
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

        println!("[DEBUG] Prevouts for sighash:");
        for (i, prevout) in prevouts.iter().enumerate() {
            println!("[DEBUG] Input {}: value={}, script_pubkey={}", 
                i, 
                prevout.value.to_sat(), 
                hex::encode(prevout.script_pubkey.as_bytes()));
        }

        // Calculate the sighash for key path spending
        let sighash = sighasher.taproot_key_spend_signature_hash(
            1, // Buyer's input index (back to 1)
            &Prevouts::All(&prevouts),
            TapSighashType::Default,
        )
        .expect("Failed to create sighash");
        
        println!("[DEBUG] Calculated sighash: {:?}", hex::encode(sighash.to_byte_array()));
        sighash
    };

    // Sign with the buyer's tweaked key
    let msg = Message::from_digest(sighash.to_byte_array());
    println!("[DEBUG] Message to sign: {:?}", hex::encode(msg.as_ref()));
    
    // Get the tweaked key for signing using the merkle root from seller's PSBT
    let merkle_root = seller_psbt.inputs[0].tap_merkle_root.unwrap();
    println!("[DEBUG] Merkle root from seller's PSBT: {:?}", hex::encode(merkle_root.as_byte_array()));
    
    // Create the tweaked keypair
    let buyer_tweaked = buyer_keypair.tap_tweak(&secp, Some(merkle_root));
    let (tweaked_x_only, _) = buyer_tweaked.to_inner().x_only_public_key();
    println!("[DEBUG] Buyer's tweaked x-only key: {:?}", hex::encode(tweaked_x_only.serialize()));
    
    // Sign with the tweaked keypair since we're doing key path spending
    let buyer_signature = secp.sign_schnorr(&msg, &buyer_tweaked.to_inner());
    println!("[DEBUG] Generated signature: {:?}", hex::encode(buyer_signature.serialize()));
    
    let buyer_signature = bitcoin::taproot::Signature {
        signature: buyer_signature,
        sighash_type: TapSighashType::Default,
    };

    // Add the signature to the PSBT
    buyer_psbt.inputs[1].tap_key_sig = Some(buyer_signature);

    // Construct the witness stack for key path spending
    let mut buyer_witness = Witness::new();
    buyer_witness.push(buyer_signature.to_vec());
    println!("[DEBUG] Final witness stack length: {}", buyer_witness.len());
    buyer_psbt.inputs[1].final_script_witness = Some(buyer_witness);

    // Extract the transaction (no finalize needed since we set all witnesses manually)
    let final_tx = buyer_psbt.extract_tx()?;

    let raw_attach_tx_hex = hex::encode(serialize_tx(&attach_tx));
    let raw_swap_tx_hex = hex::encode(serialize_tx(&final_tx));
    println!("raw_attach_tx_hex: {}", raw_attach_tx_hex);
    println!("raw_swap_tx_hex: {}", raw_swap_tx_hex);

    let result = client
        .test_mempool_accept(&[raw_attach_tx_hex, raw_swap_tx_hex])
        .await?;
    println!("result: {:#?}", result);

    // Assert both transactions are allowed
    assert_eq!(result.len(), 2, "Expected exactly two transaction results");
    assert!(result[0].allowed, "Attach transaction was rejected");
    assert!(result[1].allowed, "Swap transaction was rejected");

    Ok(())
}

fn generate_address_from_mnemonic(
    secp: &Secp256k1<secp256k1::All>,
    path: &Path,
    index: u32,
) -> Result<(Address, Xpriv), anyhow::Error> {
    let mnemonic = fs::read_to_string(path)
        .expect("Failed to read mnemonic file")
        .trim()
        .to_string();

    // Parse the mnemonic
    let mnemonic = Mnemonic::from_str(&mnemonic).expect("Invalid mnemonic phrase");

    // Generate seed from mnemonic
    let seed = mnemonic.to_seed("");

    // Create master key
    let master_key =
        Xpriv::new_master(Network::Bitcoin, &seed).expect("Failed to create master key");

    // Derive first child key using a proper derivation path
    let path = DerivationPath::from_str(&format!("m/86'/0'/0'/0/{}", index))
        .expect("Invalid derivation path");
    let child_key = master_key
        .derive_priv(secp, &path)
        .expect("Failed to derive child key");

    // Get the private key
    let private_key = PrivateKey::new(child_key.private_key, Network::Bitcoin);

    // Get the public key
    let public_key = BitcoinPublicKey::from_private_key(secp, &private_key);

    // Create a Taproot address
    let x_only_pubkey = public_key.inner.x_only_public_key().0;
    let address = Address::p2tr(secp, x_only_pubkey, None, KnownHrp::Mainnet);

    Ok((address, child_key))
}
