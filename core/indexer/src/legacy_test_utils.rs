use anyhow::Result;
use bitcoin::absolute::LockTime;
use bitcoin::address::Address;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::key::{TapTweak, TweakedKeypair};
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_EQUALVERIFY, OP_RETURN, OP_SHA256};
use bitcoin::psbt::{Input, Output, PsbtSighashType};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{All, Keypair};
use bitcoin::secp256k1::{Message, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{ControlBlock, LeafVersion, TaprootSpendInfo};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, EcdsaSighashType, OutPoint, Psbt, ScriptBuf, Sequence, TapLeafHash, TapSighashType,
    Transaction, TxIn, TxOut, Witness, XOnlyPublicKey, secp256k1,
};
use bitcoin::{
    Network,
    key::{CompressedPublicKey, Secp256k1},
};
use indexer_types::serialize;
use std::collections::HashMap;

pub enum PublicKey<'a> {
    Segwit(&'a CompressedPublicKey),
    Taproot(&'a XOnlyPublicKey),
}

use serde::{Deserialize, Serialize};

#[derive(Debug, PartialEq, Serialize, Deserialize)]
pub enum LegacyOpReturnData {
    A {
        #[serde(rename = "o")]
        output_index: u32,
    }, // attach
    S {
        #[serde(rename = "d")]
        destination: Vec<u8>,
    }, // swap
    D {
        #[serde(rename = "d")]
        destination: XOnlyPublicKey,
    }, // detach
}

pub fn build_witness_script(key: PublicKey, serialized_token_balance: &[u8]) -> ScriptBuf {
    // Create the tapscript with x-only public key
    let base_witness_script = Builder::new()
        .push_slice(b"kon")
        .push_opcode(OP_EQUALVERIFY)
        .push_opcode(OP_SHA256)
        .push_slice(sha256::Hash::hash(serialized_token_balance).as_byte_array())
        .push_opcode(OP_EQUALVERIFY);

    let witness_script = match key {
        PublicKey::Segwit(compressed) => base_witness_script.push_slice(compressed.to_bytes()),
        PublicKey::Taproot(x_only) => base_witness_script.push_slice(x_only.serialize()),
    };

    witness_script.push_opcode(OP_CHECKSIG).into_script()
}

pub fn build_signed_taproot_attach_tx(
    secp: &Secp256k1<secp256k1::All>,
    keypair: &Keypair,
    seller_address: &Address,
    script_spendable_address: &Address,
    seller_out_point: OutPoint,
    seller_utxo_for_output: TxOut,
) -> Result<Transaction> {
    let mut op_return_script = ScriptBuf::new();
    op_return_script.push_opcode(OP_RETURN);
    op_return_script.push_slice(b"kon");

    let op_return_data = LegacyOpReturnData::A { output_index: 0 };
    op_return_script.push_slice(PushBytesBuf::try_from(serialize(&op_return_data)?)?);

    // Create the transaction
    let mut attach_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: seller_out_point, // The output we are spending
            script_sig: ScriptBuf::default(),  // For a p2tr script_sig is empty
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
                value: seller_utxo_for_output.value
                    - Amount::from_sat(1000)
                    - Amount::from_sat(300), // seller utxo amount - 1000 - 300 fee
                script_pubkey: seller_address.script_pubkey(),
            },
        ],
    };
    let input_index = 0;

    // Sign the transaction
    let sighash_type = TapSighashType::Default;
    let prevouts = vec![TxOut {
        value: seller_utxo_for_output.value, // existing seller utxo
        script_pubkey: seller_address.script_pubkey(),
    }];
    let prevouts = Prevouts::All(&prevouts);

    let mut sighasher = SighashCache::new(&attach_tx);
    let sighash = sighasher
        .taproot_key_spend_signature_hash(input_index, &prevouts, sighash_type)
        .expect("failed to construct sighash");

    // Sign the sighash
    let tweaked: TweakedKeypair = keypair.tap_tweak(secp, None);
    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, &tweaked.to_keypair());

    // Update the witness stack
    let signature = bitcoin::taproot::Signature {
        signature,
        sighash_type,
    };
    attach_tx.input[input_index]
        .witness
        .push(signature.to_vec());

    Ok(attach_tx)
}

pub fn build_long_token_balance() -> HashMap<String, i32> {
    // Create token balance data
    let mut token_balances = HashMap::new();
    token_balances.insert("token_name".to_string(), 1000);
    token_balances.insert("token_name2".to_string(), 2000);
    token_balances.insert("token_name3".to_string(), 3000);
    token_balances.insert("token_name4".to_string(), 4000);
    token_balances.insert("token_name5".to_string(), 5000);
    token_balances.insert("token_name6".to_string(), 6000);
    token_balances.insert("token_name7".to_string(), 7000);
    token_balances.insert("token_name8".to_string(), 8000);
    token_balances.insert("token_name9".to_string(), 9000);
    token_balances.insert("token_name10".to_string(), 10000);

    token_balances
}

pub fn build_seller_psbt_and_sig_taproot(
    secp: &Secp256k1<secp256k1::All>,
    keypair: &Keypair,
    seller_address: &Address,
    attach_tx: &Transaction,
    seller_internal_key: &XOnlyPublicKey,
    taproot_spend_info: &TaprootSpendInfo,
    tap_script: &ScriptBuf,
) -> Result<(Psbt, bitcoin::taproot::Signature, ControlBlock)> {
    let seller_internal_key = *seller_internal_key;
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
            tap_internal_key: Some(seller_internal_key),
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

    // Not necessary for test, but this is where the signature would be stored in the marketplace until it was ready to be spent
    seller_psbt.inputs[0].tap_script_sigs.insert(
        (
            seller_internal_key,
            TapLeafHash::from_script(tap_script, LeafVersion::TapScript),
        ),
        signature,
    );

    Ok((seller_psbt, signature, control_block))
}

pub fn build_signed_buyer_psbt_taproot(
    secp: &Secp256k1<secp256k1::All>,
    buyer_keypair: &Keypair,
    buyer_internal_key: XOnlyPublicKey,
    buyer_address: &Address,
    buyer_out_point: OutPoint,
    buyer_utxo_for_output: TxOut,
    seller_address: &Address,
    attach_tx: &Transaction,
    script_spendable_address: &Address,
    seller_psbt: &Psbt,
) -> Result<Psbt> {
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
                    previous_output: buyer_out_point,
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
                        op_return_script.push_slice(b"kon");

                        // Create transfer data pointing to output 2 (buyer's address)
                        let transfer_data = LegacyOpReturnData::S {
                            destination: buyer_address.script_pubkey().as_bytes().to_vec(),
                        };
                        op_return_script
                            .push_slice(PushBytesBuf::try_from(serialize(&transfer_data)?)?);

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
                    value: buyer_utxo_for_output.value
                        - Amount::from_sat(600)
                        - Amount::from_sat(546), // buyer utxo amount - 600 - 546
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
                    value: buyer_utxo_for_output.value,
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
                value: buyer_utxo_for_output.value, // The value of the second input (buyer's UTXO)
                script_pubkey: buyer_address.script_pubkey(),
            },
        ];

        // Calculate the sighash for key path spending
        sighasher
            .taproot_key_spend_signature_hash(
                1, // Buyer's input index (back to 1)
                &Prevouts::All(&prevouts),
                TapSighashType::Default,
            )
            .expect("Failed to create sighash")
    };

    // Sign with the buyer's tweaked key
    let msg = Message::from_digest(sighash.to_byte_array());

    // Create the tweaked keypair
    let buyer_tweaked = buyer_keypair.tap_tweak(secp, None);
    // Sign with the tweaked keypair since we're doing key path spending
    let buyer_signature = secp.sign_schnorr(&msg, &buyer_tweaked.to_keypair());

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

pub fn build_signed_attach_tx_segwit(
    secp: &Secp256k1<All>,
    seller_address: &Address,
    seller_compressed_pubkey: &CompressedPublicKey,
    secret_key: &SecretKey,
    witness_script: &ScriptBuf,
    seller_out_point: OutPoint,
    seller_utxo_for_output: &TxOut,
) -> Result<Transaction> {
    let script_address: Address = Address::p2wsh(witness_script, Network::Bitcoin);

    let mut op_return_script = ScriptBuf::new();
    op_return_script.push_opcode(OP_RETURN);
    op_return_script.push_slice(b"kon");

    let op_return_data = LegacyOpReturnData::A { output_index: 0 };
    op_return_script.push_slice(PushBytesBuf::try_from(serialize(&op_return_data)?)?);

    // Create first transaction to create our special UTXO
    let mut create_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: seller_out_point,
            ..Default::default()
        }],
        output: vec![
            TxOut {
                value: Amount::from_sat(1000),
                script_pubkey: script_address.script_pubkey(),
            },
            TxOut {
                value: seller_utxo_for_output.value
                    - Amount::from_sat(1000)
                    - Amount::from_sat(300), // seller utxo amount - 1000 - 300 fee
                script_pubkey: seller_address.script_pubkey(),
            },
            TxOut {
                value: Amount::from_sat(0),
                script_pubkey: op_return_script,
            },
        ],
    };

    // Sign the input as normal P2WPKH
    let mut sighash_cache = SighashCache::new(&create_tx);
    let sighash = sighash_cache
        .p2wpkh_signature_hash(
            0,
            &seller_address.script_pubkey(),
            seller_utxo_for_output.value,
            EcdsaSighashType::All,
        )
        .expect("Failed to compute sighash");

    let msg = secp256k1::Message::from(sighash);
    let sig = secp.sign_ecdsa(&msg, secret_key);
    let sig = bitcoin::ecdsa::Signature::sighash_all(sig);

    // Create witness data for P2WPKH
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(seller_compressed_pubkey.to_bytes());
    create_tx.input[0].witness = witness;

    Ok(create_tx)
}

pub fn build_seller_psbt_and_sig_segwit(
    secp: &Secp256k1<All>,
    seller_address: &Address,
    secret_key: &SecretKey,
    attach_tx: &Transaction,
    witness_script: &ScriptBuf,
) -> Result<(Psbt, bitcoin::ecdsa::Signature)> {
    // Create seller's PSBT
    let seller_psbt = Psbt {
        unsigned_tx: Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![TxIn {
                previous_output: OutPoint {
                    txid: attach_tx.compute_txid(),
                    vout: 0,
                },
                ..Default::default()
            }],
            output: vec![TxOut {
                value: Amount::from_sat(600),
                script_pubkey: seller_address.script_pubkey(),
            }],
        },
        inputs: vec![Input {
            witness_script: Some(witness_script.clone()),
            witness_utxo: Some(TxOut {
                script_pubkey: attach_tx.output[0].script_pubkey.clone(),
                value: Amount::from_sat(1000), // Use the actual output amount from attach_tx
            }),
            sighash_type: Some(PsbtSighashType::from(
                EcdsaSighashType::SinglePlusAnyoneCanPay,
            )),
            ..Default::default()
        }],
        outputs: vec![Output::default()],
        version: 0,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
    };

    // Sign seller's PSBT with the witness script and secret data
    let mut sighash_cache = SighashCache::new(&seller_psbt.unsigned_tx);
    let (msg, sighash_type) = seller_psbt.sighash_ecdsa(0, &mut sighash_cache)?;

    let sig = secp.sign_ecdsa(&msg, secret_key);
    let sig = bitcoin::ecdsa::Signature {
        signature: sig,
        sighash_type,
    };

    Ok((seller_psbt, sig))
}

pub fn build_signed_buyer_psbt_segwit(
    secp: &Secp256k1<All>,
    buyer_address: &Address,
    buyer_secret_key: &SecretKey,
    attach_tx: &Transaction,
    buyer_compressed_pubkey: &CompressedPublicKey,
    seller_address: &Address,
    seller_psbt: &Psbt,
    buyer_out_point: OutPoint,
    buyer_utxo_for_output: TxOut,
) -> Result<Psbt> {
    let mut buyer_op_return_script = ScriptBuf::new();
    buyer_op_return_script.push_opcode(bitcoin::opcodes::all::OP_RETURN);
    buyer_op_return_script.push_slice(b"kon");

    let buyer_op_return_data = LegacyOpReturnData::S {
        destination: buyer_address.script_pubkey().as_bytes().to_vec(),
    };

    buyer_op_return_script.push_slice(PushBytesBuf::try_from(serialize(&buyer_op_return_data)?)?);

    // Create buyer's PSBT
    let mut buyer_psbt = Psbt {
        unsigned_tx: Transaction {
            version: Version(2),
            lock_time: LockTime::ZERO,
            input: vec![
                // Seller's signed input
                TxIn {
                    previous_output: OutPoint {
                        txid: attach_tx.compute_txid(),
                        vout: 0,
                    },
                    ..Default::default()
                },
                // Buyer's UTXO input
                TxIn {
                    previous_output: buyer_out_point,
                    ..Default::default()
                },
            ],
            output: vec![
                // Seller receives payment
                TxOut {
                    value: Amount::from_sat(600),
                    script_pubkey: seller_address.script_pubkey(),
                },
                // Buyer receives the asset
                TxOut {
                    value: Amount::from_sat(0),
                    script_pubkey: buyer_op_return_script, // OP_RETURN with data pointing to the attached UTXO
                },
                // Buyer's change
                TxOut {
                    value: buyer_utxo_for_output.value
                        - Amount::from_sat(600)
                        - Amount::from_sat(546), // buyer utxo amount - 600 - 546
                    script_pubkey: buyer_address.script_pubkey(),
                },
            ],
        },
        inputs: vec![
            // Seller's signed input
            seller_psbt.inputs[0].clone(),
            // Buyer's UTXO input
            Input {
                witness_utxo: Some(TxOut {
                    script_pubkey: buyer_address.script_pubkey(),
                    value: buyer_utxo_for_output.value,
                }),
                sighash_type: Some(PsbtSighashType::from(EcdsaSighashType::All)),
                ..Default::default()
            },
        ],
        outputs: vec![Output::default(), Output::default(), Output::default()],
        version: 0,
        xpub: Default::default(),
        proprietary: Default::default(),
        unknown: Default::default(),
    };

    // Sign buyer's input
    let mut sighash_cache = SighashCache::new(&buyer_psbt.unsigned_tx);
    let (msg, sighash_type) = buyer_psbt.sighash_ecdsa(1, &mut sighash_cache)?;

    let sig = secp.sign_ecdsa(&msg, buyer_secret_key);
    let sig = bitcoin::ecdsa::Signature {
        signature: sig,
        sighash_type,
    };

    // Create witness data for buyer's input
    let mut witness = Witness::new();
    witness.push(sig.to_vec());
    witness.push(buyer_compressed_pubkey.to_bytes());
    buyer_psbt.inputs[1].final_script_witness = Some(witness);

    Ok(buyer_psbt)
}
