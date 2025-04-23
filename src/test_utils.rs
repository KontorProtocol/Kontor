use anyhow::Result;
use bip39::Mnemonic;
use bitcoin::absolute::LockTime;
use bitcoin::address::Address;
use bitcoin::hashes::{Hash, sha256};
use bitcoin::key::{PublicKey as BitcoinPublicKey, TapTweak, TweakedKeypair};
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_EQUALVERIFY, OP_RETURN, OP_SHA256};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::Keypair;
use bitcoin::secp256k1::Message;
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::transaction::Version;
use bitcoin::{
    Amount, KnownHrp, OutPoint, ScriptBuf, Sequence, TapSighashType, Transaction, TxIn, TxOut,
    Txid, Witness, XOnlyPublicKey, secp256k1,
};
use bitcoin::{
    Network, PrivateKey,
    bip32::{DerivationPath, Xpriv},
    key::{CompressedPublicKey, Secp256k1},
};
use std::fs;
use std::path::Path;
use std::str::FromStr;

use crate::op_return::OpReturnData;

pub fn generate_address_from_mnemonic_p2wpkh(
    secp: &Secp256k1<bitcoin::secp256k1::All>,
    path: &Path,
) -> Result<(Address, Xpriv, CompressedPublicKey), anyhow::Error> {
    // Read mnemonic from secret file
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
    let path = DerivationPath::from_str("m/84'/0'/0'/0/0").expect("Invalid derivation path");
    let child_key = master_key
        .derive_priv(secp, &path)
        .expect("Failed to derive child key");

    // Get the private key
    let private_key = PrivateKey::new(child_key.private_key, Network::Bitcoin);

    // Get the public key
    let public_key = BitcoinPublicKey::from_private_key(secp, &private_key);
    let compressed_pubkey = bitcoin::CompressedPublicKey(public_key.inner);

    // Create a P2WPKH address
    let address = Address::p2wpkh(&compressed_pubkey, Network::Bitcoin);

    Ok((address, child_key, compressed_pubkey))
}

pub enum PublicKey<'a> {
    Segwit(&'a CompressedPublicKey),
    Taproot(&'a XOnlyPublicKey),
}

pub fn build_witness_script(key: PublicKey, serialized_token_balance: &[u8]) -> ScriptBuf {
    // Create the tapscript with x-only public key
    let base_witness_script = Builder::new()
        .push_slice(b"KNTR")
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

pub fn generate_taproot_address_from_mnemonic(
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

pub fn build_signed_taproot_attach_tx(
    secp: &Secp256k1<secp256k1::All>,
    keypair: &Keypair,
    seller_address: &Address,
    script_spendable_address: &Address,
) -> Result<Transaction> {
    let mut op_return_script = ScriptBuf::new();
    op_return_script.push_opcode(OP_RETURN);
    op_return_script.push_slice(b"KNTR");

    let op_return_data = OpReturnData::A { output_index: 0 };
    let mut s = Vec::new();
    ciborium::into_writer(&op_return_data, &mut s).unwrap();
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
    let tweaked: TweakedKeypair = keypair.tap_tweak(secp, None);
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

    Ok(attach_tx)
}
