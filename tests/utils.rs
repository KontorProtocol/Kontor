use anyhow::Result;
use bip39::Mnemonic;
use bitcoin::address::Address;
use bitcoin::key::PublicKey as BitcoinPublicKey;
use bitcoin::{
    Network, PrivateKey,
    bip32::{DerivationPath, Xpriv},
    key::{CompressedPublicKey, Secp256k1},
};
use std::fs;
use std::path::Path;
use std::str::FromStr;

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
