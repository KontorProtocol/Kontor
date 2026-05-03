use anyhow::{Context, Result};
use bitcoin::secp256k1::{Keypair, Secp256k1, SecretKey};
use clap::{Args, Subcommand};
use hkdf::Hkdf;
use serde_json::json;
use sha2::Sha256;

use crate::consensus::signing::PrivateKey;

#[derive(Args)]
pub struct KeygenArgs {
    /// Hex-encoded master seed (64 hex chars = 32 bytes).
    /// Generate one with: openssl rand -hex 32
    #[clap(long)]
    pub master_seed: String,

    #[command(subcommand)]
    pub mode: KeygenMode,
}

#[derive(Subcommand)]
pub enum KeygenMode {
    /// Emit the genesis JSON skeleton for N validators.
    Validators {
        /// Number of validators to derive (typically 4).
        n: u32,
        /// Stake amount per validator (decimal string).
        #[clap(long, default_value = "1")]
        stake: String,
    },
    /// Emit the four key fields for a single validator
    /// (ed25519 + secp256k1 keypairs, private + public).
    Validator {
        /// 0-based validator index.
        n: u32,
    },
}

pub fn run(args: KeygenArgs) -> Result<()> {
    let master = parse_master_seed(&args.master_seed)?;
    match args.mode {
        KeygenMode::Validators { n, stake } => emit_genesis(&master, n, &stake),
        KeygenMode::Validator { n } => emit_validator(&master, n),
    }
}

fn parse_master_seed(hex_str: &str) -> Result<[u8; 32]> {
    let bytes = hex::decode(hex_str).context("invalid master seed hex")?;
    bytes.try_into().map_err(|v: Vec<u8>| {
        anyhow::anyhow!(
            "master seed must be 32 bytes (64 hex chars), got {}",
            v.len()
        )
    })
}

/// HKDF-SHA256 expansion of the master seed for a labeled context.
fn derive(master: &[u8; 32], info: &str) -> [u8; 32] {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut out = [0u8; 32];
    hk.expand(info.as_bytes(), &mut out)
        .expect("HKDF expand to 32 bytes never fails");
    out
}

fn derive_ed25519(master: &[u8; 32], idx: u32) -> PrivateKey {
    PrivateKey::from(derive(master, &format!("ed25519/{idx}")))
}

/// Secp256k1 secret keys must be in [1, n-1]. Random 32 bytes are valid with
/// probability ~1 - 2^-128, but we still rejection-sample with a counter
/// suffix on the rare miss to keep the function total.
fn derive_secp256k1(master: &[u8; 32], idx: u32) -> SecretKey {
    for counter in 0u32..256 {
        let bytes = derive(master, &format!("secp256k1/{idx}/{counter}"));
        if let Ok(sk) = SecretKey::from_slice(&bytes) {
            return sk;
        }
    }
    panic!("could not derive valid secp256k1 secret key after 256 attempts");
}

pub struct ValidatorKeys {
    pub ed25519_private: [u8; 32],
    pub ed25519_pubkey: [u8; 32],
    pub secp256k1_private: [u8; 32],
    pub x_only_pubkey: [u8; 32],
}

pub fn derive_validator(master: &[u8; 32], idx: u32) -> ValidatorKeys {
    let ed_priv = derive_ed25519(master, idx);
    let ed_pub = ed_priv.public_key();
    let secp = Secp256k1::new();
    let sk = derive_secp256k1(master, idx);
    let kp = Keypair::from_secret_key(&secp, &sk);
    let (x_only_pk, _parity) = kp.x_only_public_key();
    ValidatorKeys {
        ed25519_private: ed_priv.inner().to_bytes(),
        ed25519_pubkey: *ed_pub.as_bytes(),
        secp256k1_private: sk.secret_bytes(),
        x_only_pubkey: x_only_pk.serialize(),
    }
}

fn emit_genesis(master: &[u8; 32], n: u32, stake: &str) -> Result<()> {
    let validators: Vec<_> = (0..n)
        .map(|i| {
            let keys = derive_validator(master, i);
            json!({
                "x_only_pubkey": hex::encode(keys.x_only_pubkey),
                "stake": stake,
                "ed25519_pubkey": hex::encode(keys.ed25519_pubkey),
            })
        })
        .collect();
    let genesis = json!({ "validators": validators });
    println!("{}", serde_json::to_string_pretty(&genesis)?);
    Ok(())
}

fn emit_validator(master: &[u8; 32], i: u32) -> Result<()> {
    let keys = derive_validator(master, i);
    println!("ed25519_private:   {}", hex::encode(keys.ed25519_private));
    println!("ed25519_pubkey:    {}", hex::encode(keys.ed25519_pubkey));
    println!("secp256k1_private: {}", hex::encode(keys.secp256k1_private));
    println!("x_only_pubkey:     {}", hex::encode(keys.x_only_pubkey));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const TEST_SEED: [u8; 32] = [0x42u8; 32];

    #[test]
    fn derivation_is_deterministic() {
        let a = derive_validator(&TEST_SEED, 0);
        let b = derive_validator(&TEST_SEED, 0);
        assert_eq!(a.ed25519_private, b.ed25519_private);
        assert_eq!(a.ed25519_pubkey, b.ed25519_pubkey);
        assert_eq!(a.secp256k1_private, b.secp256k1_private);
        assert_eq!(a.x_only_pubkey, b.x_only_pubkey);
    }

    #[test]
    fn different_indices_produce_different_keys() {
        let v0 = derive_validator(&TEST_SEED, 0);
        let v1 = derive_validator(&TEST_SEED, 1);
        assert_ne!(v0.ed25519_private, v1.ed25519_private);
        assert_ne!(v0.secp256k1_private, v1.secp256k1_private);
        assert_ne!(v0.ed25519_pubkey, v1.ed25519_pubkey);
        assert_ne!(v0.x_only_pubkey, v1.x_only_pubkey);
    }

    #[test]
    fn ed25519_pubkey_matches_signing_module_derivation() {
        // The pubkey emitted by keygen must match what the running daemon
        // computes from the same private key via private_key_from_hex().
        let v = derive_validator(&TEST_SEED, 0);
        let parsed = crate::consensus::signing::private_key_from_hex(&hex::encode(
            v.ed25519_private,
        ))
        .unwrap();
        assert_eq!(*parsed.public_key().as_bytes(), v.ed25519_pubkey);
    }

    #[test]
    fn x_only_pubkey_matches_secp256k1_derivation() {
        // Same self-consistency check for the secp256k1 side.
        let v = derive_validator(&TEST_SEED, 0);
        let secp = Secp256k1::new();
        let sk = SecretKey::from_slice(&v.secp256k1_private).unwrap();
        let kp = Keypair::from_secret_key(&secp, &sk);
        let (x_only_pk, _parity) = kp.x_only_public_key();
        assert_eq!(x_only_pk.serialize(), v.x_only_pubkey);
    }
}
