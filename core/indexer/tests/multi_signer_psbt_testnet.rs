use anyhow::{Result, anyhow};
use bitcoin::Witness;
use bitcoin::address::Address;
use bitcoin::amount::Amount;
use bitcoin::hashes::Hash as _;
use bitcoin::key::{Keypair, Secp256k1, TapTweak};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::Signature as TapSig;
use bitcoin::transaction::Version;
use bitcoin::{
    Network, OutPoint, Psbt, Sequence, Transaction, TxIn, TxOut, XOnlyPublicKey, absolute::LockTime,
};
use bitcoin::{TapSighashType, consensus::encode::serialize as serialize_tx};
use clap::Parser;
use futures_util::future::join_all;
use indexer::config::{Config, TestConfig};
use indexer::{bitcoin_client::Client, test_utils};
use std::str::FromStr;

#[derive(Clone, Debug)]
struct SignerInput {
    outpoint: OutPoint,
    prevout: TxOut,
    internal_key: XOnlyPublicKey,
    keypair: Keypair,
    recipient: Address,
}

#[tokio::test]
async fn test_multi_signer_psbt_testnet() -> Result<()> {
    // RPC to your local bitcoind. Adjust if needed.
    let mut config = Config::try_parse()?;
    config.bitcoin_rpc_url = "http://127.0.0.1:48332".to_string();
    let client = Client::new_from_config(&config)?;

    // Use testnet4 derivation and the repo's mnemonic-based derivation util
    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();

    // Number of concurrent signers. Adjust as needed.
    let num_signers: usize = 3;

    // Prepare signer inputs with placeholder UTXOs (replace before running)
    let mut signers: Vec<SignerInput> = Vec::with_capacity(num_signers);
    for i in 0..num_signers {
        let (address, child_key, _compressed) =
            test_utils::generate_taproot_address_from_mnemonic(&secp, &test_cfg, i as u32)?;
        let keypair = Keypair::from_secret_key(&secp, &child_key.private_key);
        let (internal_key, _parity) = keypair.x_only_public_key();

        // REPLACE these with real testnet UTXOs for each signer index i
        // Example: ("738c9c29646f2efe149fc3abb23976f4e3c3009656bdb4349a8e04570ed2ba9a", 1, 500_000)
        let (txid_str, vout_u32, value_sat): (&str, u32, u64) = match i {
            0 => ("dac8f123136bb59926e559e9da97eccc9f46726c3e7daaf2ab3502ef3a47fa46", 0, 500_000),
            1 => ("465de2192b246635df14ff81c3b6f37fb864f308ad271d4f91a29dcf476640ba", 0, 500_000),
            2 => ("49e327c2945f88908f67586de66af3bfc2567fe35ec7c5f1769f973f9fe8e47e", 0, 500_000),
            _ => ("b672084964187d9655a008c2af90c7d79b19fddcd66390bcf2926c0ea8e4135a", 0, 500_000),
        };
        let outpoint = OutPoint {
            txid: bitcoin::Txid::from_str(txid_str)?,
            vout: vout_u32,
        };
        let prevout = TxOut {
            value: Amount::from_sat(value_sat),
            script_pubkey: address.script_pubkey(),
        };

        // Recipient can be the same address for a simple fan-out demo
        let recipient = address.clone();

        signers.push(SignerInput {
            outpoint,
            prevout,
            internal_key,
            keypair,
            recipient,
        });
    }

    // Build aggregate unsigned transaction with all inputs/outputs
    let fee_per_input: u64 = 500; // conservative flat fee per input
    let unsigned_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: signers
            .iter()
            .map(|s| TxIn {
                previous_output: s.outpoint,
                script_sig: bitcoin::script::ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            })
            .collect(),
        output: signers
            .iter()
            .map(|s| TxOut {
                value: Amount::from_sat(s.prevout.value.to_sat().saturating_sub(fee_per_input)),
                script_pubkey: s.recipient.script_pubkey(),
            })
            .collect(),
    };

    let mut psbt = Psbt::from_unsigned_tx(unsigned_tx.clone())?;
    for (i, s) in signers.iter().enumerate() {
        psbt.inputs[i].witness_utxo = Some(s.prevout.clone());
        psbt.inputs[i].tap_internal_key = Some(s.internal_key);
    }

    // Prepare prevouts for sighash computation
    let prevouts: Vec<TxOut> = signers.iter().map(|s| s.prevout.clone()).collect();

    // Each signer signs their input concurrently with SIGHASH_NONE | ANYONECANPAY
    let futures = signers.iter().enumerate().map(|(idx, s)| {
        let tx = unsigned_tx.clone();
        let prevouts = prevouts.clone();
        let secp_ref = secp.clone();
        let keypair = s.keypair;
        async move {
            let sighash_type = TapSighashType::NonePlusAnyoneCanPay;
            let mut sighasher = SighashCache::new(tx.clone());
            let sighash = sighasher.taproot_key_spend_signature_hash(
                idx,
                &Prevouts::All(&prevouts),
                sighash_type,
            )?;
            let msg =
                bitcoin::secp256k1::Message::from_digest(sighash.to_raw_hash().to_byte_array());
            let tweaked = keypair.tap_tweak(&secp_ref, None);
            let schnorr = secp_ref.sign_schnorr(&msg, &tweaked.to_keypair());
            let sig = TapSig {
                signature: schnorr,
                sighash_type,
            };
            Ok::<(usize, TapSig), anyhow::Error>((idx, sig))
        }
    });

    let signed_parts = join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    // Apply signatures and finalize witnesses
    for (idx, sig) in signed_parts {
        psbt.inputs[idx].tap_key_sig = Some(sig);
        let mut w = Witness::new();
        w.push(
            psbt.inputs[idx]
                .tap_key_sig
                .as_ref()
                .expect("sig just set")
                .to_vec(),
        );
        psbt.inputs[idx].final_script_witness = Some(w);
    }

    let final_tx = psbt.extract_tx()?;
    let hex = hex::encode(serialize_tx(&final_tx));
    let res = client.test_mempool_accept(&[hex]).await?;
    if res.is_empty() {
        return Err(anyhow!("Empty testmempoolaccept response"));
    }
    assert!(
        res[0].allowed,
        "Final aggregated transaction was rejected: {:?}",
        res[0].reject_reason
    );

    Ok(())
}
