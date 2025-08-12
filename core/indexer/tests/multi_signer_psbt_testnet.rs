use anyhow::{Result, anyhow};
use bitcoin::address::Address;
use bitcoin::amount::Amount;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::transaction::Version;
use bitcoin::{
    Network, OutPoint, Psbt, Sequence, Transaction, TxIn, TxOut, XOnlyPublicKey, absolute::LockTime,
};
use bitcoin::{TapSighashType, consensus::encode::serialize as serialize_tx};
use bitcoin::{Txid, Witness};
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
    // set up config
    let mut config = Config::try_parse()?;
    config.bitcoin_rpc_url = "http://127.0.0.1:48332".to_string();
    let client = Client::new_from_config(&config)?;

    let mut test_cfg = TestConfig::try_parse()?;
    test_cfg.network = Network::Testnet4;
    let secp = Secp256k1::new();

    // Set up inputs/outputs for the 3 concurrent signers
    let num_signers: usize = 3;

    let mut signers: Vec<SignerInput> = Vec::with_capacity(num_signers);
    for i in 0..num_signers {
        let (address, child_key, _compressed) =
            test_utils::generate_taproot_address_from_mnemonic(&secp, &test_cfg, i as u32)?;
        let keypair = Keypair::from_secret_key(&secp, &child_key.private_key);
        let (internal_key, _parity) = keypair.x_only_public_key();

        let (txid_str, vout_u32, value_sat): (&str, u32, u64) = match i {
            0 => (
                "dac8f123136bb59926e559e9da97eccc9f46726c3e7daaf2ab3502ef3a47fa46",
                0,
                500_000,
            ),
            1 => (
                "465de2192b246635df14ff81c3b6f37fb864f308ad271d4f91a29dcf476640ba",
                0,
                500_000,
            ),
            2 => (
                "49e327c2945f88908f67586de66af3bfc2567fe35ec7c5f1769f973f9fe8e47e",
                0,
                500_000,
            ),
            _ => (
                "b672084964187d9655a008c2af90c7d79b19fddcd66390bcf2926c0ea8e4135a",
                0,
                500_000,
            ),
        };
        let outpoint = OutPoint {
            txid: Txid::from_str(txid_str)?,
            vout: vout_u32,
        };
        let prevout = TxOut {
            value: Amount::from_sat(value_sat),
            script_pubkey: address.script_pubkey(),
        };

        // BTC will be returned back to the storage nodes
        let recipient = address.clone();

        signers.push(SignerInput {
            outpoint,
            prevout,
            internal_key,
            keypair,
            recipient,
        });
    }

    // PORTAL: create an empty base PSBT (transaction template)
    let base_tx = Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    };
    let base_psbt = Psbt::from_unsigned_tx(base_tx)?;

    // STORAGE NODES: Each clones the base, appends its own input/output, signs with SINGLE|ACP, returns PSBT
    let fee_per_input: u64 = 500; // conservative flat fee per input
    let futures = signers.iter().map(|s| {
        let secp = Secp256k1::new();
        let mut psbt_one = base_psbt.clone();
        async move {
            // Append signer's input
            psbt_one.unsigned_tx.input.push(TxIn {
                previous_output: s.outpoint,
                script_sig: bitcoin::script::ScriptBuf::new(),
                sequence: Sequence::ENABLE_RBF_NO_LOCKTIME,
                witness: Witness::new(),
            });
            psbt_one.inputs.push(Default::default());
            let new_input_index = psbt_one.unsigned_tx.input.len() - 1;
            psbt_one.inputs[new_input_index].witness_utxo = Some(s.prevout.clone());
            psbt_one.inputs[new_input_index].tap_internal_key = Some(s.internal_key);

            // Append signer's return output at the same index as the new input (end of vectors)
            psbt_one.unsigned_tx.output.push(TxOut {
                value: Amount::from_sat(s.prevout.value.to_sat().saturating_sub(fee_per_input)),
                script_pubkey: s.recipient.script_pubkey(),
            });
            psbt_one.outputs.push(Default::default());

            // Sign only this new input, binding to its paired output (same index) using SINGLE|ACP
            let mut tx_to_sign = psbt_one.unsigned_tx.clone();
            test_utils::sign_key_spend(
                &secp,
                &mut tx_to_sign,
                std::slice::from_ref(&s.prevout),
                &s.keypair,
                new_input_index,
                Some(TapSighashType::SinglePlusAnyoneCanPay),
            )?;
            psbt_one.inputs[new_input_index].final_script_witness =
                Some(tx_to_sign.input[new_input_index].witness.clone());

            Ok::<Psbt, anyhow::Error>(psbt_one)
        }
    });

    let mut parts: Vec<Psbt> = join_all(futures)
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    // Portal aggregates: concatenate inputs/outputs and input metadata in the same order
    let mut final_psbt = Psbt::from_unsigned_tx(Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![],
        output: vec![],
    })?;

    for mut p in parts.drain(..) {
        // move single input and output
        final_psbt
            .unsigned_tx
            .input
            .push(p.unsigned_tx.input.remove(0));
        final_psbt.inputs.push(p.inputs.remove(0));
        final_psbt
            .unsigned_tx
            .output
            .push(p.unsigned_tx.output.remove(0));
        final_psbt.outputs.push(p.outputs.remove(0));
    }

    let final_tx = final_psbt.extract_tx()?;
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
