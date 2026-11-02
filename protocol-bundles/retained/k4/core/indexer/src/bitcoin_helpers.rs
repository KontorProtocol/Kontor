use anyhow::Result;
use bitcoin::hashes::Hash;
use bitcoin::key::{Secp256k1, TapTweak};
use bitcoin::psbt::Input as PsbtInput;
use bitcoin::secp256k1::{All, Keypair, Message};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{LeafVersion, Signature as TaprootSignature, TaprootSpendInfo};
use bitcoin::{
    BlockHash, ScriptBuf, TapLeafHash, TapSighashType, Transaction as BitcoinTransaction, TxOut,
    Witness,
};

pub fn sign_key_spend(
    secp: &Secp256k1<All>,
    key_spend_tx: &mut BitcoinTransaction,
    prevouts: &[TxOut],
    keypair: &Keypair,
    input_index: usize,
    sighash_type: Option<TapSighashType>,
) -> Result<()> {
    let sighash_type = sighash_type.unwrap_or(TapSighashType::Default);

    let mut sighasher = SighashCache::new(key_spend_tx.clone());
    let sighash = sighasher
        .taproot_key_spend_signature_hash(input_index, &Prevouts::All(prevouts), sighash_type)
        .expect("Failed to construct sighash");

    let tweaked_sender = keypair.tap_tweak(secp, None);
    let msg = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, &tweaked_sender.to_keypair());

    let signature = TaprootSignature {
        signature,
        sighash_type,
    };
    key_spend_tx.input[input_index]
        .witness
        .push(signature.to_vec());
    Ok(())
}

/// Pull a participant input's tap leaf script + version out of its
/// PSBT `tap_scripts` map (`PSBT_IN_TAP_LEAF_SCRIPT`, BIP 371). By
/// our convention each participant input carries exactly one leaf
/// script, so we take the first map entry. Replaces the old
/// `RevealOutputs.commit_tap_leaf_scripts[i]` lookup — the leaf
/// script now lives in the PSBT proper, so wallets that speak
/// taproot PSBT can sign without any client-side fixup.
pub fn participant_tap_script(input: &PsbtInput) -> Result<(ScriptBuf, LeafVersion)> {
    input
        .tap_scripts
        .first_key_value()
        .map(|(_cb, sv)| sv.clone())
        .ok_or_else(|| anyhow::anyhow!("PSBT input has no tap leaf script"))
}

pub fn sign_script_spend(
    secp: &Secp256k1<All>,
    taproot_spend_info: &TaprootSpendInfo,
    tap_script: &ScriptBuf,
    script_spend_tx: &mut BitcoinTransaction,
    prevouts: &[TxOut],
    keypair: &Keypair,
    input_index: usize,
) -> Result<()> {
    sign_script_spend_with_sighash(
        secp,
        taproot_spend_info,
        tap_script,
        script_spend_tx,
        prevouts,
        keypair,
        input_index,
        TapSighashType::Default,
    )
}

pub fn sign_script_spend_with_sighash(
    secp: &Secp256k1<All>,
    taproot_spend_info: &TaprootSpendInfo,
    tap_script: &ScriptBuf,
    script_spend_tx: &mut BitcoinTransaction,
    prevouts: &[TxOut],
    keypair: &Keypair,
    input_index: usize,
    sighash_type: TapSighashType,
) -> Result<()> {
    let control_block = taproot_spend_info
        .control_block(&(tap_script.clone(), LeafVersion::TapScript))
        .expect("Failed to create control block");

    let mut sighasher = SighashCache::new(script_spend_tx.clone());
    let sighash = sighasher
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::All(prevouts),
            TapLeafHash::from_script(tap_script, LeafVersion::TapScript),
            sighash_type,
        )
        .expect("Failed to create sighash");

    let msg: Message = Message::from_digest(sighash.to_byte_array());
    let signature = secp.sign_schnorr(&msg, keypair);

    let signature = TaprootSignature {
        signature,
        sighash_type,
    };

    let mut witness = Witness::new();
    witness.push(signature.to_vec());
    witness.push(tap_script.as_bytes());
    witness.push(control_block.serialize());
    script_spend_tx.input[input_index].witness = witness;
    Ok(())
}

pub fn new_mock_block_hash(i: u32) -> BlockHash {
    let mut bytes = [0u8; 32];
    let i_bytes = i.to_le_bytes();
    for chunk in bytes.chunks_mut(4) {
        chunk.copy_from_slice(&i_bytes[..chunk.len()]);
    }
    BlockHash::from_slice(&bytes).unwrap()
}
