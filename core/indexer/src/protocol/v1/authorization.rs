use bitcoin::hashes::Hash;
use bitcoin::key::TapTweak;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF};
use bitcoin::script::Instruction;
use bitcoin::secp256k1::{Message, Secp256k1, VerifyOnly, XOnlyPublicKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{ControlBlock, LeafVersion, Signature, TapNodeHash};
use bitcoin::{
    Amount, Network, ScriptBuf, TapLeafHash, TapSighashType, Transaction as BitcoinTransaction,
    TxOut,
};
use indexer_types::{Input, InstKind, Insts, deserialize};

const FORMAT_TAG: &[u8] = b"kon2";
const MAX_LEAF_BYTES: usize = 387 * 1024;
const MAX_MONEY_SATS: u64 = 2_100_000_000_000_000;

#[cfg(test)]
mod tests;

pub(crate) struct AuthorizedInput {
    pub(crate) input: Input,
    pub(crate) leaf_hash: TapLeafHash,
    pub(crate) signature_mode: TapSighashType,
}

/// This establishes consent to the leaf and a hypothetical previous output.
/// Bitcoin acceptance must independently validate the actual spent output.
pub(crate) fn parse_authorized_input(
    tx: &BitcoinTransaction,
    sighash_cache: &mut SighashCache<&BitcoinTransaction>,
    secp: &Secp256k1<VerifyOnly>,
    input_index: usize,
    network: Network,
) -> Option<AuthorizedInput> {
    let input = tx.input.get(input_index)?;
    let witness = &input.witness;
    // The launch grammar has exactly one signature and no annex. An extra
    // stack item would change script execution without changing the leaf.
    if witness.len() != 3 || witness.taproot_annex().is_some() {
        return None;
    }
    let signature_bytes = witness.nth(0)?;
    if signature_bytes.len() != 65 {
        return None;
    }
    let signature = Signature::from_slice(signature_bytes).ok()?;
    if !matches!(
        signature.sighash_type,
        TapSighashType::AllPlusAnyoneCanPay | TapSighashType::SinglePlusAnyoneCanPay
    ) {
        return None;
    }
    let leaf = witness.taproot_leaf_script()?;
    if leaf.version != LeafVersion::TapScript || leaf.script.len() > MAX_LEAF_BYTES {
        return None;
    }
    let control = ControlBlock::decode(witness.taproot_control_block()?).ok()?;
    if control.leaf_version != LeafVersion::TapScript {
        return None;
    }

    let (signer, amount, insts) = parse_leaf(leaf.script, network)?;
    let mut root = TapNodeHash::from_script(leaf.script, control.leaf_version);
    for sibling in &control.merkle_branch {
        root = TapNodeHash::from_node_hashes(root, *sibling);
    }
    let (output_key, parity) = control.internal_key.tap_tweak(secp, Some(root));
    if parity != control.output_key_parity {
        return None;
    }
    let hypothetical_prevout = TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(output_key),
    };
    let leaf_hash = TapLeafHash::from_script(leaf.script, LeafVersion::TapScript);
    // Both allowed modes use ANYONECANPAY, whose own Prevouts::One is read
    // directly; the shared cache retains only transaction common hashes.
    let digest = sighash_cache
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::One(input_index, &hypothetical_prevout),
            leaf_hash,
            signature.sighash_type,
        )
        .ok()?;
    let message = Message::from_digest(digest.to_byte_array());
    secp.verify_schnorr(&signature.signature, &message, &signer)
        .ok()?;

    Some(AuthorizedInput {
        input: Input {
            previous_output: input.previous_output,
            input_index: input_index as u32,
            x_only_pubkey: signer,
            insts,
        },
        leaf_hash,
        signature_mode: signature.sighash_type,
    })
}

fn parse_leaf(script: &bitcoin::Script, network: Network) -> Option<(XOnlyPublicKey, u64, Insts)> {
    let mut instructions = script.instructions();
    let Some(Ok(Instruction::PushBytes(key))) = instructions.next() else {
        return None;
    };
    let signer = XOnlyPublicKey::from_slice(key.as_bytes()).ok()?;
    if instructions.next() != Some(Ok(Instruction::Op(OP_CHECKSIG))) {
        return None;
    }
    let Some(Ok(Instruction::PushBytes(false_value))) = instructions.next() else {
        return None;
    };
    if !false_value.is_empty() || instructions.next() != Some(Ok(Instruction::Op(OP_IF))) {
        return None;
    }
    let Some(Ok(Instruction::PushBytes(tag))) = instructions.next() else {
        return None;
    };
    if tag.as_bytes() != FORMAT_TAG {
        return None;
    }
    let Some(Ok(Instruction::PushBytes(amount_bytes))) = instructions.next() else {
        return None;
    };
    let amount = u64::from_be_bytes(amount_bytes.as_bytes().try_into().ok()?);
    if amount > MAX_MONEY_SATS {
        return None;
    }
    let Some(Ok(Instruction::PushBytes(network_bytes))) = instructions.next() else {
        return None;
    };
    if network_bytes.as_bytes() != network.magic().to_bytes() {
        return None;
    }

    let mut data = Vec::new();
    loop {
        match instructions.next() {
            Some(Ok(Instruction::PushBytes(chunk))) => {
                if data.len().checked_add(chunk.len())? > MAX_LEAF_BYTES {
                    return None;
                }
                data.extend_from_slice(chunk.as_bytes());
            }
            Some(Ok(Instruction::Op(OP_ENDIF))) => break,
            _ => return None,
        }
    }
    if instructions.next().is_some() || data.is_empty() {
        return None;
    }
    let insts = deserialize::<Insts>(&data).ok()?;
    if insts.ops.is_empty()
        || insts
            .aggregate
            .as_ref()
            .is_some_and(|aggregate| aggregate.signers.len() != insts.ops.len())
        || insts.ops.iter().any(|inst| {
            matches!(inst.kind, InstKind::Sponsor)
                || match &inst.kind {
                    InstKind::Publish { provenance, .. }
                    | InstKind::UpdateProvenance { provenance, .. } => {
                        provenance.validate().is_err()
                    }
                    _ => false,
                }
        })
    {
        return None;
    }
    Some((signer, amount, insts))
}
