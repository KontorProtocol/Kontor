use bitcoin::absolute::LockTime;
use bitcoin::consensus::serialize as serialize_bitcoin;
use bitcoin::hashes::Hash;
use bitcoin::opcodes::OP_FALSE;
use bitcoin::opcodes::all::{OP_CHECKSIG, OP_ENDIF, OP_IF, OP_RETURN};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::secp256k1::{Keypair, Message, Secp256k1, SecretKey};
use bitcoin::sighash::{Prevouts, SighashCache};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::transaction::{TxIn, Version};
use bitcoin::{
    Amount, Network, OutPoint, ScriptBuf, Sequence, TapLeafHash, TapSighashType,
    Transaction as BitcoinTransaction, TxOut, Txid, Witness,
};
use indexer_types::{Inst, InstKind, Insts, serialize};

use super::{AuthorizedInput, parse_authorized_input as parse_with_cache};
use crate::protocol::v1::transactions::filter_map_for_network;

fn parse_authorized_input(
    tx: &BitcoinTransaction,
    input_index: usize,
    network: Network,
) -> Option<AuthorizedInput> {
    let mut cache = SighashCache::new(tx);
    let secp = Secp256k1::verification_only();
    parse_with_cache(tx, &mut cache, &secp, input_index, network)
}

fn signed_transaction(
    mode: TapSighashType,
    input_index: usize,
    claimed_key_is_signer: bool,
    branched_control: bool,
    gas_limit: u64,
) -> BitcoinTransaction {
    let secp = Secp256k1::new();
    let signer = Keypair::from_secret_key(
        &secp,
        &SecretKey::from_slice(&[7; 32]).expect("dummy signer"),
    );
    let claimed_key = if claimed_key_is_signer {
        signer.x_only_public_key().0
    } else {
        Keypair::from_secret_key(
            &secp,
            &SecretKey::from_slice(&[8; 32]).expect("dummy other signer"),
        )
        .x_only_public_key()
        .0
    };
    let amount = 2000u64;
    let insts = Insts::single(Inst {
        gas_limit,
        kind: InstKind::Issuance,
    });
    let data = serialize(&insts).expect("dummy instructions");
    let script = Builder::new()
        .push_slice(claimed_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_slice(amount.to_be_bytes())
        .push_slice(Network::Regtest.magic().to_bytes())
        .push_slice(PushBytesBuf::try_from(data).expect("bounded dummy instructions"))
        .push_opcode(OP_ENDIF)
        .into_script();
    let mut tree = TaprootBuilder::new();
    if branched_control {
        tree = tree
            .add_leaf(1, script.clone())
            .expect("first leaf")
            .add_leaf(1, ScriptBuf::new())
            .expect("second leaf");
    } else {
        tree = tree.add_leaf(0, script.clone()).expect("single leaf");
    }
    let spend = tree.finalize(&secp, claimed_key).expect("dummy tree");
    let control = spend
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .expect("dummy control block");
    let prevout = TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(spend.output_key()),
    };
    let mut tx = BitcoinTransaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: (0..=input_index)
            .map(|index| TxIn {
                previous_output: OutPoint::new(Txid::from_byte_array([9; 32]), index as u32),
                script_sig: ScriptBuf::new(),
                sequence: Sequence::MAX,
                witness: Witness::new(),
            })
            .collect(),
        output: (0..=input_index)
            .map(|_| TxOut {
                value: Amount::ZERO,
                script_pubkey: Builder::new().push_opcode(OP_RETURN).into_script(),
            })
            .collect(),
    };
    let digest = SighashCache::new(&tx)
        .taproot_script_spend_signature_hash(
            input_index,
            &Prevouts::One(input_index, &prevout),
            TapLeafHash::from_script(&script, LeafVersion::TapScript),
            mode,
        )
        .expect("dummy sighash");
    let message = Message::from_digest(digest.to_byte_array());
    let mut signature = secp.sign_schnorr(&message, &signer).serialize().to_vec();
    signature.push(mode as u8);
    tx.input[input_index].witness =
        Witness::from_slice(&[signature, script.into_bytes(), control.serialize()]);
    tx
}

#[test]
fn consent_binds_claimed_key_leaf_amount_network_and_own_outpoint() {
    for mode in [
        TapSighashType::AllPlusAnyoneCanPay,
        TapSighashType::SinglePlusAnyoneCanPay,
    ] {
        let tx = signed_transaction(mode, 1, true, true, 1000);
        let authorized = parse_authorized_input(&tx, 1, Network::Regtest).expect("signed leaf");
        assert_eq!(authorized.input.input_index, 1);
        assert_eq!(authorized.signature_mode, mode);
        assert!(parse_authorized_input(&tx, 1, Network::Bitcoin).is_none());

        let mut changed_outpoint = tx.clone();
        changed_outpoint.input[1].previous_output.vout += 1;
        assert!(parse_authorized_input(&changed_outpoint, 1, Network::Regtest).is_none());

        let mut changed_output = tx.clone();
        changed_output.output[1].value = Amount::from_sat(1);
        assert!(parse_authorized_input(&changed_output, 1, Network::Regtest).is_none());

        let mut changed_other_input = tx.clone();
        changed_other_input.input[0].previous_output.vout += 1;
        assert!(parse_authorized_input(&changed_other_input, 1, Network::Regtest).is_some());

        let mut bad_control = tx.clone();
        let mut witness = bad_control.input[1].witness.to_vec();
        witness[2][0] ^= 1;
        bad_control.input[1].witness = Witness::from_slice(&witness);
        assert!(parse_authorized_input(&bad_control, 1, Network::Regtest).is_none());

        let mut implicit_sighash = tx.clone();
        let mut witness = implicit_sighash.input[1].witness.to_vec();
        witness[0].pop();
        implicit_sighash.input[1].witness = Witness::from_slice(&witness);
        assert!(parse_authorized_input(&implicit_sighash, 1, Network::Regtest).is_none());

        let mut with_annex = tx;
        let mut witness = with_annex.input[1].witness.to_vec();
        witness.push(vec![0x50, 0]);
        with_annex.input[1].witness = Witness::from_slice(&witness);
        assert!(parse_authorized_input(&with_annex, 1, Network::Regtest).is_none());

        let forged = signed_transaction(mode, 1, false, true, 1000);
        assert!(parse_authorized_input(&forged, 1, Network::Regtest).is_none());
    }
}

#[test]
fn single_anyonecanpay_requires_matching_output() {
    let mut tx = signed_transaction(TapSighashType::SinglePlusAnyoneCanPay, 1, true, false, 1000);
    tx.output.pop();
    assert!(parse_authorized_input(&tx, 1, Network::Regtest).is_none());
}

#[test]
fn shared_cache_uses_each_inputs_own_hypothetical_prevout() {
    let mut tx = signed_transaction(TapSighashType::SinglePlusAnyoneCanPay, 1, true, true, 1000);
    let secp = Secp256k1::new();
    let signer = Keypair::from_secret_key(
        &secp,
        &SecretKey::from_slice(&[9; 32]).expect("second dummy signer"),
    );
    let key = signer.x_only_public_key().0;
    let amount = 3000u64;
    let data = serialize(&Insts::single(Inst {
        gas_limit: 2200,
        kind: InstKind::Issuance,
    }))
    .expect("second dummy instructions");
    let script = Builder::new()
        .push_slice(key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_slice(amount.to_be_bytes())
        .push_slice(Network::Regtest.magic().to_bytes())
        .push_slice(PushBytesBuf::try_from(data).expect("bounded instructions"))
        .push_opcode(OP_ENDIF)
        .into_script();
    let spend = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .expect("leaf")
        .finalize(&secp, key)
        .expect("spend tree");
    let control = spend
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .expect("control");
    let prevout = TxOut {
        value: Amount::from_sat(amount),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(spend.output_key()),
    };
    let digest = SighashCache::new(&tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::One(0, &prevout),
            TapLeafHash::from_script(&script, LeafVersion::TapScript),
            TapSighashType::AllPlusAnyoneCanPay,
        )
        .expect("second sighash");
    let message = Message::from_digest(digest.to_byte_array());
    let mut signature = secp.sign_schnorr(&message, &signer).serialize().to_vec();
    signature.push(TapSighashType::AllPlusAnyoneCanPay as u8);
    tx.input[0].witness =
        Witness::from_slice(&[signature, script.into_bytes(), control.serialize()]);

    let mut cache = SighashCache::new(&tx);
    let verifier = Secp256k1::verification_only();
    let first = parse_with_cache(&tx, &mut cache, &verifier, 0, Network::Regtest);
    let second = parse_with_cache(&tx, &mut cache, &verifier, 1, Network::Regtest);
    assert_eq!(first.expect("first proof").input.x_only_pubkey, key);
    assert_eq!(
        second.expect("second proof").signature_mode,
        TapSighashType::SinglePlusAnyoneCanPay
    );
}

#[test]
fn sponsor_binds_the_sacp_recipients_exact_leaf_and_outpoint() {
    let mut tx = signed_transaction(TapSighashType::SinglePlusAnyoneCanPay, 1, true, false, 1000);
    assert!(filter_map_for_network((0, tx.clone()), Network::Regtest).is_none());

    let secp = Secp256k1::new();
    let buyer = Keypair::from_secret_key(
        &secp,
        &SecretKey::from_slice(&[10; 32]).expect("dummy buyer"),
    );
    let buyer_key = buyer.x_only_public_key().0;
    let target_point = serialize_bitcoin(&tx.input[1].previous_output);
    let target_leaf =
        ScriptBuf::from_bytes(tx.input[1].witness.nth(1).expect("seller leaf").to_vec());
    let sponsor = Insts::single(Inst {
        gas_limit: 10_000,
        kind: InstKind::SponsorBound {
            target_input_index: 1,
            target_txid: target_point[..32].try_into().expect("txid"),
            target_vout_le: target_point[32..].try_into().expect("vout"),
            target_leaf_hash: TapLeafHash::from_script(&target_leaf, LeafVersion::TapScript)
                .to_byte_array(),
            max_total_gas_le: 10_000u64.to_le_bytes(),
        },
    });
    let script = Builder::new()
        .push_slice(buyer_key.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_slice(3000u64.to_be_bytes())
        .push_slice(Network::Regtest.magic().to_bytes())
        .push_slice(
            PushBytesBuf::try_from(serialize(&sponsor).expect("Sponsor bytes")).expect("push"),
        )
        .push_opcode(OP_ENDIF)
        .into_script();
    let spend = TaprootBuilder::new()
        .add_leaf(0, script.clone())
        .expect("leaf")
        .finalize(&secp, buyer_key)
        .expect("buyer tree");
    let control = spend
        .control_block(&(script.clone(), LeafVersion::TapScript))
        .expect("buyer control");
    let prevout = TxOut {
        value: Amount::from_sat(3000),
        script_pubkey: ScriptBuf::new_p2tr_tweaked(spend.output_key()),
    };
    let digest = SighashCache::new(&tx)
        .taproot_script_spend_signature_hash(
            0,
            &Prevouts::One(0, &prevout),
            TapLeafHash::from_script(&script, LeafVersion::TapScript),
            TapSighashType::AllPlusAnyoneCanPay,
        )
        .expect("buyer sighash");
    let message = Message::from_digest(digest.to_byte_array());
    let mut signature = secp.sign_schnorr(&message, &buyer).serialize().to_vec();
    signature.push(TapSighashType::AllPlusAnyoneCanPay as u8);
    tx.input[0].witness =
        Witness::from_slice(&[signature, script.into_bytes(), control.serialize()]);

    let recognized =
        filter_map_for_network((0, tx.clone()), Network::Regtest).expect("both authorized inputs");
    assert_eq!(recognized.inputs.len(), 2);
    assert_eq!(recognized.inputs[0].input_index, 0);
    assert_eq!(recognized.inputs[1].input_index, 1);

    let mut changed_leaf = tx.clone();
    changed_leaf.input[1].witness =
        signed_transaction(TapSighashType::SinglePlusAnyoneCanPay, 1, true, false, 2000).input[1]
            .witness
            .clone();
    assert!(filter_map_for_network((0, changed_leaf), Network::Regtest).is_none());

    let mut missing_buyer = tx;
    missing_buyer.input[0].witness = Witness::new();
    assert!(filter_map_for_network((0, missing_buyer), Network::Regtest).is_none());
}
