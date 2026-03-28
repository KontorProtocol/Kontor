use bitcoin::absolute::LockTime;
use bitcoin::key::rand;
use bitcoin::key::{Keypair, Secp256k1};
use bitcoin::opcodes::all::{OP_ADD, OP_CHECKSIG, OP_ENDIF, OP_IF};
use bitcoin::opcodes::{OP_0, OP_FALSE};
use bitcoin::script::{Builder, PushBytesBuf};
use bitcoin::taproot::{LeafVersion, TaprootBuilder};
use bitcoin::transaction::Version;
use bitcoin::{Amount, OutPoint, ScriptBuf, Sequence, Transaction, TxIn, TxOut, Witness};
use indexer::block::filter_map;
use indexer::test_utils::{PublicKey as TestPublicKey, build_inscription};
use indexer_types::{AggregateInfo, ContractAddress, Inst, Insts, Signer, serialize};

fn tx_with_taproot_script_witness(
    tap_script: ScriptBuf,
    internal_key: bitcoin::XOnlyPublicKey,
) -> Transaction {
    let secp = Secp256k1::new();
    let spend_info = TaprootBuilder::new()
        .add_leaf(0, tap_script.clone())
        .expect("add_leaf")
        .finalize(&secp, internal_key)
        .expect("finalize");
    let control_block = spend_info
        .control_block(&(tap_script.clone(), LeafVersion::TapScript))
        .expect("control_block");

    let mut witness = Witness::new();
    // The parser does not validate this signature; it only needs a script-path witness shape.
    witness.push(vec![0u8; 64]);
    witness.push(tap_script.as_bytes());
    witness.push(control_block.serialize());

    Transaction {
        version: Version(2),
        lock_time: LockTime::ZERO,
        input: vec![TxIn {
            previous_output: OutPoint::null(),
            script_sig: ScriptBuf::new(),
            sequence: Sequence::MAX,
            witness,
        }],
        output: vec![TxOut {
            value: Amount::from_sat(0),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

fn random_xonly() -> bitcoin::XOnlyPublicKey {
    let secp = Secp256k1::new();
    Keypair::new(&secp, &mut rand::thread_rng())
        .x_only_public_key()
        .0
}

#[test]
fn filter_map_parses_valid_aggregate_envelope() {
    let xonly = random_xonly();
    let contract = ContractAddress {
        name: "c".to_string(),
        height: 1,
        tx_index: 2,
    };
    let call_inst = Inst::Call {
        gas_limit: 123,
        contract,
        nonce: Some(0),
        expr: "noop()".to_string(),
    };
    let insts = Insts {
        ops: vec![call_inst.clone()],
        aggregate: Some(AggregateInfo {
            signer_ids: vec![7],
            signature: vec![9u8; 48],
        }),
    };
    let payload = serialize(&insts).expect("serialize Insts");
    let tap_script =
        build_inscription(payload, TestPublicKey::Taproot(&xonly)).expect("build tap script");
    let tx = tx_with_taproot_script_witness(tap_script, xonly);

    let parsed = filter_map((0, tx)).expect("expected tx to be recognized as Kontor tx");
    assert_eq!(parsed.inputs.len(), 1);
    let input = &parsed.inputs[0];
    assert_eq!(input.witness_signer, Signer::XOnlyPubKey(xonly.to_string()));
    assert!(input.insts.is_aggregate());
    assert_eq!(input.insts.ops, vec![call_inst]);
    let agg = input.insts.aggregate.as_ref().unwrap();
    assert_eq!(agg.signer_ids, vec![7]);
    assert_eq!(agg.signature, vec![9u8; 48]);
}

#[test]
fn filter_map_rejects_wrong_marker() {
    let xonly = random_xonly();
    let insts = Insts {
        ops: vec![Inst::Issuance],
        aggregate: None,
    };
    let payload = serialize(&insts).expect("serialize Insts");

    let tap_script = Builder::new()
        .push_slice(xonly.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kor")
        .push_opcode(OP_0)
        .push_slice(PushBytesBuf::try_from(payload).expect("pushbytes"))
        .push_opcode(OP_ENDIF)
        .into_script();

    let tx = tx_with_taproot_script_witness(tap_script, xonly);
    assert!(filter_map((0, tx)).is_none());
}

#[test]
fn filter_map_rejects_trailing_instructions_after_endif() {
    let xonly = random_xonly();
    let insts = Insts {
        ops: vec![Inst::Issuance],
        aggregate: None,
    };
    let payload = serialize(&insts).expect("serialize Insts");

    let tap_script = Builder::new()
        .push_slice(xonly.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0)
        .push_slice(PushBytesBuf::try_from(payload).expect("pushbytes"))
        .push_opcode(OP_ENDIF)
        // Trailing instruction should cause rejection.
        .push_opcode(OP_0)
        .into_script();

    let tx = tx_with_taproot_script_witness(tap_script, xonly);
    assert!(filter_map((0, tx)).is_none());
}

#[test]
fn filter_map_concatenates_multi_push_payload() {
    let xonly = random_xonly();
    let call_inst = Inst::Call {
        gas_limit: 7,
        contract: ContractAddress {
            name: "arith".to_string(),
            height: 1,
            tx_index: 0,
        },
        nonce: None,
        expr: "eval(10, id)".to_string(),
    };
    let insts = Insts {
        ops: vec![call_inst.clone()],
        aggregate: None,
    };
    let payload = serialize(&insts).expect("serialize Insts");

    let mid = payload.len() / 2;
    let (p0, p1) = payload.split_at(mid);

    let tap_script = Builder::new()
        .push_slice(xonly.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0)
        .push_slice(PushBytesBuf::try_from(p0.to_vec()).expect("pushbytes"))
        .push_slice(PushBytesBuf::try_from(p1.to_vec()).expect("pushbytes"))
        .push_opcode(OP_ENDIF)
        .into_script();

    let tx = tx_with_taproot_script_witness(tap_script, xonly);
    let parsed = filter_map((0, tx)).expect("expected tx to be recognized as Kontor tx");
    assert_eq!(parsed.inputs.len(), 1);
    let input = &parsed.inputs[0];
    assert_eq!(input.witness_signer, Signer::XOnlyPubKey(xonly.to_string()));
    assert!(!input.insts.is_aggregate());
    assert_eq!(input.insts.ops, vec![call_inst]);
}

#[test]
fn filter_map_rejects_non_pushbytes_inside_envelope() {
    let xonly = random_xonly();
    let insts = Insts {
        ops: vec![Inst::Issuance],
        aggregate: None,
    };
    let payload = serialize(&insts).expect("serialize Insts");

    let tap_script = Builder::new()
        .push_slice(xonly.serialize())
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0)
        .push_slice(PushBytesBuf::try_from(payload).expect("pushbytes"))
        // Non-push opcode before OP_ENDIF must cause rejection.
        .push_opcode(OP_ADD)
        .push_opcode(OP_ENDIF)
        .into_script();

    let tx = tx_with_taproot_script_witness(tap_script, xonly);
    assert!(filter_map((0, tx)).is_none());
}

#[test]
fn filter_map_rejects_invalid_xonly_pubkey_bytes() {
    let internal_key = random_xonly();
    let insts = Insts {
        ops: vec![Inst::Issuance],
        aggregate: None,
    };
    let payload = serialize(&insts).expect("serialize Insts");

    let tap_script = Builder::new()
        .push_slice([0u8; 32])
        .push_opcode(OP_CHECKSIG)
        .push_opcode(OP_FALSE)
        .push_opcode(OP_IF)
        .push_slice(b"kon")
        .push_opcode(OP_0)
        .push_slice(PushBytesBuf::try_from(payload).expect("pushbytes"))
        .push_opcode(OP_ENDIF)
        .into_script();

    let tx = tx_with_taproot_script_witness(tap_script, internal_key);
    assert!(filter_map((0, tx)).is_none());
}
