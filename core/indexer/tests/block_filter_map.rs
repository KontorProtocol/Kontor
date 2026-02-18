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
use indexer_types::{BlsBulkOp, ContractAddress, Inst, Op, Signer, serialize};

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
fn filter_map_parses_valid_blsbulk_envelope() {
    let xonly = random_xonly();
    let contract = ContractAddress {
        name: "c".to_string(),
        height: 1,
        tx_index: 2,
    };
    let op = BlsBulkOp::Call {
        signer_id: 7,
        gas_limit: 123,
        contract,
        expr: "noop()".to_string(),
    };
    let inst = Inst::BlsBulk {
        ops: vec![op.clone()],
        signature: vec![9u8; 48],
    };
    let payload = serialize(&inst).expect("serialize Inst");
    let tap_script =
        build_inscription(payload, TestPublicKey::Taproot(&xonly)).expect("build tap script");
    let tx = tx_with_taproot_script_witness(tap_script, xonly);

    let parsed = filter_map((0, tx)).expect("expected tx to be recognized as Kontor tx");
    assert_eq!(parsed.ops.len(), 1);
    match &parsed.ops[0] {
        Op::BlsBulk {
            metadata,
            ops,
            signature,
        } => {
            assert_eq!(metadata.signer, Signer::XOnlyPubKey(xonly.to_string()));
            assert_eq!(ops.as_slice(), &[op]);
            assert_eq!(signature.as_slice(), &[9u8; 48]);
        }
        other => panic!("expected Op::BlsBulk, got {other:?}"),
    }
}

#[test]
fn filter_map_rejects_wrong_marker() {
    let xonly = random_xonly();
    let inst = Inst::Issuance;
    let payload = serialize(&inst).expect("serialize Inst");

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
    let inst = Inst::Issuance;
    let payload = serialize(&inst).expect("serialize Inst");

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
    let inst = Inst::Call {
        gas_limit: 7,
        contract: ContractAddress {
            name: "arith".to_string(),
            height: 1,
            tx_index: 0,
        },
        expr: "eval(10, id)".to_string(),
    };
    let payload = serialize(&inst).expect("serialize Inst");

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
    assert_eq!(parsed.ops.len(), 1);
    match &parsed.ops[0] {
        Op::Call {
            metadata,
            gas_limit,
            contract,
            expr,
        } => {
            assert_eq!(metadata.signer, Signer::XOnlyPubKey(xonly.to_string()));
            assert_eq!(*gas_limit, 7);
            assert_eq!(contract.name, "arith");
            assert_eq!(contract.height, 1);
            assert_eq!(contract.tx_index, 0);
            assert_eq!(expr, "eval(10, id)");
        }
        other => panic!("expected Op::Call, got {other:?}"),
    }
}

#[test]
fn filter_map_rejects_non_pushbytes_inside_envelope() {
    let xonly = random_xonly();
    let inst = Inst::Issuance;
    let payload = serialize(&inst).expect("serialize Inst");

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
    let inst = Inst::Issuance;
    let payload = serialize(&inst).expect("serialize Inst");

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
