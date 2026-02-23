use bitcoin::Network;
use blst::BLST_ERROR;
use blst::min_sig::AggregateSignature;
use indexer::bls::{KONTOR_BLS_DST, bls_derivation_path, derive_bls_secret_key_eip2333};
use indexer_types::{BlsBulkOp, ContractAddress};

const KONTOR_OP_PREFIX: &[u8] = b"KONTOR-OP-V1";

fn build_kontor_op_message(op: &BlsBulkOp) -> Vec<u8> {
    let op_bytes = indexer_types::serialize(op).expect("failed to serialize BlsBulkOp");
    let mut msg = Vec::with_capacity(KONTOR_OP_PREFIX.len() + op_bytes.len());
    msg.extend_from_slice(KONTOR_OP_PREFIX);
    msg.extend_from_slice(&op_bytes);
    msg
}

fn derive_test_key(seed_byte: u8) -> blst::min_sig::SecretKey {
    let seed = [seed_byte; 64];
    derive_bls_secret_key_eip2333(&seed, &bls_derivation_path(Network::Regtest))
        .expect("failed to derive EIP-2333 secret key")
}

#[test]
fn bls_bulk_aggregate_signature_roundtrip() {
    let sk1 = derive_test_key(1);
    let sk2 = derive_test_key(2);
    let pk1 = sk1.sk_to_pk();
    let pk2 = sk2.sk_to_pk();

    let contract = ContractAddress {
        name: "arith".to_string(),
        height: 123,
        tx_index: 4,
    };

    let op1 = BlsBulkOp::Call {
        signer_id: 1,
        gas_limit: 50_000,
        contract: contract.clone(),
        expr: "eval(10, id)".to_string(),
    };
    let op2 = BlsBulkOp::Call {
        signer_id: 2,
        gas_limit: 50_000,
        contract,
        expr: "eval(10, sum({y: 8}))".to_string(),
    };

    let msg1 = build_kontor_op_message(&op1);
    let msg2 = build_kontor_op_message(&op2);
    let sig1 = sk1.sign(&msg1, KONTOR_BLS_DST, &[]);
    let sig2 = sk2.sign(&msg2, KONTOR_BLS_DST, &[]);

    let aggregate = AggregateSignature::aggregate(&[&sig1, &sig2], true)
        .expect("failed to aggregate signatures");
    let aggregate_sig = aggregate.to_signature();

    let messages = [msg1, msg2];
    let msg_refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    let pk_refs = [&pk1, &pk2];
    let verify_result =
        aggregate_sig.aggregate_verify(true, msg_refs.as_slice(), KONTOR_BLS_DST, &pk_refs, true);
    assert_eq!(
        verify_result,
        BLST_ERROR::BLST_SUCCESS,
        "aggregate signature verification should succeed"
    );
}

#[test]
fn bls_bulk_aggregate_signature_fails_if_op_bytes_change() {
    let sk1 = derive_test_key(7);
    let sk2 = derive_test_key(9);
    let pk1 = sk1.sk_to_pk();
    let pk2 = sk2.sk_to_pk();

    let contract = ContractAddress {
        name: "arith".to_string(),
        height: 123,
        tx_index: 4,
    };

    let op1 = BlsBulkOp::Call {
        signer_id: 1,
        gas_limit: 50_000,
        contract: contract.clone(),
        expr: "eval(10, id)".to_string(),
    };
    let op2 = BlsBulkOp::Call {
        signer_id: 2,
        gas_limit: 50_000,
        contract,
        expr: "eval(10, sum({y: 8}))".to_string(),
    };

    let msg1 = build_kontor_op_message(&op1);
    let msg2 = build_kontor_op_message(&op2);
    let sig1 = sk1.sign(&msg1, KONTOR_BLS_DST, &[]);
    let sig2 = sk2.sign(&msg2, KONTOR_BLS_DST, &[]);

    let aggregate = AggregateSignature::aggregate(&[&sig1, &sig2], true)
        .expect("failed to aggregate signatures");
    let aggregate_sig = aggregate.to_signature();

    // Mutate op1 after signing (e.g. bundler changes gas_limit). Verification must fail.
    let BlsBulkOp::Call {
        signer_id,
        gas_limit: _,
        contract,
        expr,
    } = &op1
    else {
        panic!("expected BlsBulkOp::Call");
    };
    let op1_mutated = BlsBulkOp::Call {
        signer_id: *signer_id,
        gas_limit: 60_000,
        contract: contract.clone(),
        expr: expr.clone(),
    };
    let msg1_mutated = build_kontor_op_message(&op1_mutated);

    let messages = [msg1_mutated, msg2];
    let msg_refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    let pk_refs = [&pk1, &pk2];
    let verify_result =
        aggregate_sig.aggregate_verify(true, msg_refs.as_slice(), KONTOR_BLS_DST, &pk_refs, true);
    assert_ne!(
        verify_result,
        BLST_ERROR::BLST_SUCCESS,
        "aggregate signature verification should fail when op bytes change"
    );
}

#[test]
fn bls_bulk_call_roundtrip_serialization_preserves_signer_id() {
    let contract = ContractAddress {
        name: "arith".to_string(),
        height: 7,
        tx_index: 3,
    };
    let op = BlsBulkOp::Call {
        signer_id: 42,
        gas_limit: 50_000,
        contract,
        expr: "eval(10, id)".to_string(),
    };

    let bytes = indexer_types::serialize(&op).expect("serialize");
    let decoded: BlsBulkOp = indexer_types::deserialize(&bytes).expect("deserialize");
    assert_eq!(decoded, op);
}

#[test]
fn bls_bulk_message_changes_when_signer_id_changes() {
    let contract = ContractAddress {
        name: "arith".to_string(),
        height: 123,
        tx_index: 4,
    };
    let op1 = BlsBulkOp::Call {
        signer_id: 1,
        gas_limit: 50_000,
        contract: contract.clone(),
        expr: "eval(10, id)".to_string(),
    };
    let op2 = BlsBulkOp::Call {
        signer_id: 2,
        gas_limit: 50_000,
        contract,
        expr: "eval(10, id)".to_string(),
    };

    let msg1 = build_kontor_op_message(&op1);
    let msg2 = build_kontor_op_message(&op2);
    assert_ne!(msg1, msg2, "signer_id must affect signed bytes");
}
