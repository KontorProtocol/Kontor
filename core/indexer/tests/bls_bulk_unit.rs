use bitcoin::Network;
use blst::BLST_ERROR;
use blst::min_sig::AggregateSignature;
use indexer::bls::KONTOR_BLS_DST;
use indexer::bls::{bls_derivation_path, derive_bls_secret_key_eip2333};
use indexer_types::{BlsBulkOp, ContractAddress, Signer};
use proptest::prelude::*;

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
        nonce: 0,
        gas_limit: 50_000,
        contract: contract.clone(),
        expr: "eval(10, id)".to_string(),
    };
    let op2 = BlsBulkOp::Call {
        signer_id: 2,
        nonce: 0,
        gas_limit: 50_000,
        contract,
        expr: "eval(10, sum({y: 8}))".to_string(),
    };

    let msg1 = op1.signing_message().unwrap();
    let msg2 = op2.signing_message().unwrap();
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
        nonce: 0,
        gas_limit: 50_000,
        contract: contract.clone(),
        expr: "eval(10, id)".to_string(),
    };
    let op2 = BlsBulkOp::Call {
        signer_id: 2,
        nonce: 0,
        gas_limit: 50_000,
        contract,
        expr: "eval(10, sum({y: 8}))".to_string(),
    };

    let msg1 = op1.signing_message().unwrap();
    let msg2 = op2.signing_message().unwrap();
    let sig1 = sk1.sign(&msg1, KONTOR_BLS_DST, &[]);
    let sig2 = sk2.sign(&msg2, KONTOR_BLS_DST, &[]);

    let aggregate = AggregateSignature::aggregate(&[&sig1, &sig2], true)
        .expect("failed to aggregate signatures");
    let aggregate_sig = aggregate.to_signature();

    // Mutate op1 after signing (e.g. bundler changes gas_limit). Verification must fail.
    let BlsBulkOp::Call {
        signer_id,
        nonce,
        gas_limit: _,
        contract,
        expr,
    } = &op1
    else {
        panic!("expected BlsBulkOp::Call");
    };
    let op1_mutated = BlsBulkOp::Call {
        signer_id: *signer_id,
        nonce: *nonce,
        gas_limit: 60_000,
        contract: contract.clone(),
        expr: expr.clone(),
    };
    let msg1_mutated = op1_mutated.signing_message().unwrap();

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
        nonce: 7,
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
        nonce: 0,
        gas_limit: 50_000,
        contract: contract.clone(),
        expr: "eval(10, id)".to_string(),
    };
    let op2 = BlsBulkOp::Call {
        signer_id: 2,
        nonce: 0,
        gas_limit: 50_000,
        contract,
        expr: "eval(10, id)".to_string(),
    };

    let msg1 = op1.signing_message().unwrap();
    let msg2 = op2.signing_message().unwrap();
    assert_ne!(msg1, msg2, "signer_id must affect signed bytes");
}

#[test]
fn bls_bulk_message_changes_when_nonce_changes() {
    let contract = ContractAddress {
        name: "arith".to_string(),
        height: 123,
        tx_index: 4,
    };
    let op1 = BlsBulkOp::Call {
        signer_id: 1,
        nonce: 0,
        gas_limit: 50_000,
        contract: contract.clone(),
        expr: "eval(10, id)".to_string(),
    };
    let op2 = BlsBulkOp::Call {
        signer_id: 1,
        nonce: 1,
        gas_limit: 50_000,
        contract,
        expr: "eval(10, id)".to_string(),
    };

    let msg1 = op1.signing_message().unwrap();
    let msg2 = op2.signing_message().unwrap();
    assert_ne!(msg1, msg2, "nonce must affect signed bytes");
}

#[test]
fn bls_bulk_message_changes_when_gas_limit_changes() {
    let contract = ContractAddress {
        name: "arith".to_string(),
        height: 123,
        tx_index: 4,
    };
    let op1 = BlsBulkOp::Call {
        signer_id: 1,
        nonce: 0,
        gas_limit: 50_000,
        contract: contract.clone(),
        expr: "eval(10, id)".to_string(),
    };
    let op2 = BlsBulkOp::Call {
        signer_id: 1,
        nonce: 0,
        gas_limit: 60_000,
        contract,
        expr: "eval(10, id)".to_string(),
    };

    let msg1 = op1.signing_message().unwrap();
    let msg2 = op2.signing_message().unwrap();
    assert_ne!(msg1, msg2, "gas_limit must affect signed bytes");
}

#[test]
fn bls_bulk_message_changes_when_contract_name_changes() {
    let op1 = BlsBulkOp::Call {
        signer_id: 1,
        nonce: 0,
        gas_limit: 50_000,
        contract: ContractAddress {
            name: "token".to_string(),
            height: 1,
            tx_index: 0,
        },
        expr: "transfer(\"x\", 10)".to_string(),
    };
    let op2 = BlsBulkOp::Call {
        signer_id: 1,
        nonce: 0,
        gas_limit: 50_000,
        contract: ContractAddress {
            name: "pool".to_string(),
            height: 1,
            tx_index: 0,
        },
        expr: "transfer(\"x\", 10)".to_string(),
    };

    let msg1 = op1.signing_message().unwrap();
    let msg2 = op2.signing_message().unwrap();
    assert_ne!(msg1, msg2, "contract name must affect signed bytes");
}

#[test]
fn bls_bulk_message_changes_when_contract_height_changes() {
    let op1 = BlsBulkOp::Call {
        signer_id: 1,
        nonce: 0,
        gas_limit: 50_000,
        contract: ContractAddress {
            name: "token".to_string(),
            height: 1,
            tx_index: 0,
        },
        expr: "transfer(\"x\", 10)".to_string(),
    };
    let op2 = BlsBulkOp::Call {
        signer_id: 1,
        nonce: 0,
        gas_limit: 50_000,
        contract: ContractAddress {
            name: "token".to_string(),
            height: 2,
            tx_index: 0,
        },
        expr: "transfer(\"x\", 10)".to_string(),
    };

    let msg1 = op1.signing_message().unwrap();
    let msg2 = op2.signing_message().unwrap();
    assert_ne!(msg1, msg2, "contract height must affect signed bytes");
}

#[test]
fn bls_bulk_message_changes_when_contract_tx_index_changes() {
    let op1 = BlsBulkOp::Call {
        signer_id: 1,
        nonce: 0,
        gas_limit: 50_000,
        contract: ContractAddress {
            name: "token".to_string(),
            height: 1,
            tx_index: 0,
        },
        expr: "transfer(\"x\", 10)".to_string(),
    };
    let op2 = BlsBulkOp::Call {
        signer_id: 1,
        nonce: 0,
        gas_limit: 50_000,
        contract: ContractAddress {
            name: "token".to_string(),
            height: 1,
            tx_index: 1,
        },
        expr: "transfer(\"x\", 10)".to_string(),
    };

    let msg1 = op1.signing_message().unwrap();
    let msg2 = op2.signing_message().unwrap();
    assert_ne!(msg1, msg2, "contract tx_index must affect signed bytes");
}

#[test]
fn bls_bulk_message_changes_when_expr_changes() {
    let contract = ContractAddress {
        name: "token".to_string(),
        height: 1,
        tx_index: 0,
    };
    let op1 = BlsBulkOp::Call {
        signer_id: 1,
        nonce: 0,
        gas_limit: 50_000,
        contract: contract.clone(),
        expr: "transfer(\"alice\", 10)".to_string(),
    };
    let op2 = BlsBulkOp::Call {
        signer_id: 1,
        nonce: 0,
        gas_limit: 50_000,
        contract,
        expr: "transfer(\"bob\", 10)".to_string(),
    };

    let msg1 = op1.signing_message().unwrap();
    let msg2 = op2.signing_message().unwrap();
    assert_ne!(msg1, msg2, "expr must affect signed bytes");
}

/// Op references signer A's registry ID but is signed by signer B's secret
/// key. The aggregate signature is mathematically valid for B's pubkey, but
/// the verifier resolves A's pubkey from the registry — mismatch must fail.
#[test]
fn bls_bulk_wrong_signer_key_fails_single_op() {
    let sk_a = derive_test_key(20);
    let sk_b = derive_test_key(21);
    let pk_a = sk_a.sk_to_pk();

    let op = BlsBulkOp::Call {
        signer_id: 1,
        nonce: 0,
        gas_limit: 50_000,
        contract: ContractAddress {
            name: "token".to_string(),
            height: 1,
            tx_index: 0,
        },
        expr: "transfer(\"dest\", 100)".to_string(),
    };
    let msg = op.signing_message().unwrap();

    // B signs A's op.
    let sig_by_b = sk_b.sign(&msg, KONTOR_BLS_DST, &[]);

    // Verifier has A's pubkey (from registry). Verification must fail.
    let result = sig_by_b.aggregate_verify(
        true,
        &[msg.as_slice()],
        KONTOR_BLS_DST,
        &[&pk_a],
        true,
    );
    assert_ne!(
        result,
        BLST_ERROR::BLST_SUCCESS,
        "op signed by wrong key must fail verification against the registered pubkey"
    );
}

/// Two-signer bundle where signer B's op is signed by A's key (key swap).
/// Both ops individually have valid BLS signatures — just for the wrong
/// signer. The aggregate must still fail.
#[test]
fn bls_bulk_wrong_signer_key_fails_multi_op_key_swap() {
    let sk_a = derive_test_key(30);
    let sk_b = derive_test_key(31);
    let pk_a = sk_a.sk_to_pk();
    let pk_b = sk_b.sk_to_pk();

    let contract = ContractAddress {
        name: "token".to_string(),
        height: 1,
        tx_index: 0,
    };

    let op_a = BlsBulkOp::Call {
        signer_id: 1,
        nonce: 0,
        gas_limit: 50_000,
        contract: contract.clone(),
        expr: "transfer(\"x\", 10)".to_string(),
    };
    let op_b = BlsBulkOp::Call {
        signer_id: 2,
        nonce: 0,
        gas_limit: 50_000,
        contract,
        expr: "transfer(\"y\", 20)".to_string(),
    };
    let msg_a = op_a.signing_message().unwrap();
    let msg_b = op_b.signing_message().unwrap();

    // Swap: A signs B's op, B signs A's op.
    let sig_a_by_b = sk_b.sign(&msg_a, KONTOR_BLS_DST, &[]);
    let sig_b_by_a = sk_a.sign(&msg_b, KONTOR_BLS_DST, &[]);

    let aggregate = AggregateSignature::aggregate(&[&sig_a_by_b, &sig_b_by_a], true)
        .expect("aggregation of valid signatures must succeed");
    let aggregate_sig = aggregate.to_signature();

    // Verifier resolves pk_a for op_a and pk_b for op_b.
    let result = aggregate_sig.aggregate_verify(
        true,
        &[msg_a.as_slice(), msg_b.as_slice()],
        KONTOR_BLS_DST,
        &[&pk_a, &pk_b],
        true,
    );
    assert_ne!(
        result,
        BLST_ERROR::BLST_SUCCESS,
        "swapped signer keys must fail aggregate verification"
    );
}

/// One op signed correctly, the other signed by the wrong key. The valid
/// op must not "save" the bundle — aggregate verification is all-or-nothing.
#[test]
fn bls_bulk_one_correct_one_wrong_key_fails_entire_aggregate() {
    let sk_a = derive_test_key(40);
    let sk_b = derive_test_key(41);
    let sk_c = derive_test_key(42);
    let pk_a = sk_a.sk_to_pk();
    let pk_b = sk_b.sk_to_pk();

    let contract = ContractAddress {
        name: "token".to_string(),
        height: 1,
        tx_index: 0,
    };

    let op_a = BlsBulkOp::Call {
        signer_id: 1,
        nonce: 0,
        gas_limit: 50_000,
        contract: contract.clone(),
        expr: "transfer(\"x\", 10)".to_string(),
    };
    let op_b = BlsBulkOp::Call {
        signer_id: 2,
        nonce: 0,
        gas_limit: 50_000,
        contract,
        expr: "transfer(\"y\", 20)".to_string(),
    };
    let msg_a = op_a.signing_message().unwrap();
    let msg_b = op_b.signing_message().unwrap();

    // A signs correctly; C (impersonator) signs B's op.
    let sig_a = sk_a.sign(&msg_a, KONTOR_BLS_DST, &[]);
    let sig_b_by_c = sk_c.sign(&msg_b, KONTOR_BLS_DST, &[]);

    let aggregate = AggregateSignature::aggregate(&[&sig_a, &sig_b_by_c], true)
        .expect("aggregation of valid signatures must succeed");
    let aggregate_sig = aggregate.to_signature();

    let result = aggregate_sig.aggregate_verify(
        true,
        &[msg_a.as_slice(), msg_b.as_slice()],
        KONTOR_BLS_DST,
        &[&pk_a, &pk_b],
        true,
    );
    assert_ne!(
        result,
        BLST_ERROR::BLST_SUCCESS,
        "one impersonated signer must fail the entire aggregate"
    );
}

// ---------------------------------------------------------------------------
// Property tests — signing_message must never panic on arbitrary op fields
// ---------------------------------------------------------------------------

proptest! {
    #[test]
    fn signing_message_no_panic_on_arbitrary_call(
        signer_id in any::<u64>(),
        nonce in any::<u64>(),
        gas_limit in any::<u64>(),
        name in any::<String>(),
        height in any::<u64>(),
        tx_index in any::<u64>(),
        expr in any::<String>(),
    ) {
        let op = BlsBulkOp::Call {
            signer_id,
            nonce,
            gas_limit,
            contract: ContractAddress { name, height, tx_index },
            expr,
        };
        let msg = op.signing_message().expect("signing_message must not fail");
        prop_assert!(!msg.is_empty(), "signing_message must produce non-empty output");
    }

    #[test]
    fn signing_message_no_panic_on_arbitrary_register(
        signer_hex in proptest::collection::vec(any::<u8>(), 32..=32)
            .prop_map(|b| hex::encode(&b)),
        bls_pubkey in proptest::collection::vec(any::<u8>(), 0..256),
        schnorr_sig in proptest::collection::vec(any::<u8>(), 0..256),
        bls_sig in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let op = BlsBulkOp::RegisterBlsKey {
            signer: Signer::XOnlyPubKey(signer_hex),
            bls_pubkey,
            schnorr_sig,
            bls_sig,
        };
        let msg = op.signing_message().expect("signing_message must not fail");
        prop_assert!(!msg.is_empty(), "signing_message must produce non-empty output");
    }
}

