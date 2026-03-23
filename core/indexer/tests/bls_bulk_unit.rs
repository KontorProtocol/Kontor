use bitcoin::Network;
use blst::BLST_ERROR;
use blst::min_sig::AggregateSignature;
use indexer::bls::KONTOR_BLS_DST;
use indexer::bls::{bls_derivation_path, derive_bls_secret_key_eip2333};
use indexer_types::{AggregateInst, ContractAddress, Inst, SignerRef};
use proptest::prelude::*;

fn derive_test_key(seed_byte: u8) -> blst::min_sig::SecretKey {
    let seed = [seed_byte; 64];
    derive_bls_secret_key_eip2333(&seed, &bls_derivation_path(Network::Regtest))
        .expect("failed to derive EIP-2333 secret key")
}

//TODO!
fn call_op(
    signer_id: u64,
    nonce: u64,
    gas_limit: u64,
    contract: ContractAddress,
    expr: impl Into<String>,
) -> AggregateInst {
    AggregateInst {
        signer: SignerRef::SignerId { id: signer_id },
        inst: Inst::Call {
            gas_limit,
            contract,
            nonce: Some(nonce),
            expr: expr.into(),
        },
    }
}

fn register_op(
    signer_hex: impl Into<String>,
    bls_pubkey: Vec<u8>,
    schnorr_sig: Vec<u8>,
    bls_sig: Vec<u8>,
) -> AggregateInst {
    AggregateInst {
        signer: SignerRef::XOnlyPubKey(signer_hex.into()),
        inst: Inst::RegisterBlsKey {
            bls_pubkey,
            schnorr_sig,
            bls_sig,
        },
    }
}

#[test]
fn aggregate_signature_roundtrip() {
    let sk1 = derive_test_key(1);
    let sk2 = derive_test_key(2);
    let pk1 = sk1.sk_to_pk();
    let pk2 = sk2.sk_to_pk();

    let contract = ContractAddress {
        name: "arith".to_string(),
        height: 123,
        tx_index: 4,
    };

    let op1 = call_op(1, 0, 50_000, contract.clone(), "eval(10, id)");
    let op2 = call_op(2, 0, 50_000, contract, "eval(10, sum({y: 8}))");

    let msg1 = op1.signing_message().unwrap();
    let msg2 = op2.signing_message().unwrap();
    let sig1 = sk1.sign(&msg1, KONTOR_BLS_DST, &[]);
    let sig2 = sk2.sign(&msg2, KONTOR_BLS_DST, &[]);

    let aggregate = AggregateSignature::aggregate(&[&sig1, &sig2], true).unwrap();
    let aggregate_sig = aggregate.to_signature();

    let messages = [msg1, msg2];
    let msg_refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    let pk_refs = [&pk1, &pk2];
    assert_eq!(
        aggregate_sig.aggregate_verify(true, msg_refs.as_slice(), KONTOR_BLS_DST, &pk_refs, true),
        BLST_ERROR::BLST_SUCCESS
    );
}

#[test]
fn aggregate_signature_fails_if_op_bytes_change() {
    let sk1 = derive_test_key(7);
    let sk2 = derive_test_key(9);
    let pk1 = sk1.sk_to_pk();
    let pk2 = sk2.sk_to_pk();

    let contract = ContractAddress {
        name: "arith".to_string(),
        height: 123,
        tx_index: 4,
    };

    let op1 = call_op(1, 0, 50_000, contract.clone(), "eval(10, id)");
    let op2 = call_op(2, 0, 50_000, contract, "eval(10, sum({y: 8}))");

    let msg1 = op1.signing_message().unwrap();
    let msg2 = op2.signing_message().unwrap();
    let sig1 = sk1.sign(&msg1, KONTOR_BLS_DST, &[]);
    let sig2 = sk2.sign(&msg2, KONTOR_BLS_DST, &[]);

    let aggregate = AggregateSignature::aggregate(&[&sig1, &sig2], true).unwrap();
    let aggregate_sig = aggregate.to_signature();

    let AggregateInst {
        signer,
        inst:
            Inst::Call {
                contract,
                nonce,
                expr,
                ..
            },
    } = &op1
    else {
        panic!("expected aggregate call");
    };
    let op1_mutated = AggregateInst {
        signer: signer.clone(),
        inst: Inst::Call {
            gas_limit: 60_000,
            contract: contract.clone(),
            nonce: *nonce,
            expr: expr.clone(),
        },
    };
    let msg1_mutated = op1_mutated.signing_message().unwrap();

    let messages = [msg1_mutated, msg2];
    let msg_refs: Vec<&[u8]> = messages.iter().map(Vec::as_slice).collect();
    let pk_refs = [&pk1, &pk2];
    assert_ne!(
        aggregate_sig.aggregate_verify(true, msg_refs.as_slice(), KONTOR_BLS_DST, &pk_refs, true),
        BLST_ERROR::BLST_SUCCESS
    );
}

#[test]
fn aggregate_call_roundtrip_serialization_preserves_signer_id() {
    let op = call_op(
        42,
        7,
        50_000,
        ContractAddress {
            name: "arith".to_string(),
            height: 7,
            tx_index: 3,
        },
        "eval(10, id)",
    );

    let bytes = indexer_types::serialize(&op).expect("serialize");
    let decoded: AggregateInst = indexer_types::deserialize(&bytes).expect("deserialize");
    assert_eq!(decoded, op);
}

#[test]
fn message_changes_when_signer_id_changes() {
    let contract = ContractAddress {
        name: "arith".to_string(),
        height: 123,
        tx_index: 4,
    };
    let op1 = call_op(1, 0, 50_000, contract.clone(), "eval(10, id)");
    let op2 = call_op(2, 0, 50_000, contract, "eval(10, id)");
    assert_ne!(
        op1.signing_message().unwrap(),
        op2.signing_message().unwrap()
    );
}

#[test]
fn message_changes_when_nonce_changes() {
    let contract = ContractAddress {
        name: "arith".to_string(),
        height: 123,
        tx_index: 4,
    };
    let op1 = call_op(1, 0, 50_000, contract.clone(), "eval(10, id)");
    let op2 = call_op(1, 1, 50_000, contract, "eval(10, id)");
    assert_ne!(
        op1.signing_message().unwrap(),
        op2.signing_message().unwrap()
    );
}

#[test]
fn message_changes_when_gas_limit_changes() {
    let contract = ContractAddress {
        name: "arith".to_string(),
        height: 123,
        tx_index: 4,
    };
    let op1 = call_op(1, 0, 50_000, contract.clone(), "eval(10, id)");
    let op2 = call_op(1, 0, 60_000, contract, "eval(10, id)");
    assert_ne!(
        op1.signing_message().unwrap(),
        op2.signing_message().unwrap()
    );
}

#[test]
fn message_changes_when_contract_name_changes() {
    let op1 = call_op(
        1,
        0,
        50_000,
        ContractAddress {
            name: "token".to_string(),
            height: 1,
            tx_index: 0,
        },
        "transfer(\"x\", 10)",
    );
    let op2 = call_op(
        1,
        0,
        50_000,
        ContractAddress {
            name: "pool".to_string(),
            height: 1,
            tx_index: 0,
        },
        "transfer(\"x\", 10)",
    );
    assert_ne!(
        op1.signing_message().unwrap(),
        op2.signing_message().unwrap()
    );
}

#[test]
fn message_changes_when_contract_height_changes() {
    let op1 = call_op(
        1,
        0,
        50_000,
        ContractAddress {
            name: "token".to_string(),
            height: 1,
            tx_index: 0,
        },
        "transfer(\"x\", 10)",
    );
    let op2 = call_op(
        1,
        0,
        50_000,
        ContractAddress {
            name: "token".to_string(),
            height: 2,
            tx_index: 0,
        },
        "transfer(\"x\", 10)",
    );
    assert_ne!(
        op1.signing_message().unwrap(),
        op2.signing_message().unwrap()
    );
}

#[test]
fn message_changes_when_contract_tx_index_changes() {
    let op1 = call_op(
        1,
        0,
        50_000,
        ContractAddress {
            name: "token".to_string(),
            height: 1,
            tx_index: 0,
        },
        "transfer(\"x\", 10)",
    );
    let op2 = call_op(
        1,
        0,
        50_000,
        ContractAddress {
            name: "token".to_string(),
            height: 1,
            tx_index: 1,
        },
        "transfer(\"x\", 10)",
    );
    assert_ne!(
        op1.signing_message().unwrap(),
        op2.signing_message().unwrap()
    );
}

#[test]
fn message_changes_when_expr_changes() {
    let contract = ContractAddress {
        name: "token".to_string(),
        height: 1,
        tx_index: 0,
    };
    let op1 = call_op(1, 0, 50_000, contract.clone(), "transfer(\"alice\", 10)");
    let op2 = call_op(1, 0, 50_000, contract, "transfer(\"bob\", 10)");
    assert_ne!(
        op1.signing_message().unwrap(),
        op2.signing_message().unwrap()
    );
}

#[test]
fn wrong_signer_key_fails_single_op() {
    let sk_a = derive_test_key(20);
    let sk_b = derive_test_key(21);
    let pk_a = sk_a.sk_to_pk();

    let op = call_op(
        1,
        0,
        50_000,
        ContractAddress {
            name: "token".to_string(),
            height: 1,
            tx_index: 0,
        },
        "transfer(\"dest\", 100)",
    );
    let msg = op.signing_message().unwrap();
    let sig_by_b = sk_b.sign(&msg, KONTOR_BLS_DST, &[]);

    assert_ne!(
        sig_by_b.aggregate_verify(true, &[msg.as_slice()], KONTOR_BLS_DST, &[&pk_a], true),
        BLST_ERROR::BLST_SUCCESS
    );
}

#[test]
fn wrong_signer_key_fails_multi_op_key_swap() {
    let sk_a = derive_test_key(30);
    let sk_b = derive_test_key(31);
    let pk_a = sk_a.sk_to_pk();
    let pk_b = sk_b.sk_to_pk();

    let contract = ContractAddress {
        name: "token".to_string(),
        height: 1,
        tx_index: 0,
    };

    let op_a = call_op(1, 0, 50_000, contract.clone(), "transfer(\"x\", 10)");
    let op_b = call_op(2, 0, 50_000, contract, "transfer(\"y\", 20)");
    let msg_a = op_a.signing_message().unwrap();
    let msg_b = op_b.signing_message().unwrap();

    let sig_a_by_b = sk_b.sign(&msg_a, KONTOR_BLS_DST, &[]);
    let sig_b_by_a = sk_a.sign(&msg_b, KONTOR_BLS_DST, &[]);
    let aggregate = AggregateSignature::aggregate(&[&sig_a_by_b, &sig_b_by_a], true).unwrap();
    let aggregate_sig = aggregate.to_signature();

    assert_ne!(
        aggregate_sig.aggregate_verify(
            true,
            &[msg_a.as_slice(), msg_b.as_slice()],
            KONTOR_BLS_DST,
            &[&pk_a, &pk_b],
            true,
        ),
        BLST_ERROR::BLST_SUCCESS
    );
}

#[test]
fn one_correct_one_wrong_key_fails_entire_aggregate() {
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

    let op_a = call_op(1, 0, 50_000, contract.clone(), "transfer(\"x\", 10)");
    let op_b = call_op(2, 0, 50_000, contract, "transfer(\"y\", 20)");
    let msg_a = op_a.signing_message().unwrap();
    let msg_b = op_b.signing_message().unwrap();

    let sig_a = sk_a.sign(&msg_a, KONTOR_BLS_DST, &[]);
    let sig_b_by_c = sk_c.sign(&msg_b, KONTOR_BLS_DST, &[]);
    let aggregate = AggregateSignature::aggregate(&[&sig_a, &sig_b_by_c], true).unwrap();
    let aggregate_sig = aggregate.to_signature();

    assert_ne!(
        aggregate_sig.aggregate_verify(
            true,
            &[msg_a.as_slice(), msg_b.as_slice()],
            KONTOR_BLS_DST,
            &[&pk_a, &pk_b],
            true,
        ),
        BLST_ERROR::BLST_SUCCESS
    );
}

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
        let op = call_op(
            signer_id,
            nonce,
            gas_limit,
            ContractAddress { name, height, tx_index },
            expr,
        );
        let msg = op.signing_message().expect("signing_message must not fail");
        prop_assert!(!msg.is_empty());
    }

    #[test]
    fn signing_message_no_panic_on_arbitrary_register(
        signer_hex in proptest::collection::vec(any::<u8>(), 32..=32).prop_map(|b| hex::encode(&b)),
        bls_pubkey in proptest::collection::vec(any::<u8>(), 0..256),
        schnorr_sig in proptest::collection::vec(any::<u8>(), 0..256),
        bls_sig in proptest::collection::vec(any::<u8>(), 0..256),
    ) {
        let op = register_op(signer_hex, bls_pubkey, schnorr_sig, bls_sig);
        let msg = op.signing_message().expect("signing_message must not fail");
        prop_assert!(!msg.is_empty());
    }
}
