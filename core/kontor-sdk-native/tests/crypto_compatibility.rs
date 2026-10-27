use std::fmt::Debug;
use std::str;

use kontor_sdk_native::{
    CoreError, bls_aggregate_signatures, bls_pubkey_from_secret, bls_secret_from_seed_eip2333,
    bls_secret_key_gen, bls_sign, bls_verify,
};
use serde_json::Value;

fn bytes(vectors: &Value, name: &str) -> Vec<u8> {
    let (pairs, remainder) = vectors[name].as_str().unwrap().as_bytes().as_chunks::<2>();
    assert!(
        remainder.is_empty(),
        "hex fixture must contain complete bytes"
    );
    pairs
        .iter()
        .map(|pair| u8::from_str_radix(str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect()
}

fn assert_error<T: Debug>(result: Result<T, CoreError>, vectors: &Value, name: &str) {
    assert_eq!(
        result.unwrap_err().to_string(),
        vectors["errors"][name]["message"].as_str().unwrap()
    );
}

#[test]
fn native_crypto_matches_pristine_wasm_sdk_bytes_and_errors() {
    // The fixture was executed through the committed pre-vendoring Wasm SDK,
    // identified by its commit and binary hash, rather than this native crate.
    let reference: Value = serde_json::from_str(include_str!(
        "../../../tools/native-crypto/fixtures/sdk-vectors.json"
    ))
    .unwrap();
    let vectors = &reference["vectors"];
    let seed: Vec<u8> = (0..32).collect();
    let message = b"Kontor protocol crypto compatibility".to_vec();
    let secret = bls_secret_key_gen(seed.clone()).unwrap();
    let public = bls_pubkey_from_secret(secret.clone()).unwrap();
    let signature = bls_sign(secret, message.clone()).unwrap();
    assert_eq!(public, bytes(vectors, "publicKey"));
    assert_eq!(signature, bytes(vectors, "signature"));
    assert_eq!(
        bls_secret_key_gen(seed.clone()).unwrap(),
        bytes(vectors, "secret")
    );
    assert!(bls_verify(public.clone(), message.clone(), signature.clone()).unwrap());
    assert!(!bls_verify(public.clone(), vec![1], signature.clone()).unwrap());
    assert_eq!(
        bls_secret_from_seed_eip2333(seed.clone(), vec![]).unwrap(),
        bytes(vectors, "derivedRoot")
    );
    assert_eq!(
        bls_secret_from_seed_eip2333(seed, vec![12381, 0, 0, 0]).unwrap(),
        bytes(vectors, "derivedChild")
    );
    let other_secret = bls_secret_key_gen(vec![7; 32]).unwrap();
    let other_signature = bls_sign(other_secret, message.clone()).unwrap();
    assert_eq!(
        bls_aggregate_signatures(vec![signature.clone(), other_signature]).unwrap(),
        bytes(vectors, "aggregate")
    );
    assert_error(bls_secret_key_gen(vec![0; 31]), vectors, "shortSeed");
    assert_error(bls_pubkey_from_secret(vec![0; 32]), vectors, "zeroSecret");
    assert_error(
        bls_verify(vec![0; 96], message.clone(), signature.clone()),
        vectors,
        "invalidPublicKey",
    );
    assert_error(
        bls_verify(public.clone(), message.clone(), vec![0; 48]),
        vectors,
        "invalidSignature",
    );
    assert_error(
        bls_verify(public, message, signature[..47].to_vec()),
        vectors,
        "shortSignature",
    );
    assert_error(bls_aggregate_signatures(vec![]), vectors, "emptyAggregate");
}
