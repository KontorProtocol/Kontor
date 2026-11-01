use blst::BLST_ERROR;
use blst::min_pk::{AggregateSignature, PublicKey, SecretKey, Signature};
use ring::digest::{SHA256, digest};
use ring::signature::{ED25519, Ed25519KeyPair, KeyPair, UnparsedPublicKey};
use secp256k1::ecdsa::Signature as EcdsaSignature;
use secp256k1::{Keypair, Message, Secp256k1, SecretKey as SecpSecretKey};

fn unhex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| {
            let digit = |b: u8| match b {
                b'0'..=b'9' => b - b'0',
                b'a'..=b'f' => b - b'a' + 10,
                _ => panic!("invalid test vector"),
            };
            digit(pair[0]) * 16 + digit(pair[1])
        })
        .collect()
}

pub fn exercise() -> Vec<u8> {
    let mut output = Vec::new();
    let sha = digest(&SHA256, b"abc");
    assert_eq!(
        sha.as_ref(),
        unhex("ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
    );
    output.extend_from_slice(sha.as_ref());

    // RFC 8032 section 7.1, test 1, including the exact signature bytes.
    let seed = unhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60");
    let ed = Ed25519KeyPair::from_seed_unchecked(&seed).unwrap();
    assert_eq!(
        ed.public_key().as_ref(),
        unhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    );
    let signature = ed.sign(b"");
    assert_eq!(
        signature.as_ref(),
        unhex(concat!(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f",
            "b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        ))
    );
    let verifier = UnparsedPublicKey::new(&ED25519, ed.public_key());
    verifier.verify(b"", signature.as_ref()).unwrap();
    assert!(verifier.verify(b"wrong", signature.as_ref()).is_err());
    assert!(verifier.verify(b"", &signature.as_ref()[..63]).is_err());
    output.extend_from_slice(ed.public_key().as_ref());
    output.extend_from_slice(signature.as_ref());

    let dst = b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";
    let key = SecretKey::key_gen(&[7; 32], &[]).unwrap();
    let other_key = SecretKey::key_gen(&[8; 32], &[]).unwrap();
    let public = key.sk_to_pk();
    let signature = key.sign(b"kontor-one", dst, &[]);
    let other_signature = other_key.sign(b"kontor-two", dst, &[]);
    assert_eq!(
        signature.verify(true, b"kontor-one", dst, &[], &public, true),
        BLST_ERROR::BLST_SUCCESS
    );
    assert_ne!(
        signature.verify(true, b"wrong", dst, &[], &public, true),
        BLST_ERROR::BLST_SUCCESS
    );
    assert!(PublicKey::from_bytes(&[0; 48]).is_err());
    assert!(Signature::from_bytes(&[0; 96]).is_err());
    assert!(Signature::from_bytes(&signature.to_bytes()[..95]).is_err());
    let aggregate = AggregateSignature::aggregate(&[&signature, &other_signature], true)
        .unwrap()
        .to_signature();
    assert_eq!(
        aggregate.aggregate_verify(
            true,
            &[b"kontor-one", b"kontor-two"],
            dst,
            &[&public, &other_key.sk_to_pk()],
            true
        ),
        BLST_ERROR::BLST_SUCCESS
    );
    output.extend_from_slice(&public.to_bytes());
    output.extend_from_slice(&signature.to_bytes());
    output.extend_from_slice(&aggregate.to_bytes());

    let secp = Secp256k1::new();
    let key = SecpSecretKey::from_slice(&[7; 32]).unwrap();
    let public = key.public_key(&secp);
    let message = Message::from_digest([2; 32]);
    let ecdsa = secp.sign_ecdsa(&message, &key);
    secp.verify_ecdsa(&message, &ecdsa, &public).unwrap();
    assert!(
        secp.verify_ecdsa(&Message::from_digest([3; 32]), &ecdsa, &public)
            .is_err()
    );
    assert!(SecpSecretKey::from_slice(&[0; 32]).is_err());
    assert!(EcdsaSignature::from_der(&[0; 64]).is_err());
    let recoverable = secp.sign_ecdsa_recoverable(&message, &key);
    assert_eq!(secp.recover_ecdsa(&message, &recoverable).unwrap(), public);
    assert_eq!(recoverable.to_standard(), ecdsa);
    output.extend_from_slice(&public.serialize());
    output.extend_from_slice(&ecdsa.serialize_compact());

    let pair = Keypair::from_secret_key(&secp, &key);
    let (xonly, _) = pair.x_only_public_key();
    let schnorr = secp.sign_schnorr_with_aux_rand(&message, &pair, &[0; 32]);
    secp.verify_schnorr(&schnorr, &message, &xonly).unwrap();
    assert!(
        secp.verify_schnorr(&schnorr, &Message::from_digest([3; 32]), &xonly)
            .is_err()
    );
    output.extend_from_slice(&xonly.serialize());
    output.extend_from_slice(schnorr.as_ref());
    output
}
