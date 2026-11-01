use bitcoin::absolute::LockTime;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::consensus::serialize;
use bitcoin::hashes::Hash;
use bitcoin::transaction::Version;
use bitcoin::{Amount, Network, ScriptBuf, Transaction, TxIn, TxOut, Witness};
use bytes::Bytes;
use indexer::consensus::codec::ProtobufCodec;
use indexer::consensus::signing::{Ed25519Provider, PrivateKey};
use indexer::consensus::{Height, ProposalData, ProposalPart, Value, proto};
use malachitebft_app::engine::util::streaming::{StreamContent, StreamId, StreamMessage};
use malachitebft_codec::Codec;
use malachitebft_core_types::Round;
use malachitebft_proto::Protobuf;
use sha2::{Digest, Sha256};

fn digest(domain: &[u8], bytes: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(domain);
    hash.update([0]);
    hash.update(bytes);
    hash.finalize().into()
}

fn transaction(value: u64) -> Transaction {
    Transaction {
        version: Version::TWO,
        lock_time: LockTime::ZERO,
        input: vec![TxIn::default()],
        output: vec![TxOut {
            value: Amount::from_sat(value),
            script_pubkey: ScriptBuf::new(),
        }],
    }
}

// Construct the documented KVD1 wire independently of the implementation's
// private constructors. These tests exercise the same decoding as live traffic.
fn descriptor(command: &[u8], count: u32, body: &[u8]) -> Vec<u8> {
    let mut bytes = b"KVD1".to_vec();
    bytes.extend([1; 32]);
    bytes.extend([2; 32]);
    bytes.extend([3; 32]);
    bytes.extend(1u32.to_be_bytes());
    bytes.extend(command);
    bytes.extend(count.to_be_bytes());
    bytes.extend((body.len() as u32).to_be_bytes());
    bytes.extend(digest(b"kontor/certified-input-body/v1", body));
    bytes
}

fn batch(txs: &[Transaction]) -> proto::Value {
    let mut body = (txs.len() as u32).to_be_bytes().to_vec();
    for tx in txs {
        let bytes = serialize(tx);
        body.extend((bytes.len() as u32).to_be_bytes());
        body.extend(bytes);
    }
    let mut command = vec![0];
    command.extend(7u64.to_be_bytes());
    command.extend([4; 32]);
    proto::Value {
        descriptor: descriptor(&command, txs.len() as u32, &body).into(),
        body: body.into(),
    }
}

#[test]
fn witness_order_and_protocol_context_bind_votes_and_proposal_signatures() {
    let first = transaction(1);
    let mut changed = first.clone();
    changed.input[0].witness = Witness::from_slice(&[b"different operation"]);
    assert_eq!(first.compute_txid(), changed.compute_txid());
    let wire = batch(&[first.clone(), transaction(2)]);
    assert_eq!(wire.descriptor.len(), 185);
    let value = Value::from_proto(wire.clone()).unwrap();
    assert_eq!(
        value.id().0,
        digest(b"kontor/certified-value/v1", &wire.descriptor)
    );
    let original = ProposalData::new(value.clone());
    let signer = Ed25519Provider::new(PrivateKey::from([7; 32]));
    let key = PrivateKey::from([7; 32]).public_key();
    let height = Height::new(9);
    let round = Round::new(2);
    let signature = signer.sign(&original.signing_digest(height, round));
    assert!(signer.verify(&original.signing_digest(height, round), &signature, &key));
    let mut variants = vec![
        batch(&[changed, transaction(2)]),
        batch(&[transaction(2), first]),
    ];
    for offset in [4, 36, 68, 105, 113] {
        let mut variant = wire.clone();
        let mut bytes = variant.descriptor.to_vec();
        bytes[offset] ^= 1;
        variant.descriptor = bytes.into();
        variants.push(variant);
    }
    for variant in variants {
        let different = Value::from_proto(variant).unwrap();
        assert_ne!(value.id(), different.id());
        assert!(!signer.verify(
            &ProposalData::new(different).signing_digest(height, round),
            &signature,
            &key
        ));
    }
    assert!(!signer.verify(
        &original.signing_digest(Height::new(10), round),
        &signature,
        &key
    ));
    assert!(!signer.verify(
        &original.signing_digest(height, Round::new(3)),
        &signature,
        &key
    ));
}

#[test]
fn exact_inputs_survive_value_proposal_stream_and_serde_roundtrips() {
    let mut tx = transaction(1);
    tx.input[0].witness = Witness::from_slice(&[b"retained witness"]);
    for wire in [batch(&[]), batch(&[tx])] {
        let value = Value::from_proto(wire.clone()).unwrap();
        let encoded = value.to_bytes().unwrap();
        let decoded = Value::from_bytes(&encoded).unwrap();
        assert_eq!(decoded.to_proto().unwrap(), wire);
        let json = serde_json::to_vec(&value).unwrap();
        let restored: Value = serde_json::from_slice(&json).unwrap();
        assert_eq!(restored.to_proto().unwrap(), wire);
        let part = ProposalPart::Data(ProposalData::new(value));
        let stream = StreamMessage::new(
            StreamId::new(Bytes::from_static(b"stream")),
            1,
            StreamContent::Data(part),
        );
        let bytes = ProtobufCodec.encode(&stream).unwrap();
        let restored: StreamMessage<ProposalPart> = ProtobufCodec.decode(bytes).unwrap();
        let part = restored.content.into_data().unwrap();
        assert_eq!(part.as_data().unwrap().value().to_proto().unwrap(), wire);
    }
}

#[test]
fn legacy_partial_and_substituted_bodies_are_rejected() {
    let wire = batch(&[transaction(1)]);
    let mut bad = wire.clone();
    let mut tx = transaction(1);
    tx.input[0].witness = Witness::from_slice(&[b"substituted"]);
    bad.body = batch(&[tx]).body;
    assert!(Value::from_proto(bad).is_err());
    for body in [
        Bytes::new(),
        Bytes::from(vec![255; 4]),
        Bytes::from([wire.body.as_ref(), &[0]].concat()),
    ] {
        let mut bad = wire.clone();
        bad.body = body;
        assert!(Value::from_proto(bad).is_err());
    }
    for offset in [100, 104, 145, 149] {
        let mut bad = wire.clone();
        let mut bytes = bad.descriptor.to_vec();
        bytes[offset] = 255;
        bad.descriptor = bytes.into();
        assert!(Value::from_proto(bad).is_err());
    }
    let mut bad = wire.clone();
    bad.descriptor = [wire.descriptor.as_ref(), &[0]].concat().into();
    assert!(Value::from_proto(bad).is_err());
    assert!(Value::from_bytes(&[0x0a, 0x00]).is_err());
    assert!(Value::from_proto(proto::Value::default()).is_err());
    let value = Value::from_proto(wire).unwrap();
    let mut json = serde_json::to_value(value).unwrap();
    json["body"] = serde_json::json!([]);
    assert!(serde_json::from_value::<Value>(json).is_err());
}

#[test]
fn block_values_retain_and_validate_complete_bitcoin_input() {
    let block = genesis_block(Network::Bitcoin);
    let body = serialize(&block);
    let mut command = vec![1];
    command.extend(0u64.to_be_bytes());
    command.extend(block.block_hash().to_byte_array());
    command.extend(block.header.prev_blockhash.to_byte_array());
    command.extend(serialize(&block.header));
    let wire = proto::Value {
        descriptor: descriptor(&command, 1, &body).into(),
        body: body.into(),
    };
    assert_eq!(wire.descriptor.len(), 297);
    let value = Value::from_proto(wire.clone()).unwrap();
    assert!(value.is_block());
    assert_eq!(value.block_hash(), block.block_hash());
    assert_eq!(value.to_proto().unwrap(), wire);
    for offset in [113, 145, 177] {
        let mut bad = wire.clone();
        let mut bytes = bad.descriptor.to_vec();
        bytes[offset] ^= 1;
        bad.descriptor = bytes.into();
        assert!(Value::from_proto(bad).is_err());
    }
    let mut bad = wire;
    let mut bytes = bad.body.to_vec();
    *bytes.last_mut().unwrap() ^= 1;
    bad.body = bytes.into();
    assert!(Value::from_proto(bad).is_err());
}

fn transaction_with_size(size: usize, value: u64) -> Transaction {
    let mut tx = transaction(value);
    // Large script lengths use the five-byte CompactSize encoding.
    tx.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0; size - 64]);
    assert_eq!(tx.total_size(), size);
    tx
}

fn maximal_batches() -> [Vec<Transaction>; 2] {
    const MAX_BODY: usize = 4_186_112;
    let large = vec![
        transaction_with_size(4_000_000, 1),
        transaction_with_size(MAX_BODY - 12 - 4_000_000, 2),
    ];
    let small = transaction(1).total_size() + 4;
    let count = (MAX_BODY - 4) / small;
    let mut many: Vec<_> = (0..count).map(|i| transaction(i as u64)).collect();
    let remainder = MAX_BODY - 4 - count * small;
    many.last_mut().unwrap().output[0].script_pubkey = ScriptBuf::from_bytes(vec![0; remainder]);
    [large, many]
}

#[test]
fn maximal_batch_inputs_fit_the_actual_proposal_stream_encoding() {
    const MAX_BODY: usize = 4_186_112;
    for txs in maximal_batches() {
        let wire = batch(&txs);
        assert_eq!(wire.body.len(), MAX_BODY);
        let value = Value::from_proto(wire).unwrap();
        let part = ProposalPart::Data(ProposalData::new(value));
        let stream = StreamMessage::new(
            StreamId::new(Bytes::from(vec![0; 12])),
            u64::MAX,
            StreamContent::Data(part),
        );
        let encoded = ProtobufCodec.encode(&stream).unwrap();
        // Retain at least 7 KiB of the 8 KiB allowance for the outer signed
        // gossip envelope. The two-peer test also checks actual signed delivery.
        assert!(encoded.len() <= 4 * 1024 * 1024 - 7 * 1024);
        let decoded: StreamMessage<ProposalPart> = ProtobufCodec.decode(encoded).unwrap();
        assert_eq!(
            decoded
                .content
                .into_data()
                .unwrap()
                .as_data()
                .unwrap()
                .txids()
                .len(),
            txs.len()
        );
    }
    assert!(Value::from_proto(batch(&[transaction_with_size(4_000_001, 1)])).is_err());
}

#[path = "certified_value_wire/gossip.rs"]
mod gossip;
