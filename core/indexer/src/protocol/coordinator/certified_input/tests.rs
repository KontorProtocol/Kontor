use bitcoin::absolute::LockTime;
use bitcoin::blockdata::constants::genesis_block;
use bitcoin::opcodes::all::OP_PUSHNUM_1;
use bitcoin::transaction::Version;
use bitcoin::{Amount, Network, ScriptBuf, TxIn, TxOut, Witness};

use super::*;

fn context() -> EraContext {
    EraContext {
        chain: ChainId([1; 32]),
        era: [2; 32],
        protocol: ProtocolId([3; 32]),
        codec: 1,
    }
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

fn batch(transactions: &[Transaction]) -> ExactInput {
    ExactInput::batch(
        context(),
        7,
        BlockHash::from_byte_array([4; 32]),
        transactions,
    )
    .unwrap()
}

#[test]
fn witness_order_and_context_are_bound_even_when_txids_match() {
    let first = transaction(1);
    let mut witnessed = first.clone();
    witnessed.input[0].witness = Witness::from_slice(&[b"different instructions"]);
    assert_eq!(first.compute_txid(), witnessed.compute_txid());
    let a = batch(&[first.clone()]);
    let b = batch(&[witnessed]);
    assert_ne!(a.descriptor().id(), b.descriptor().id());
    assert!(ExactInput::validate(a.descriptor().clone(), b.body().to_vec()).is_err());
    let ab = batch(&[first.clone(), transaction(2)]);
    assert_ne!(
        ab.descriptor().id(),
        batch(&[transaction(2), first]).descriptor().id()
    );
    for changed_context in [
        EraContext {
            chain: ChainId([9; 32]),
            ..context()
        },
        EraContext {
            era: [9; 32],
            ..context()
        },
        EraContext {
            protocol: ProtocolId([9; 32]),
            ..context()
        },
    ] {
        let mut descriptor = a.descriptor().clone();
        descriptor.context = changed_context;
        assert_ne!(descriptor.id(), a.descriptor().id());
    }
}

#[test]
fn batch_and_block_descriptors_roundtrip_with_exact_body_and_count() {
    let block = genesis_block(Network::Bitcoin);
    for input in [
        batch(&[]),
        batch(&[transaction(42)]),
        ExactInput::block(context(), 0, serialize(&block)).unwrap(),
    ] {
        let bytes = input.descriptor().encode().unwrap();
        assert_eq!(
            bytes.len(),
            if matches!(input.descriptor().command, Command::Batch { .. }) {
                185
            } else {
                297
            }
        );
        assert_eq!(&bytes[..4], b"KVD1");
        let descriptor = Descriptor::decode(&bytes).unwrap();
        assert_eq!(
            ExactInput::validate(descriptor, input.body().to_vec()),
            Ok(input.clone())
        );
        assert_eq!(
            input.transactions().unwrap().len(),
            input.descriptor().input_count as usize
        );
        for length in 0..bytes.len() {
            assert!(Descriptor::decode(&bytes[..length]).is_err());
        }
        let mut trailing = bytes.clone();
        trailing.push(0);
        assert_eq!(
            Descriptor::decode(&trailing),
            Err(CodecError::TrailingBytes)
        );
        let mut bad_count = input.descriptor().clone();
        bad_count.input_count += 1;
        assert!(ExactInput::validate(bad_count, input.body().to_vec()).is_err());
        let mut bad_length = input.descriptor().clone();
        bad_length.body_length += 1;
        assert!(ExactInput::validate(bad_length, input.body().to_vec()).is_err());
    }
}

#[test]
fn malformed_framing_is_rejected_before_transaction_allocation() {
    for bytes in [
        vec![255; 4],
        vec![0, 0, 0, 2, 0, 0, 0, 0],
        vec![0, 0, 0, 1, 255, 255, 255, 255],
    ] {
        assert!(decode_batch(&bytes).is_err());
    }
    let mut trailing = batch(&[transaction(1)]).body().to_vec();
    trailing.push(0);
    assert_eq!(decode_batch(&trailing), Err(CodecError::TrailingBytes));
    let mut transaction_trailing = serialize(&transaction(1));
    transaction_trailing.push(0);
    let mut body = Encoder::default();
    body.count(1).unwrap();
    body.bytes(&transaction_trailing).unwrap();
    assert_eq!(decode_batch(&body.finish()), Err(CodecError::InvalidValue));
    // Non-minimal CompactSize for one input must not acquire another encoding.
    let mut noncanonical = serialize(&transaction(1));
    noncanonical.splice(4..5, [0xfd, 1, 0]);
    let mut body = Encoder::default();
    body.count(1).unwrap();
    body.bytes(&noncanonical).unwrap();
    assert_eq!(decode_batch(&body.finish()), Err(CodecError::InvalidValue));
    assert_eq!(
        Descriptor::decode(&vec![0; MAX_DESCRIPTOR_BYTES + 1]),
        Err(CodecError::LengthOverflow)
    );
}

#[test]
fn wire_limits_apply_before_encoding_and_accept_exact_maximum() {
    let mut first = transaction(1);
    first.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51; 2_000_000]);
    let mut second = transaction(2);
    // A script above 65535 bytes uses a five-byte CompactSize prefix.
    let second_script_len = MAX_BATCH_BYTES - 12 - first.total_size() - second.total_size() - 4;
    second.output[0].script_pubkey = ScriptBuf::from_bytes(vec![0x51; second_script_len]);
    let exact = batch(&[first.clone(), second.clone()]);
    assert_eq!(exact.body().len(), MAX_BATCH_BYTES);
    second.output[0].script_pubkey.push_opcode(OP_PUSHNUM_1);
    assert_eq!(
        ExactInput::batch(context(), 7, BlockHash::all_zeros(), &[first, second]),
        Err(CodecError::LengthOverflow)
    );
    assert_eq!(
        decode_batch(&vec![0; MAX_BATCH_BYTES + 1]),
        Err(CodecError::LengthOverflow)
    );
    assert_eq!(
        decode_block(&vec![0; MAX_BITCOIN_BYTES + 1]),
        Err(CodecError::LengthOverflow)
    );
}

#[test]
fn block_header_parent_count_and_body_commitments_are_validated() {
    let block = genesis_block(Network::Bitcoin);
    let input = ExactInput::block(context(), 0, serialize(&block)).unwrap();
    for parent in [false, true] {
        let mut descriptor = input.descriptor().clone();
        if let Command::Block {
            hash,
            parent: previous,
            ..
        } = &mut descriptor.command
        {
            if parent {
                *previous = BlockHash::from_byte_array([7; 32]);
            } else {
                *hash = BlockHash::from_byte_array([7; 32]);
            }
        }
        assert!(descriptor.encode().is_err());
        assert!(ExactInput::validate(descriptor, input.body().to_vec()).is_err());
    }
    let mut changed = block.clone();
    changed.txdata[0].output[0].value = Amount::ZERO;
    assert!(ExactInput::block(context(), 0, serialize(&changed)).is_err());
    let mut duplicate = block;
    duplicate.txdata.push(duplicate.txdata[0].clone());
    duplicate.header.merkle_root = duplicate.compute_merkle_root().unwrap();
    assert!(ExactInput::block(context(), 0, serialize(&duplicate)).is_err());
}

#[test]
fn stripped_and_altered_segwit_bodies_are_not_historical_inputs() {
    let mut block = genesis_block(Network::Bitcoin);
    block.txdata[0].input[0].witness.push([0; 32]);
    let commitment = Block::compute_witness_commitment(&block.witness_root().unwrap(), &[0; 32]);
    let mut script = vec![0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed];
    script.extend_from_slice(&commitment.to_byte_array());
    block.txdata[0].output.push(TxOut {
        value: Amount::ZERO,
        script_pubkey: ScriptBuf::from_bytes(script),
    });
    block.header.merkle_root = block.compute_merkle_root().unwrap();
    let input = ExactInput::block(context(), 1, serialize(&block)).unwrap();
    let mut stripped = block.clone();
    stripped.txdata[0].input[0].witness.clear();
    assert!(stripped.check_witness_commitment());
    assert!(ExactInput::block(context(), 1, serialize(&stripped)).is_err());
    assert!(ExactInput::validate(input.descriptor().clone(), serialize(&stripped)).is_err());
    block.txdata[0].input[0].witness = Witness::from_slice(&[[1; 32]]);
    assert!(ExactInput::block(context(), 1, serialize(&block)).is_err());
}
