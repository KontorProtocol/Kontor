use bitcoin::Transaction;
use bitcoin::consensus::Encodable;
use bitcoin::io::{self, Write};
use sha2::{Digest, Sha256};

use super::canonical_codec::{CodecError, Decoder, Encoder};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CanonicalInput {
    Bitcoin([u8; 32]),
    #[cfg(test)]
    Synthetic([u8; 32]),
}

impl CanonicalInput {
    pub(crate) fn bitcoin(transactions: &[Transaction]) -> Result<Self, CodecError> {
        let count = u32::try_from(transactions.len()).map_err(|_| CodecError::LengthOverflow)?;
        let mut writer = HashWriter::new(b"kontor/canonical-input/v1");
        writer.0.update([1]);
        writer.0.update(count.to_be_bytes());
        for transaction in transactions {
            let length =
                u32::try_from(transaction.total_size()).map_err(|_| CodecError::LengthOverflow)?;
            writer.0.update(length.to_be_bytes());
            // Bitcoin consensus serialization includes witnesses. Streaming avoids
            // allocating another block-sized buffer merely to identify its input.
            let written = transaction
                .consensus_encode(&mut writer)
                .map_err(|_| CodecError::InvalidValue)?;
            if written != length as usize {
                return Err(CodecError::InvalidValue);
            }
        }
        Ok(Self::Bitcoin(writer.0.finalize().into()))
    }

    #[cfg(test)]
    pub(crate) fn synthetic(txids: &[[u8; 32]]) -> Result<Self, CodecError> {
        let count = u32::try_from(txids.len()).map_err(|_| CodecError::LengthOverflow)?;
        let mut writer = HashWriter::new(b"kontor/synthetic-test-input/v1");
        writer.0.update([1]);
        writer.0.update(count.to_be_bytes());
        for txid in txids {
            writer.0.update(txid);
        }
        Ok(Self::Synthetic(writer.0.finalize().into()))
    }

    pub(crate) fn authentic(self) -> bool {
        matches!(self, Self::Bitcoin(_))
    }

    pub(crate) fn encode(self, output: &mut Encoder) -> Result<(), CodecError> {
        let (tag, digest) = match self {
            Self::Bitcoin(digest) => (0, digest),
            #[cfg(test)]
            Self::Synthetic(digest) => (1, digest),
        };
        output.tag(tag)?;
        output.fixed(&digest)
    }

    pub(crate) fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        match input.tag()? {
            0 => Ok(Self::Bitcoin(input.fixed()?)),
            #[cfg(test)]
            1 => Ok(Self::Synthetic(input.fixed()?)),
            _ => Err(CodecError::InvalidTag),
        }
    }
}

struct HashWriter(Sha256);

impl HashWriter {
    fn new(domain: &[u8]) -> Self {
        let mut hash = Sha256::new();
        hash.update(domain);
        hash.update([0]);
        Self(hash)
    }
}

impl Write for HashWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.update(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::absolute::LockTime;
    use bitcoin::consensus::serialize;
    use bitcoin::transaction::Version;
    use bitcoin::{Amount, ScriptBuf, Transaction, TxIn, TxOut, Witness};

    use super::CanonicalInput;
    use crate::protocol::canonical_codec::{CodecError, Decoder, Encoder};
    use crate::protocol::identity::domain_digest;

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

    #[test]
    fn witnesses_change_identity_even_when_txid_is_unchanged() {
        let first = transaction(1);
        let mut second = first.clone();
        second.input[0].witness = Witness::from_slice(&[b"witness"]);
        assert_eq!(first.compute_txid(), second.compute_txid());
        assert_ne!(
            CanonicalInput::bitcoin(&[first]).unwrap(),
            CanonicalInput::bitcoin(&[second]).unwrap()
        );
    }

    #[test]
    fn ordered_full_input_and_empty_input_are_distinct() {
        let first = transaction(1);
        let second = transaction(2);
        let full = CanonicalInput::bitcoin(&[first.clone(), second.clone()]).unwrap();
        assert_ne!(
            full,
            CanonicalInput::bitcoin(&[second, first.clone()]).unwrap()
        );
        assert_ne!(full, CanonicalInput::bitcoin(&[first]).unwrap());
        assert_ne!(full, CanonicalInput::bitcoin(&[]).unwrap());
    }

    #[test]
    fn streaming_encoding_matches_explicit_framing() {
        let mut tx = transaction(42);
        tx.input[0].witness = Witness::from_slice(&[b"one", b"two"]);
        let raw = serialize(&tx);
        let mut payload = vec![1];
        payload.extend_from_slice(&1_u32.to_be_bytes());
        payload.extend_from_slice(&(raw.len() as u32).to_be_bytes());
        payload.extend_from_slice(&raw);
        assert_eq!(
            CanonicalInput::bitcoin(&[tx]).unwrap(),
            CanonicalInput::Bitcoin(domain_digest(b"kontor/canonical-input/v1", &payload))
        );
    }

    #[test]
    fn synthetic_input_cannot_be_used_as_authentic_history() {
        let raw = CanonicalInput::bitcoin(&[]).unwrap();
        let synthetic = CanonicalInput::synthetic(&[]).unwrap();
        assert!(raw.authentic());
        assert!(!synthetic.authentic());
        assert_ne!(raw, synthetic);
        for value in [raw, synthetic] {
            let mut encoded = Encoder::default();
            value.encode(&mut encoded).unwrap();
            let bytes = encoded.finish();
            let mut input = Decoder::new(&bytes);
            assert_eq!(CanonicalInput::decode(&mut input), Ok(value));
            input.finish().unwrap();
        }
        assert_eq!(
            CanonicalInput::decode(&mut Decoder::new(&[2])),
            Err(CodecError::InvalidTag)
        );
    }
}
