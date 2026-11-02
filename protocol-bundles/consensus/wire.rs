use bytes::Bytes;
use malachitebft_codec::{Codec, HasEncodedLen};
use malachitebft_proto::Error;

use crate::consensus::codec::ProtobufCodec;

const PREFIX: &[u8] = b"KONTOR2\0";

#[derive(Clone, Copy, Debug)]
pub(crate) struct WireCodec;

impl<T> Codec<T> for WireCodec
where
    ProtobufCodec: Codec<T, Error = Error>,
{
    type Error = Error;

    fn encode(&self, value: &T) -> Result<Bytes, Self::Error> {
        ProtobufCodec.encode(value)
    }

    fn decode(&self, bytes: Bytes) -> Result<T, Self::Error> {
        if bytes.starts_with(PREFIX) {
            return Err(Error::Other("wrong consensus wire codec".into()));
        }
        ProtobufCodec.decode(bytes)
    }
}

impl<T> HasEncodedLen<T> for WireCodec
where
    ProtobufCodec: HasEncodedLen<T> + Codec<T, Error = Error>,
{
    fn encoded_len(&self, value: &T) -> Result<usize, Error> {
        ProtobufCodec.encoded_len(value)
    }
}

#[cfg(test)]
mod tests {
    use malachitebft_codec::Codec;

    use super::{PREFIX, WireCodec};
    use crate::consensus::Value;
    use crate::consensus::codec::ProtobufCodec;
    use crate::consensus::test_fixtures;

    #[test]
    fn real_kontor_value_round_trip_preserves_certified_identity() {
        let value = test_fixtures::block();
        let bytes = WireCodec.encode(&value).unwrap();
        let restored: Value = WireCodec.decode(bytes.clone()).unwrap();
        assert_eq!(restored.id(), value.id());
        assert_eq!(restored.input(), value.input());
        let mut incompatible = PREFIX.to_vec();
        incompatible.extend_from_slice(&bytes);
        assert!(Codec::<Value>::decode(&WireCodec, incompatible.into()).is_err());
        assert_eq!(bytes, ProtobufCodec.encode(&value).unwrap());
    }
}
