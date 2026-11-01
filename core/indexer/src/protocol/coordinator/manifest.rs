use crate::protocol::canonical_codec::{CodecError, Decoder, Encoder, strictly_ordered};
use crate::protocol::identity::{
    ChainId, ExecutionDefinitionId, MigrationDefinitionId, ProtocolId, domain_digest,
};

pub(crate) const MAX_MANIFEST_BYTES: usize = 65_536;
const FIXED_BYTES: usize = 264;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ProtocolManifest {
    pub(crate) chain: ChainId,
    pub(crate) protocol_number: u64,
    pub(crate) predecessor: ProtocolId,
    pub(crate) executor: ExecutionDefinitionId,
    pub(crate) consensus: [u8; 32],
    pub(crate) transaction_formats: Vec<u32>,
    pub(crate) host_abis: Vec<u32>,
    pub(crate) bridge_schema: u32,
    pub(crate) state_schema: u32,
    pub(crate) certificate_codec: u32,
    pub(crate) control_codec: u32,
    pub(crate) parameters_root: [u8; 32],
    pub(crate) native_contracts_root: [u8; 32],
    pub(crate) migration: MigrationDefinitionId,
    pub(crate) input_state_schema: u32,
    pub(crate) output_state_schema: u32,
}

impl ProtocolManifest {
    fn validate(&self) -> Result<(), CodecError> {
        let entries = self
            .transaction_formats
            .len()
            .checked_add(self.host_abis.len())
            .ok_or(CodecError::LengthOverflow)?;
        if entries > (MAX_MANIFEST_BYTES - FIXED_BYTES) / 4 {
            return Err(CodecError::LengthOverflow);
        }
        strictly_ordered(&self.transaction_formats)?;
        strictly_ordered(&self.host_abis)?;
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>, CodecError> {
        self.validate()?;
        let mut output = Encoder::default();
        output.fixed(b"KPM1")?;
        output.fixed(&self.chain.0)?;
        output.u64(self.protocol_number)?;
        output.fixed(&self.predecessor.0)?;
        output.fixed(&self.executor.0)?;
        output.fixed(&self.consensus)?;
        for ids in [&self.transaction_formats, &self.host_abis] {
            let count = u16::try_from(ids.len()).map_err(|_| CodecError::LengthOverflow)?;
            output.fixed(&count.to_be_bytes())?;
            for id in ids {
                output.fixed(&id.to_be_bytes())?;
            }
        }
        for id in [
            self.bridge_schema,
            self.state_schema,
            self.certificate_codec,
            self.control_codec,
        ] {
            output.fixed(&id.to_be_bytes())?;
        }
        output.fixed(&self.parameters_root)?;
        output.fixed(&self.native_contracts_root)?;
        output.fixed(&self.migration.0)?;
        output.fixed(&self.input_state_schema.to_be_bytes())?;
        output.fixed(&self.output_state_schema.to_be_bytes())?;
        Ok(output.finish())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self, CodecError> {
        if bytes.len() > MAX_MANIFEST_BYTES {
            return Err(CodecError::LengthOverflow);
        }
        let mut input = Decoder::new(bytes);
        if input.fixed::<4>()? != *b"KPM1" {
            return Err(CodecError::InvalidTag);
        }
        let value = Self {
            chain: ChainId(input.fixed()?),
            protocol_number: input.u64()?,
            predecessor: ProtocolId(input.fixed()?),
            executor: ExecutionDefinitionId(input.fixed()?),
            consensus: input.fixed()?,
            transaction_formats: decode_ids(&mut input)?,
            host_abis: decode_ids(&mut input)?,
            bridge_schema: u32::from_be_bytes(input.fixed()?),
            state_schema: u32::from_be_bytes(input.fixed()?),
            certificate_codec: u32::from_be_bytes(input.fixed()?),
            control_codec: u32::from_be_bytes(input.fixed()?),
            parameters_root: input.fixed()?,
            native_contracts_root: input.fixed()?,
            migration: MigrationDefinitionId(input.fixed()?),
            input_state_schema: u32::from_be_bytes(input.fixed()?),
            output_state_schema: u32::from_be_bytes(input.fixed()?),
        };
        input.finish()?;
        value.validate()?;
        Ok(value)
    }

    pub(crate) fn id(&self) -> Result<ProtocolId, CodecError> {
        Ok(ProtocolId(domain_digest(
            b"kontor/protocol-manifest/v1",
            &self.encode()?,
        )))
    }
}

fn decode_ids(input: &mut Decoder<'_>) -> Result<Vec<u32>, CodecError> {
    let count = input.count16(4)?;
    let mut ids = Vec::new();
    ids.try_reserve(count).map_err(|_| CodecError::Allocation)?;
    for _ in 0..count {
        ids.push(u32::from_be_bytes(input.fixed()?));
    }
    strictly_ordered(&ids)?;
    Ok(ids)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    fn manifest() -> ProtocolManifest {
        ProtocolManifest {
            chain: ChainId([0x11; 32]),
            protocol_number: 2,
            predecessor: ProtocolId([0x22; 32]),
            executor: ExecutionDefinitionId([0x33; 32]),
            consensus: [0x44; 32],
            transaction_formats: vec![0, 1],
            host_abis: vec![1],
            bridge_schema: 1,
            state_schema: 2,
            certificate_codec: 2,
            control_codec: 1,
            parameters_root: [0x55; 32],
            native_contracts_root: [0x66; 32],
            migration: MigrationDefinitionId([0x77; 32]),
            input_state_schema: 1,
            output_state_schema: 2,
        }
    }

    #[test]
    fn kpm1_matches_independent_golden_vector() {
        let golden: Value = serde_json::from_str(include_str!(
            "../../../../../tools/protocol-bundles/protocol-manifest-vector.json"
        ))
        .unwrap();
        let value = manifest();
        let bytes = value.encode().unwrap();
        assert_eq!(hex::encode(&bytes), golden["bytes_hex"].as_str().unwrap());
        assert_eq!(
            hex::encode(value.id().unwrap().0),
            golden["protocol_id"].as_str().unwrap()
        );
        assert_eq!(ProtocolManifest::decode(&bytes), Ok(value));
    }

    #[test]
    fn rejects_truncation_trailing_bytes_unknown_magic_and_unordered_ids() {
        let bytes = manifest().encode().unwrap();
        for length in 0..bytes.len() {
            assert!(
                ProtocolManifest::decode(&bytes[..length]).is_err(),
                "length {length}"
            );
        }
        let mut changed = bytes.clone();
        changed.push(0);
        assert_eq!(
            ProtocolManifest::decode(&changed),
            Err(CodecError::TrailingBytes)
        );
        changed = bytes.clone();
        changed[3] = b'2';
        assert_eq!(
            ProtocolManifest::decode(&changed),
            Err(CodecError::InvalidTag)
        );
        changed = bytes.clone();
        changed[140..142].copy_from_slice(&u16::MAX.to_be_bytes());
        assert_eq!(
            ProtocolManifest::decode(&changed),
            Err(CodecError::Truncated)
        );
        for ids in [vec![1, 1], vec![1, 0]] {
            let mut value = manifest();
            value.transaction_formats = ids;
            assert_eq!(value.encode(), Err(CodecError::UnorderedSet));
        }
        changed = bytes;
        changed[146..150].copy_from_slice(&0u32.to_be_bytes());
        assert_eq!(
            ProtocolManifest::decode(&changed),
            Err(CodecError::UnorderedSet)
        );
    }

    #[test]
    fn manifest_size_limit_is_checked_in_both_directions() {
        let mut value = manifest();
        value.host_abis.clear();
        value.transaction_formats = (0..((MAX_MANIFEST_BYTES - FIXED_BYTES) / 4) as u32).collect();
        let bytes = value.encode().unwrap();
        assert_eq!(bytes.len(), MAX_MANIFEST_BYTES);
        assert_eq!(ProtocolManifest::decode(&bytes), Ok(value.clone()));
        value.host_abis.push(1);
        assert_eq!(value.encode(), Err(CodecError::LengthOverflow));
        assert_eq!(
            ProtocolManifest::decode(&vec![0; MAX_MANIFEST_BYTES + 1]),
            Err(CodecError::LengthOverflow)
        );
    }

    #[test]
    fn every_fixed_field_and_list_entry_contributes_to_identity() {
        let bytes = manifest().encode().unwrap();
        let identity = manifest().id().unwrap();
        for offset in 4..bytes.len() {
            let mut changed = bytes.clone();
            changed[offset] ^= 1;
            if let Ok(value) = ProtocolManifest::decode(&changed) {
                assert_ne!(value.id().unwrap(), identity, "offset {offset}");
                assert_eq!(value.encode().unwrap(), changed);
            }
        }
    }
}
