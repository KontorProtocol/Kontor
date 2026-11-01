use std::error::Error;
use std::fmt;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CodecError {
    Truncated,
    TrailingBytes,
    InvalidTag,
    InvalidUtf8,
    LengthOverflow,
    Allocation,
    UnorderedSet,
    InvalidValue,
}

impl fmt::Display for CodecError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Truncated => "truncated canonical value",
            Self::TrailingBytes => "trailing canonical bytes",
            Self::InvalidTag => "unknown canonical tag or version",
            Self::InvalidUtf8 => "invalid canonical UTF-8",
            Self::LengthOverflow => "canonical length exceeds u32",
            Self::Allocation => "canonical allocation failed",
            Self::InvalidValue => "invalid canonical value",
            Self::UnorderedSet => "canonical set is unsorted or contains duplicates",
        })
    }
}

impl Error for CodecError {}

#[derive(Default)]
pub(crate) struct Encoder(Vec<u8>);

impl Encoder {
    pub(crate) fn fixed(&mut self, bytes: &[u8]) -> Result<(), CodecError> {
        self.0
            .try_reserve(bytes.len())
            .map_err(|_| CodecError::Allocation)?;
        self.0.extend_from_slice(bytes);
        Ok(())
    }

    pub(crate) fn tag(&mut self, value: u8) -> Result<(), CodecError> {
        self.fixed(&[value])
    }

    pub(crate) fn u64(&mut self, value: u64) -> Result<(), CodecError> {
        self.fixed(&value.to_be_bytes())
    }

    pub(crate) fn count(&mut self, value: usize) -> Result<(), CodecError> {
        let value = u32::try_from(value).map_err(|_| CodecError::LengthOverflow)?;
        self.fixed(&value.to_be_bytes())
    }

    pub(crate) fn bytes(&mut self, value: &[u8]) -> Result<(), CodecError> {
        self.count(value.len())?;
        self.fixed(value)
    }

    pub(crate) fn finish(self) -> Vec<u8> {
        self.0
    }
}

pub(crate) struct Decoder<'a> {
    remaining: &'a [u8],
}

impl<'a> Decoder<'a> {
    pub(crate) fn new(bytes: &'a [u8]) -> Self {
        Self { remaining: bytes }
    }

    fn take(&mut self, length: usize) -> Result<&'a [u8], CodecError> {
        let (value, rest) = self
            .remaining
            .split_at_checked(length)
            .ok_or(CodecError::Truncated)?;
        self.remaining = rest;
        Ok(value)
    }

    pub(crate) fn fixed<const N: usize>(&mut self) -> Result<[u8; N], CodecError> {
        self.take(N)?.try_into().map_err(|_| CodecError::Truncated)
    }

    pub(crate) fn tag(&mut self) -> Result<u8, CodecError> {
        Ok(self.fixed::<1>()?[0])
    }

    pub(crate) fn expect_tag(&mut self, expected: u8) -> Result<(), CodecError> {
        if self.tag()? != expected {
            return Err(CodecError::InvalidTag);
        }
        Ok(())
    }

    pub(crate) fn u64(&mut self) -> Result<u64, CodecError> {
        Ok(u64::from_be_bytes(self.fixed()?))
    }

    pub(crate) fn count(&mut self, minimum_entry_bytes: usize) -> Result<usize, CodecError> {
        let count = u32::from_be_bytes(self.fixed()?) as usize;
        // Validate a collection's backing bytes before allocating its entries.
        if minimum_entry_bytes == 0 || count > self.remaining.len() / minimum_entry_bytes {
            return Err(CodecError::Truncated);
        }
        Ok(count)
    }

    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], CodecError> {
        let length = self.count(1)?;
        self.take(length)
    }

    pub(crate) fn string(&mut self) -> Result<&'a str, CodecError> {
        std::str::from_utf8(self.bytes()?).map_err(|_| CodecError::InvalidUtf8)
    }

    pub(crate) fn owned_string(&mut self) -> Result<String, CodecError> {
        let text = self.string()?;
        let mut value = String::new();
        value
            .try_reserve(text.len())
            .map_err(|_| CodecError::Allocation)?;
        value.push_str(text);
        Ok(value)
    }

    pub(crate) fn finish(self) -> Result<(), CodecError> {
        if !self.remaining.is_empty() {
            return Err(CodecError::TrailingBytes);
        }
        Ok(())
    }
}

pub(crate) fn strictly_ordered<T: Ord>(items: &[T]) -> Result<(), CodecError> {
    if items.windows(2).any(|pair| pair[0] >= pair[1]) {
        return Err(CodecError::UnorderedSet);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{CodecError, Decoder, Encoder, strictly_ordered};

    #[test]
    fn fixed_width_big_endian_golden_encoding() {
        let mut value = Encoder::default();
        value.tag(1).unwrap();
        value.u64(0x0102_0304_0506_0708).unwrap();
        value.bytes(b"hi").unwrap();
        let bytes = value.finish();
        assert_eq!(bytes, [1, 1, 2, 3, 4, 5, 6, 7, 8, 0, 0, 0, 2, b'h', b'i']);
        let mut reader = Decoder::new(&bytes);
        reader.expect_tag(1).unwrap();
        assert_eq!(reader.u64().unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(reader.string().unwrap(), "hi");
        reader.finish().unwrap();
    }

    #[test]
    fn length_prefix_cannot_allocate_or_read_past_payload() {
        for bytes in [&[255, 255, 255, 255][..], &[0, 0, 0, 2, 1][..]] {
            assert_eq!(Decoder::new(bytes).bytes(), Err(CodecError::Truncated));
        }
        assert_eq!(
            Decoder::new(&[0, 0, 0, 2, 1, 2]).count(2),
            Err(CodecError::Truncated)
        );
        assert_eq!(Decoder::new(&[0, 0, 0, 0]).bytes(), Ok(&[][..]));
        if usize::BITS > 32 {
            assert_eq!(
                Encoder::default().count(u32::MAX as usize + 1),
                Err(CodecError::LengthOverflow)
            );
        }
    }

    #[test]
    fn tags_utf8_and_trailing_bytes_are_rejected() {
        assert_eq!(
            Decoder::new(&[2]).expect_tag(1),
            Err(CodecError::InvalidTag)
        );
        assert_eq!(Decoder::new(&[]).tag(), Err(CodecError::Truncated));
        assert_eq!(
            Decoder::new(&[0, 0, 0, 1, 255]).string(),
            Err(CodecError::InvalidUtf8)
        );
        assert_eq!(Decoder::new(&[0]).finish(), Err(CodecError::TrailingBytes));
    }

    #[test]
    fn set_encoding_requires_strict_order_instead_of_silently_sorting() {
        assert_eq!(strictly_ordered(&[1, 1]), Err(CodecError::UnorderedSet));
        assert_eq!(strictly_ordered(&[2, 1]), Err(CodecError::UnorderedSet));
        assert_eq!(strictly_ordered(&[1, 2]), Ok(()));
    }
}
