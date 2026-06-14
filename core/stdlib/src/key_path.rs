use core::{fmt::Display, ops::Deref};

use alloc::{string::String, vec::Vec};

use crate::keycodec::{self, KeyElement};

/// A storage path: a sequence of segments encoded with the order-preserving
/// [`keycodec`](crate::keycodec) (a `BLOB` key on the host). Holds only the codec
/// `bytes` (what `Deref`/`AsRef` expose and the host keys on) plus the byte offset
/// of each segment's end, so `pop`/`num_segments` are cheap without storing the
/// segments twice. Every segment is currently a string element (matching the
/// previous `K::to_string()` behavior); typed elements are layered on later.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KeyPath {
    bytes: Vec<u8>,
    /// Byte offset just past each segment, so the last segment is
    /// `bytes[ends[len-2]..ends[len-1]]` — used by `pop`/`num_segments`.
    ends: Vec<usize>,
}

impl KeyPath {
    pub fn new() -> Self {
        KeyPath {
            bytes: Vec::new(),
            ends: Vec::new(),
        }
    }

    /// Append one path segment — structural names AND keys (`K::to_string()`,
    /// index keys) — encoded as a string element. Because each element is
    /// self-delimiting (`0x00`-terminated, escaped), a segment may contain ANY
    /// content (`.`, `-`, …) without aliasing; the integrity the old `.`-join had
    /// to enforce by rejecting such keys is now structural.
    pub fn push(&self, segment: impl Into<String>) -> Self {
        let segment = segment.into();
        let mut bytes = self.bytes.clone();
        segment.encode_to(&mut bytes);
        let mut ends = self.ends.clone();
        ends.push(bytes.len());
        KeyPath { bytes, ends }
    }

    /// Drop the last segment, returning the shortened path and the popped segment
    /// (decoded back to its string form).
    pub fn pop(&self) -> (Self, Option<String>) {
        let Some(&end) = self.ends.last() else {
            return (self.clone(), None);
        };
        let start = self.ends.len().checked_sub(2).map_or(0, |i| self.ends[i]);
        let (segment, _) =
            String::decode_from(&self.bytes[start..end]).expect("a pushed segment decodes back");
        let mut ends = self.ends.clone();
        ends.pop();
        (
            KeyPath {
                bytes: self.bytes[..start].to_vec(),
                ends,
            },
            Some(segment),
        )
    }

    pub fn num_segments(&self) -> u64 {
        self.ends.len() as u64
    }

    /// The codec bytes the host keys on.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsRef<[u8]> for KeyPath {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl Deref for KeyPath {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

/// Build a path from dotted segments (`"a.b.c"` → three string-element segments).
/// A convenience for literal/test paths only — it is NOT the inverse of
/// [`Display`] (which is a lossy debug render), and it splits on `.`, so it can't
/// express a segment that contains one.
impl From<&str> for KeyPath {
    fn from(s: &str) -> Self {
        s.split('.')
            .filter(|s| !s.is_empty())
            .fold(KeyPath::new(), |path, seg| path.push(seg))
    }
}

/// Debug/log rendering ONLY — lossy, not canonical or round-trippable (the bytes
/// are). See [`keycodec::debug_render`].
impl Display for KeyPath {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", keycodec::debug_render(&self.bytes))
    }
}

impl Default for KeyPath {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use alloc::string::ToString;
    use alloc::vec;

    use super::*;

    #[test]
    fn push_pop_roundtrip() {
        let path = KeyPath::new().push("a").push("b").push("c");
        assert_eq!(path.num_segments(), 3);

        let (path, popped) = path.pop();
        assert_eq!(popped, Some("c".to_string()));
        assert_eq!(path.num_segments(), 2);
        let (path, popped) = path.pop();
        assert_eq!(popped, Some("b".to_string()));
        let (path, popped) = path.pop();
        assert_eq!(popped, Some("a".to_string()));
        let (path, popped) = path.pop();
        assert_eq!(popped, None);
        assert_eq!(path.num_segments(), 0);
    }

    #[test]
    fn from_dotted_and_debug_render() {
        let path = KeyPath::from("a.b.c");
        assert_eq!(path.num_segments(), 3);
        // `From` filters empty pieces.
        assert_eq!(KeyPath::from("a..b.").num_segments(), 2);
        // Display is the debug render (segments joined by `/`).
        assert_eq!(path.to_string(), "a/b/c");
    }

    #[test]
    fn segments_may_contain_delimiter() {
        // Codec elements are self-delimiting, so a `.` in a segment is just
        // content — distinct, recoverable bytes (what the old `.`-join rejected).
        let a = KeyPath::new().push("a").push("b.c");
        let b = KeyPath::new().push("a").push("b").push("c");
        assert_ne!(a.as_bytes(), b.as_bytes());
        let (_, popped) = a.pop();
        assert_eq!(popped, Some("b.c".to_string()));
    }

    #[test]
    fn deref_exposes_codec_bytes() {
        let path = KeyPath::new().push("k");
        assert_eq!(&*path, "k".to_string().encode().as_slice());
    }
}
