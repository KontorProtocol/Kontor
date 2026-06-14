use core::{fmt::Display, ops::Deref, str::FromStr};

use alloc::{string::String, vec::Vec};

use crate::keycodec::KeyElement;

/// A storage path: a sequence of segments encoded with the order-preserving
/// [`keycodec`](crate::keycodec) (a `BLOB` key on the host). Keeps the segments
/// as owned `String`s for `pop`/`segments`/debug, alongside the codec `bytes` that
/// the host actually keys on (and which `Deref`/`AsRef` expose). For now every
/// segment is a string element (matching the previous `K::to_string()` behavior);
/// typed elements (numeric sort, compound keys) are layered on later.
#[derive(Debug, Clone, PartialEq)]
pub struct DotPathBuf {
    segments: Vec<String>,
    bytes: Vec<u8>,
}

impl DotPathBuf {
    pub fn new() -> Self {
        DotPathBuf {
            segments: Vec::new(),
            bytes: Vec::new(),
        }
    }

    /// Append one path segment — structural names AND keys (`K::to_string()`,
    /// index keys). The segment is encoded as a string element and appended to the
    /// codec `bytes`; because each element is self-delimiting (`0x00`-terminated,
    /// escaped), a segment may contain ANY content (`.`, `-`, …) without aliasing
    /// — the integrity the old `.`-join had to enforce by rejecting such keys is
    /// now structural.
    pub fn push(&self, segment: impl Into<String>) -> Self {
        let segment = segment.into();
        let mut bytes = self.bytes.clone();
        segment.encode_to(&mut bytes);
        let mut segments = self.segments.clone();
        segments.push(segment);
        DotPathBuf { segments, bytes }
    }

    pub fn pop(&self) -> (Self, Option<String>) {
        let mut segments = self.segments.clone();
        let popped = segments.pop();
        let mut bytes = Vec::new();
        for s in &segments {
            s.encode_to(&mut bytes);
        }
        (DotPathBuf { segments, bytes }, popped)
    }

    pub fn segments(&self) -> impl Iterator<Item = &str> + '_ {
        self.segments.iter().map(|s| s.as_str())
    }

    pub fn num_segments(&self) -> u64 {
        self.segments.len() as u64
    }

    /// The codec bytes the host keys on.
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }
}

impl AsRef<[u8]> for DotPathBuf {
    fn as_ref(&self) -> &[u8] {
        &self.bytes
    }
}

impl From<&str> for DotPathBuf {
    fn from(s: &str) -> Self {
        s.split('.')
            .filter(|s| !s.is_empty())
            .fold(DotPathBuf::new(), |path, seg| path.push(seg))
    }
}

impl FromStr for DotPathBuf {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(DotPathBuf::from(s))
    }
}

impl Display for DotPathBuf {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // Debug rendering only (paths are bytes, not text).
        write!(f, "{}", self.segments.join("."))
    }
}

impl Default for DotPathBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl Deref for DotPathBuf {
    type Target = [u8];

    fn deref(&self) -> &Self::Target {
        &self.bytes
    }
}

#[cfg(test)]
mod tests {
    use alloc::{string::ToString, vec};

    use super::*;

    #[test]
    fn test_from_str() {
        let path: DotPathBuf = "a.b.c".parse().unwrap();
        assert_eq!(path.segments().collect::<Vec<_>>(), vec!["a", "b", "c"]);
        assert_eq!(path.to_string(), "a.b.c");

        let path: DotPathBuf = "a..b".parse().unwrap();
        assert_eq!(path.segments().collect::<Vec<_>>(), vec!["a", "b"]);
        assert_eq!(path.to_string(), "a.b");

        let path: DotPathBuf = "a.b.c.".parse().unwrap();
        assert_eq!(path.segments().collect::<Vec<_>>(), vec!["a", "b", "c"]);
        assert_eq!(path.to_string(), "a.b.c");

        let path: DotPathBuf = ".a.b.c.".parse().unwrap();
        assert_eq!(path.segments().collect::<Vec<_>>(), vec!["a", "b", "c"]);
        assert_eq!(path.to_string(), "a.b.c");

        let path: DotPathBuf = "".parse().unwrap();
        assert_eq!(path.segments().collect::<Vec<_>>(), vec![] as Vec<&str>);
        assert_eq!(path.to_string(), "");
    }

    #[test]
    fn test_push_pop() {
        let path = DotPathBuf::new();
        let path = path.push("a").push("b").push("c");
        assert_eq!(path.to_string(), "a.b.c");
        assert_eq!(path.segments().collect::<Vec<_>>(), vec!["a", "b", "c"]);

        let (path, popped) = path.pop();
        assert_eq!(popped, Some("c".to_string()));
        assert_eq!(path.to_string(), "a.b");

        let (path, popped) = path.pop();
        assert_eq!(popped, Some("b".to_string()));

        let (path, popped) = path.pop();
        assert_eq!(popped, Some("a".to_string()));

        let (path, popped) = path.pop();
        assert_eq!(popped, None);
        assert_eq!(path.to_string(), "");
    }

    #[test]
    fn test_conversions() {
        let path_buf: DotPathBuf = "x.y.z".parse().unwrap();
        assert_eq!(path_buf.to_string(), "x.y.z");
    }

    // Codec elements are self-delimiting, so a segment may now contain `.` or be
    // empty without aliasing — what the old `.`-join had to reject. Distinct
    // content ⇒ distinct, recoverable bytes.
    #[test]
    fn test_segments_may_contain_delimiter() {
        let a = DotPathBuf::new().push("a").push("b.c");
        let b = DotPathBuf::new().push("a").push("b").push("c");
        assert_ne!(a.as_bytes(), b.as_bytes());
        assert_eq!(a.segments().collect::<Vec<_>>(), vec!["a", "b.c"]);
    }

    #[test]
    fn test_equality() {
        let path1: DotPathBuf = "a.b.c".parse().unwrap();
        let path2: DotPathBuf = "a.b.c".parse().unwrap();
        assert_eq!(path1, path2);

        let path3: DotPathBuf = "x.y.z".parse().unwrap();
        assert_ne!(path1, path3);
    }

    #[test]
    fn test_new() {
        let path = DotPathBuf::new();
        assert_eq!(path.segments().collect::<Vec<_>>(), vec![] as Vec<&str>);
        assert_eq!(path.to_string(), "");
    }

}
