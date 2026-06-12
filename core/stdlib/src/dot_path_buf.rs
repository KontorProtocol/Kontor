use core::{fmt::Display, ops::Deref, str::FromStr};

use alloc::{string::String, vec::Vec};

#[derive(Debug, Clone, PartialEq)]
pub struct DotPathBuf {
    segments: Vec<String>,
    joined: String, // Store the joined string
}

impl DotPathBuf {
    pub fn new() -> Self {
        DotPathBuf {
            segments: Vec::new(),
            joined: String::new(),
        }
    }

    /// Append one path segment. This is the single choke point every segment
    /// passes through — structural names AND keys (`K::to_string()`, index keys)
    /// — so it's where key integrity is enforced. A segment is stored verbatim
    /// into the `.`-joined string the host actually keys on, so a segment that
    /// contains `.` would silently split into extra segments (the host re-parses
    /// `joined`, disagreeing with our `segments` vec) and an empty segment would
    /// collapse onto the parent path. Both corrupt consensus state, so reject
    /// them loudly here rather than store an unfindable/aliased row. No legitimate
    /// structural segment is ever empty or dotted, so this only ever fires on a
    /// bad key.
    pub fn push(&self, segment: impl Into<String>) -> Self {
        let segment = segment.into();
        assert!(
            !segment.is_empty(),
            "path segment must not be empty (an empty map/index key would collapse onto the parent path)"
        );
        assert!(
            !segment.contains('.'),
            "path segment must not contain the delimiter '.': {segment:?} (a key with a '.' would corrupt the path)"
        );
        let mut new_segments = self.segments.clone();
        let mut new_joined = self.joined.clone();
        new_segments.push(segment.clone());
        if !new_joined.is_empty() {
            new_joined.push('.');
        }
        new_joined.push_str(&segment);
        DotPathBuf {
            segments: new_segments,
            joined: new_joined,
        }
    }

    pub fn pop(&self) -> (Self, Option<String>) {
        let mut new_segments = self.segments.clone();
        let popped = new_segments.pop();
        let new_joined = new_segments.join(".");
        (
            DotPathBuf {
                segments: new_segments,
                joined: new_joined,
            },
            popped,
        )
    }

    pub fn segments(&self) -> impl Iterator<Item = &str> + '_ {
        self.segments.iter().map(|s| s.as_str())
    }

    pub fn num_segments(&self) -> u64 {
        self.segments.len() as u64
    }
}

impl AsRef<str> for DotPathBuf {
    fn as_ref(&self) -> &str {
        &self.joined
    }
}

impl From<&str> for DotPathBuf {
    fn from(s: &str) -> Self {
        let segments = s
            .split('.')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect::<Vec<String>>();
        let joined = segments.join(".");
        DotPathBuf { segments, joined }
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
        write!(f, "{}", self.joined)
    }
}

impl Default for DotPathBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl From<DotPathBuf> for String {
    fn from(path: DotPathBuf) -> Self {
        path.joined
    }
}

impl Deref for DotPathBuf {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        &self.joined // Return a &str referencing the stored joined string
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
        let s: String = path_buf.into();
        assert_eq!(s, "x.y.z");
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

    #[test]
    #[should_panic(expected = "delimiter")]
    fn push_rejects_dotted_segment() {
        // A key containing the path delimiter would corrupt the path.
        DotPathBuf::new().push("a").push("b.c");
    }

    #[test]
    #[should_panic(expected = "empty")]
    fn push_rejects_empty_segment() {
        // An empty key would collapse onto the parent path.
        DotPathBuf::new().push("a").push("");
    }
}
