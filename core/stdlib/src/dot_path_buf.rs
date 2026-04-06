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

    pub fn push(&self, segment: impl Into<String>) -> Self {
        let segment = segment.into();
        let mut new_segments = self.segments.clone();
        let mut new_joined = self.joined.clone();
        if !segment.is_empty() {
            new_segments.push(segment.clone());
            if !new_joined.is_empty() {
                new_joined.push('.');
            }
            new_joined.push_str(&segment);
        }
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

impl FromStr for DotPathBuf {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let segments = s
            .split('.')
            .filter(|s| !s.is_empty())
            .map(String::from)
            .collect::<Vec<String>>();
        let joined = segments.join(".");
        Ok(DotPathBuf { segments, joined })
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

        let path = path.push("");
        assert_eq!(path.to_string(), "a.b.c");

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
}
