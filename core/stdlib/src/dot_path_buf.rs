use std::{fmt::Display, ops::Deref, str::FromStr};

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
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
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
