use std::{fmt::Display, str::FromStr};

#[derive(Debug, Clone, PartialEq)]
pub struct DotPathBuf {
    segments: Vec<String>,
}

impl FromStr for DotPathBuf {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(DotPathBuf {
            segments: s
                .split('.')
                .filter(|s| !s.is_empty())
                .map(String::from)
                .collect(),
        })
    }
}

impl Display for DotPathBuf {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.segments.join("."))
    }
}

impl DotPathBuf {
    pub fn new() -> Self {
        DotPathBuf {
            segments: Vec::new(),
        }
    }

    pub fn push(&self, segment: impl Into<String>) -> Self {
        let segment = segment.into();
        let mut new_segments = self.segments.clone();
        if !segment.is_empty() {
            new_segments.push(segment);
        }
        DotPathBuf {
            segments: new_segments,
        }
    }

    pub fn pop(&self) -> (Self, Option<String>) {
        let mut new_segments = self.segments.clone();
        let popped = new_segments.pop();
        (
            DotPathBuf {
                segments: new_segments,
            },
            popped,
        )
    }

    pub fn segments(&self) -> impl Iterator<Item = &str> + '_ {
        self.segments.iter().map(|s| s.as_str())
    }
}

impl Default for DotPathBuf {
    fn default() -> Self {
        Self::new()
    }
}

impl From<DotPathBuf> for String {
    fn from(path: DotPathBuf) -> Self {
        path.to_string()
    }
}
