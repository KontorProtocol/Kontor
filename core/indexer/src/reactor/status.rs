use serde::{Deserialize, Serialize};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EngineAuthority {
    Follower,
    Validator,
    Stopped,
}

/// Reactor observation, not proof of signing eligibility or peer freshness.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuntimeStatus {
    pub authority: EngineAuthority,
    pub consensus_height: String,
    pub committee_member: bool,
    pub required_join_height: Option<String>,
}
