use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ThreadObservation {
    pub thread_category: String,
    pub thread_id: String,
    pub process_id: u64,
    pub os_thread_id: u64,
    pub identity_api: String,
    pub page_size_bytes: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    pub requested_bytes: Option<u64>,
    pub mapped_bytes: u64,
    pub guard_bytes: u64,
    pub guard_start: u64,
    pub guard_end: u64,
    pub guard_verification: String,
    pub usable_bytes: u64,
    pub mapped_start: u64,
    pub mapped_end: u64,
    pub usable_start: u64,
    pub usable_end: u64,
    pub measurement_api: String,
    pub guard_treatment: String,
    pub guard_verified: bool,
}
