use std::time::{Duration, Instant};

use bitcoin::Network;

/// Readiness observation only: never an input to consensus or block processing.
#[derive(Clone, Debug)]
pub(crate) struct ChainObservation {
    pub chain: Network,
    pub blocks: u64,
    pub headers: u64,
    pub initial_block_download: bool,
    pub observed_at: Instant,
}

impl ChainObservation {
    /// A one-block race is normal between tip discovery and index publication.
    /// Expire observations after 30s so an unreachable backend cannot leave a
    /// warm database reporting ready indefinitely. The follower normally polls
    /// every 2s; probes only read its last successful observation.
    pub(crate) fn is_synced(&self, indexed: Option<u64>, network: Network, now: Instant) -> bool {
        let Some(indexed) = indexed else {
            return false;
        };
        self.chain == network
            && !self.initial_block_download
            && now
                .checked_duration_since(self.observed_at)
                .is_some_and(|age| age <= Duration::from_secs(30))
            && self.headers >= self.blocks
            && indexed <= self.blocks
            && self.blocks - indexed <= 1
            && self.headers.saturating_sub(indexed) <= 1
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tip() -> ChainObservation {
        ChainObservation {
            chain: Network::Regtest,
            blocks: 100,
            headers: 100,
            initial_block_download: false,
            observed_at: Instant::now(),
        }
    }

    #[test]
    fn requires_indexed_state_and_accepts_only_one_block_of_lag() {
        let observation = tip();
        let now = Instant::now();
        assert!(!observation.is_synced(None, Network::Regtest, now));
        assert!(!observation.is_synced(Some(0), Network::Regtest, now));
        assert!(!observation.is_synced(Some(98), Network::Regtest, now));
        assert!(observation.is_synced(Some(99), Network::Regtest, now));
        assert!(observation.is_synced(Some(100), Network::Regtest, now));
        assert!(!observation.is_synced(Some(101), Network::Regtest, now));
    }

    #[test]
    fn stale_or_future_observation_cannot_report_ready() {
        let observation = tip();
        assert!(observation.is_synced(
            Some(100),
            Network::Regtest,
            observation.observed_at + Duration::from_secs(30)
        ));
        assert!(!observation.is_synced(
            Some(100),
            Network::Regtest,
            observation.observed_at + Duration::from_secs(31)
        ));
        assert!(!observation.is_synced(
            Some(100),
            Network::Regtest,
            observation.observed_at - Duration::from_secs(1)
        ));
    }

    #[test]
    fn rejects_ibd_wrong_network_and_headers_far_ahead() {
        let mut observation = tip();
        let now = Instant::now();
        assert!(!observation.is_synced(Some(100), Network::Signet, now));
        observation.initial_block_download = true;
        assert!(!observation.is_synced(Some(100), Network::Regtest, now));
        observation.initial_block_download = false;
        observation.headers = 102;
        assert!(!observation.is_synced(Some(100), Network::Regtest, now));
        observation.headers = 101;
        assert!(observation.is_synced(Some(100), Network::Regtest, now));
        observation.headers = 99;
        assert!(!observation.is_synced(Some(100), Network::Regtest, now));
    }

    #[test]
    fn height_boundaries_do_not_overflow_or_invent_a_tip() {
        let mut observation = tip();
        observation.blocks = 0;
        observation.headers = 0;
        assert!(observation.is_synced(Some(0), Network::Regtest, Instant::now()));
        observation.blocks = u64::MAX;
        observation.headers = u64::MAX;
        assert!(observation.is_synced(Some(u64::MAX), Network::Regtest, Instant::now()));
        assert!(!observation.is_synced(Some(0), Network::Regtest, Instant::now()));
    }
}
