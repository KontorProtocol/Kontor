use std::sync::Arc;

pub(crate) use kontor_consensus_first::api::{
    Bootstrap, Discovery, EngineConfig as Configuration, PeerSelection,
};

use super::adapter::RuntimeEngine;
use super::types::EngineError;
use crate::protocol::coordinator::durable_signer::{
    DurableSigner, SigningError, SigningRequest, VoteStep,
};

mod runtime_startup {
    use std::sync::Arc;

    use kontor_consensus_first::Engine;
    use kontor_consensus_first::api;
    use kontor_consensus_first::authority_api as authority;

    use super::{Configuration, DurableSigner, SigningError, SigningRequest, VoteStep};

    struct Signer(Arc<DurableSigner>);

    impl authority::SigningService for Signer {
        fn sign(
            &self,
            value: authority::SigningRequest,
        ) -> Result<[u8; 64], authority::SigningError> {
            self.0.sign(request(value)).map_err(error)
        }
    }

    fn request(value: authority::SigningRequest) -> SigningRequest {
        match value {
            authority::SigningRequest::Vote {
                generation,
                height,
                round,
                step,
                value_id,
                validator_address,
                preimage,
            } => SigningRequest::Vote {
                generation,
                height,
                round,
                step: match step {
                    authority::VoteStep::Prevote => VoteStep::Prevote,
                    authority::VoteStep::Precommit => VoteStep::Precommit,
                },
                value_id,
                validator_address,
                preimage,
            },
            authority::SigningRequest::Proposal {
                generation,
                height,
                round,
                pol_round,
                validator_address,
                descriptor,
                preimage,
            } => SigningRequest::Proposal {
                generation,
                height,
                round,
                pol_round,
                validator_address,
                descriptor,
                preimage,
            },
            authority::SigningRequest::ProposalFin {
                generation,
                height,
                round,
                descriptor,
                digest,
            } => SigningRequest::ProposalFin {
                generation,
                height,
                round,
                descriptor,
                digest,
            },
            authority::SigningRequest::ValidatorProof {
                generation,
                public_key,
                network_peer_id,
                preimage,
            } => SigningRequest::ValidatorProof {
                generation,
                public_key,
                network_peer_id,
                preimage,
            },
        }
    }

    fn error(value: SigningError) -> authority::SigningError {
        match value {
            SigningError::InvalidRequest(reason) => authority::SigningError::InvalidRequest(reason),
            SigningError::Conflict => authority::SigningError::Conflict,
            SigningError::Stale => authority::SigningError::Stale,
            SigningError::Fenced => authority::SigningError::Fenced,
            SigningError::Storage(reason) => authority::SigningError::Storage(reason),
            SigningError::Fault(reason) => authority::SigningError::Fault(reason),
        }
    }

    pub(super) fn start(
        input: Configuration,
        signer: Option<Arc<DurableSigner>>,
    ) -> Result<Engine, api::EngineError> {
        let authority = match signer {
            Some(signer) => authority::Authority::Validator {
                public_key: signer.public_key(),
                signer: Arc::new(Signer(signer)),
            },
            None => authority::Authority::Follower,
        };
        kontor_consensus_first::start(input, authority)
    }
}

#[cfg(test)]
pub(crate) fn network_peer_id(key: &[u8; 32]) -> Result<Vec<u8>, EngineError> {
    kontor_consensus_first::network_peer_id(key)
}

pub(crate) fn start(
    config: Configuration,
    signer: Option<Arc<DurableSigner>>,
) -> Result<RuntimeEngine, EngineError> {
    runtime_startup::start(config, signer).map(RuntimeEngine)
}

#[cfg(test)]
mod tests {
    use std::thread;
    use std::time::{Duration, Instant};

    use malachitebft_signing_ed25519::PrivateKey;
    use tempfile::TempDir;

    use super::*;
    use crate::consensus::test_fixtures;
    use crate::protocol::coordinator::durable_signer::SignerIdentity;
    use crate::protocol::coordinator::managed::types::{EnginePoll, EngineState, Request};

    #[test]
    fn successive_generations_start_through_the_node_signer_and_release_ownership() {
        let directory = TempDir::new().unwrap();
        let signer_path = directory.path().join("signer");
        let key = PrivateKey::from([11; 32]);
        for generation in [1, 2] {
            let network_key = [7; 32];
            let peer_id = network_peer_id(&network_key).unwrap();
            let signer = Arc::new(
                DurableSigner::open(
                    &signer_path,
                    SignerIdentity {
                        context: test_fixtures::context(),
                        generation,
                        network_peer_id: peer_id,
                    },
                    key.clone(),
                )
                .unwrap(),
            );
            let config = Configuration {
                generation,
                channel_capacity: 8,
                moniker: "node-authority-test".into(),
                network_key,
                listen_address: "/ip4/127.0.0.1/tcp/0".into(),
                persistent_peers: vec![],
                wal_path: directory.path().join(format!("era-{generation}.wal")),
                discovery: Discovery {
                    enabled: false,
                    bootstrap: Bootstrap::Full,
                    selection: PeerSelection::Random,
                },
                readiness_timeout: Duration::from_secs(10),
            };
            let mut engine = start(config, Some(signer.clone())).unwrap();
            let deadline = Instant::now() + Duration::from_secs(10);
            loop {
                match engine.poll().unwrap() {
                    EnginePoll::Event(event) => {
                        assert_eq!(event.generation, generation);
                        assert_eq!(event.request, Request::Ready);
                        break;
                    }
                    EnginePoll::Idle | EnginePoll::Handled => {}
                }
                assert!(Instant::now() < deadline, "engine did not become ready");
                thread::sleep(Duration::from_millis(2));
            }
            // Revocation is a node operation, independent of the engine owner.
            signer.fence_generation(generation).unwrap();
            engine.request_stop().unwrap();
            assert!(engine.wait_stopped(Duration::from_secs(10)).unwrap());
            assert_eq!(engine.state(), EngineState::Joined);
            drop(engine);
            drop(signer);
            assert!(matches!(
                DurableSigner::open(
                    &signer_path,
                    SignerIdentity {
                        context: test_fixtures::context(),
                        generation,
                        network_peer_id: network_peer_id(&network_key).unwrap(),
                    },
                    key.clone(),
                ),
                Err(SigningError::Fenced)
            ));
        }
    }
}
