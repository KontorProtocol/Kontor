use std::time::Duration;

#[cfg(kontor_consensus_runtime)]
use anyhow::anyhow;
use anyhow::{Context, Result};
use malachitebft_app_channel::app::streaming::StreamMessage;
#[cfg(any(
    test,
    feature = "testing",
    feature = "protocol-qualification",
    not(kontor_consensus_runtime)
))]
use malachitebft_app_channel::{Channels, EngineHandle, NetworkMsg, NetworkRequest};
use tokio::time::timeout;

use super::message::Message;
use super::status::EngineAuthority;
#[cfg(any(
    test,
    feature = "testing",
    feature = "protocol-qualification",
    not(kontor_consensus_runtime)
))]
use crate::consensus::Ctx;
use crate::consensus::ProposalPart;
#[cfg(any(
    test,
    feature = "testing",
    feature = "protocol-qualification",
    not(kontor_consensus_runtime)
))]
use crate::consensus::signing::Ed25519Provider;
use crate::consensus::signing::Signature;
use crate::protocol::coordinator::certified_decision::CommitteeRecord;

#[cfg(kontor_consensus_runtime)]
use crate::consensus::codec::ProtobufCodec;
#[cfg(kontor_consensus_runtime)]
use crate::protocol::coordinator::durable_signer::DurableSigner;
#[cfg(kontor_consensus_runtime)]
use crate::protocol::coordinator::managed::reactor::ReactorEngine;
#[cfg(kontor_consensus_runtime)]
use crate::protocol::coordinator::managed::types::{ProposalPartBytes, PublishError};
#[cfg(kontor_consensus_runtime)]
use malachitebft_codec::Codec;
#[cfg(kontor_consensus_runtime)]
use std::sync::Arc;
#[cfg(kontor_consensus_runtime)]
use tokio::time::sleep;

pub(super) struct Engine {
    backend: Backend,
}

enum Backend {
    #[cfg(kontor_consensus_runtime)]
    Stopped,
    #[cfg(any(
        test,
        feature = "testing",
        feature = "protocol-qualification",
        not(kontor_consensus_runtime)
    ))]
    Legacy {
        channels: Channels<Ctx>,
        handle: EngineHandle,
        signer: Ed25519Provider,
        consensus_enabled: bool,
    },
    #[cfg(kontor_consensus_runtime)]
    Managed {
        engine: ReactorEngine,
        signer: Option<Arc<DurableSigner>>,
    },
}

impl Engine {
    pub(super) fn authority(&self) -> EngineAuthority {
        match &self.backend {
            #[cfg(kontor_consensus_runtime)]
            Backend::Stopped => EngineAuthority::Stopped,
            #[cfg(any(
                test,
                feature = "testing",
                feature = "protocol-qualification",
                not(kontor_consensus_runtime)
            ))]
            Backend::Legacy {
                consensus_enabled, ..
            } => {
                if *consensus_enabled {
                    EngineAuthority::Validator
                } else {
                    EngineAuthority::Follower
                }
            }
            #[cfg(kontor_consensus_runtime)]
            Backend::Managed { signer, .. } => {
                if signer.is_some() {
                    EngineAuthority::Validator
                } else {
                    EngineAuthority::Follower
                }
            }
        }
    }

    #[cfg(any(
        test,
        feature = "testing",
        feature = "protocol-qualification",
        not(kontor_consensus_runtime)
    ))]
    pub(super) fn legacy(
        channels: Channels<Ctx>,
        handle: EngineHandle,
        signer: Ed25519Provider,
        consensus_enabled: bool,
    ) -> Self {
        Self {
            backend: Backend::Legacy {
                channels,
                handle,
                signer,
                consensus_enabled,
            },
        }
    }

    #[cfg(kontor_consensus_runtime)]
    pub(super) fn managed(engine: ReactorEngine) -> Self {
        let signer = engine.signer();
        Self {
            backend: Backend::Managed { engine, signer },
        }
    }

    pub(super) async fn next(&mut self) -> Result<Option<Message>> {
        match &mut self.backend {
            #[cfg(kontor_consensus_runtime)]
            Backend::Stopped => Ok(None),
            #[cfg(any(
                test,
                feature = "testing",
                feature = "protocol-qualification",
                not(kontor_consensus_runtime)
            ))]
            Backend::Legacy { channels, .. } => Ok(channels.consensus.recv().await.map(Into::into)),
            #[cfg(kontor_consensus_runtime)]
            Backend::Managed { engine, .. } => Ok(engine.next().await?),
        }
    }

    pub(super) async fn publish(&mut self, part: StreamMessage<ProposalPart>) -> Result<()> {
        match &mut self.backend {
            #[cfg(kontor_consensus_runtime)]
            Backend::Stopped => Err(anyhow!("consensus engine is stopped")),
            #[cfg(any(
                test,
                feature = "testing",
                feature = "protocol-qualification",
                not(kontor_consensus_runtime)
            ))]
            Backend::Legacy { channels, .. } => channels
                .network
                .send(NetworkMsg::PublishProposalPart(part))
                .await
                .context("failed to publish proposal part"),
            #[cfg(kontor_consensus_runtime)]
            Backend::Managed { engine, .. } => {
                let mut part = ProposalPartBytes(ProtobufCodec.encode(&part)?.to_vec());
                loop {
                    match engine.publish(part).await {
                        Ok(()) => return Ok(()),
                        Err(PublishError::Full(returned)) => {
                            part = returned;
                            sleep(Duration::from_millis(2)).await;
                        }
                        Err(PublishError::Closed(_)) => {
                            return Err(anyhow!("proposal channel closed"));
                        }
                        Err(PublishError::Unconfirmed) => {
                            return Err(anyhow!("proposal publication acknowledgement lost"));
                        }
                        Err(PublishError::Engine(error, _)) => return Err(error.into()),
                    }
                }
            }
        }
    }

    pub(super) async fn listen_address(&mut self) -> Result<Option<String>> {
        timeout(Duration::from_secs(5), async {
            match &mut self.backend {
                #[cfg(kontor_consensus_runtime)]
                Backend::Stopped => Ok(None),
                #[cfg(any(
                    test,
                    feature = "testing",
                    feature = "protocol-qualification",
                    not(kontor_consensus_runtime)
                ))]
                Backend::Legacy { channels, .. } => {
                    Ok(NetworkRequest::dump_state(&channels.net_requests)
                        .await?
                        .map(|dump| dump.local_node.listen_addr.to_string()))
                }
                #[cfg(kontor_consensus_runtime)]
                Backend::Managed { engine, .. } => {
                    while !engine.request_listen_address().await? {
                        sleep(Duration::from_millis(2)).await;
                    }
                    loop {
                        if let Some(address) = engine.poll_listen_address().await? {
                            return Ok(Some(address));
                        }
                        sleep(Duration::from_millis(2)).await;
                    }
                }
            }
        })
        .await
        .context("consensus listener lookup timed out")?
    }

    pub(super) async fn sign_proposal_fin(
        &mut self,
        height: u64,
        round: u32,
        descriptor: Vec<u8>,
        digest: [u8; 32],
    ) -> Result<Signature> {
        match &mut self.backend {
            #[cfg(kontor_consensus_runtime)]
            Backend::Stopped => Err(anyhow!("consensus engine is stopped")),
            #[cfg(any(
                test,
                feature = "testing",
                feature = "protocol-qualification",
                not(kontor_consensus_runtime)
            ))]
            Backend::Legacy { signer, .. } => {
                let _ = (height, round, descriptor);
                Ok(signer.sign(&digest))
            }
            #[cfg(kontor_consensus_runtime)]
            Backend::Managed { signer, .. } => {
                let signer = signer.clone().context("follower cannot sign proposals")?;
                let bytes = tokio::task::spawn_blocking(move || {
                    signer.sign_proposal_fin(height, round, &descriptor, digest)
                })
                .await
                .context("proposal signing task failed")??;
                Ok(Signature::from_bytes(bytes))
            }
        }
    }

    pub(super) async fn authorize_height(
        &self,
        committee: CommitteeRecord,
        completed_closure: [u8; 32],
    ) -> Result<()> {
        match &self.backend {
            #[cfg(kontor_consensus_runtime)]
            Backend::Stopped => Err(anyhow!("consensus engine is stopped")),
            #[cfg(kontor_consensus_runtime)]
            Backend::Managed {
                signer: Some(signer),
                ..
            } => {
                let signer = signer.clone();
                tokio::task::spawn_blocking(move || {
                    signer.authorize_height(&committee, completed_closure)
                })
                .await
                .context("height authorization task failed")??;
                Ok(())
            }
            _ => {
                let _ = (committee, completed_closure);
                Ok(())
            }
        }
    }

    pub(super) async fn stop(&mut self, deadline: Duration) -> Result<bool> {
        match &mut self.backend {
            #[cfg(kontor_consensus_runtime)]
            Backend::Stopped => Ok(true),
            #[cfg(any(
                test,
                feature = "testing",
                feature = "protocol-qualification",
                not(kontor_consensus_runtime)
            ))]
            Backend::Legacy { handle, .. } => {
                handle.actor.stop(Some("Reactor shutting down".into()));
                match timeout(deadline, &mut handle.handle).await {
                    Ok(result) => {
                        result.context("legacy consensus task failed")?;
                        Ok(true)
                    }
                    Err(_) => Ok(false),
                }
            }
            #[cfg(kontor_consensus_runtime)]
            Backend::Managed { engine, .. } => {
                engine.retire();
                match timeout(deadline, async {
                    engine.revoke_signing().await?;
                    engine.wait_stopped(deadline).await
                })
                .await
                {
                    Ok(result) => {
                        let joined = result?;
                        if joined {
                            // The stopped transport and control handles still own signer
                            // references. Release them only after revocation and join,
                            // before the replacement opens the same durable journal.
                            self.backend = Backend::Stopped;
                        }
                        Ok(joined)
                    }
                    Err(_) => Ok(false),
                }
            }
        }
    }

    #[cfg(any(test, feature = "protocol-qualification"))]
    pub(super) fn legacy_handle(&self) -> &EngineHandle {
        match &self.backend {
            #[cfg(any(
                test,
                feature = "testing",
                feature = "protocol-qualification",
                not(kontor_consensus_runtime)
            ))]
            Backend::Legacy { handle, .. } => handle,
            #[cfg(kontor_consensus_runtime)]
            _ => panic!("legacy fixture used with managed engine"),
        }
    }

    #[cfg(test)]
    pub(super) fn legacy_handle_mut(&mut self) -> &mut EngineHandle {
        match &mut self.backend {
            #[cfg(any(
                test,
                feature = "testing",
                feature = "protocol-qualification",
                not(kontor_consensus_runtime)
            ))]
            Backend::Legacy { handle, .. } => handle,
            #[cfg(kontor_consensus_runtime)]
            _ => panic!("legacy fixture used with managed engine"),
        }
    }

    #[cfg(test)]
    pub(super) fn legacy_channels_mut(&mut self) -> &mut Channels<Ctx> {
        match &mut self.backend {
            #[cfg(any(
                test,
                feature = "testing",
                feature = "protocol-qualification",
                not(kontor_consensus_runtime)
            ))]
            Backend::Legacy { channels, .. } => channels,
            #[cfg(kontor_consensus_runtime)]
            _ => panic!("legacy fixture used with managed engine"),
        }
    }
}

impl Drop for Engine {
    fn drop(&mut self) {
        // Construction can fail before the reactor gets a chance to run its shutdown path.
        match &mut self.backend {
            #[cfg(any(
                test,
                feature = "testing",
                feature = "protocol-qualification",
                not(kontor_consensus_runtime)
            ))]
            Backend::Legacy { handle, .. } => handle.actor.stop(None),
            #[cfg(kontor_consensus_runtime)]
            Backend::Stopped => {}
            #[cfg(kontor_consensus_runtime)]
            Backend::Managed { engine, .. } => engine.retire(),
        }
    }
}
