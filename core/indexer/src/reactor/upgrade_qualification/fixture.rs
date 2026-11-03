use std::path::Path;

use anyhow::{Context, Result, ensure};
use bitcoin::{BlockHash, blockdata::constants::genesis_block, consensus::serialize, hashes::Hash};
use indexer_types::BlockRow;
use libsql::Connection;
use malachitebft_core_types::{CommitSignature, NilOrVal, Round};
use prost::Message;

use super::{DATABASE, NETWORK, accepted_manifest_schedule};
use crate::bitcoin_client::Client;
use crate::consensus::codec::encode_commit_certificate;
use crate::consensus::signing::PrivateKey;
use crate::consensus::{Address, CommitCertificate, Ctx, Height, Value, Vote};
use crate::database::certified_history::{self, control};
use crate::database::connection::new_connection;
use crate::database::queries::insert_block;
use crate::protocol::coordinator::certified_decision::{AuthenticatedDecision, Decision};
use crate::protocol::coordinator::certified_input::ExactInput;
use crate::protocol::coordinator::genesis::envelope;
use crate::protocol::coordinator::linked::{canonical_session, initialize};
use crate::protocol::coordinator::{bootstrap, successor};
use crate::protocol::identity::{ExecutionDefinitionId, ProtocolId};
use crate::reactor::PruneConfig;
use crate::reactor::execution::ExecutionContext;
use crate::reactor::executor::RuntimeExecutor;
use crate::runtime::ownership::OwnerService;
use crate::runtime::{Decimal, GenesisParameters, GenesisValidator};

pub(super) async fn seed(
    path: &Path,
    service: &OwnerService,
    activation: u64,
) -> Result<ProtocolId> {
    initialize_fixture(path, service, Some(activation), None, false).await
}

pub(super) async fn unscheduled(path: &Path, service: &OwnerService) -> Result<ProtocolId> {
    initialize_fixture(path, service, None, None, false).await
}

pub(super) async fn seed_with_validator(
    path: &Path,
    service: &OwnerService,
    activation: u64,
    validator: &str,
) -> Result<ProtocolId> {
    initialize_fixture(path, service, Some(activation), Some(validator), false).await
}

pub(super) async fn seed_unsupported(path: &Path, service: &OwnerService) -> Result<ProtocolId> {
    initialize_fixture(path, service, Some(2), None, true).await
}

pub(super) fn genesis() -> GenesisParameters {
    GenesisParameters {
        sigma_min: Decimal::from("1"),
        validators: vec![GenesisValidator {
            x_only_pubkey: "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"
                .into(),
            ed25519_pubkey: PrivateKey::from([7; 32]).public_key().as_bytes().to_vec(),
            stake: Decimal::from("100"),
        }],
    }
}

async fn initialize_fixture(
    path: &Path,
    service: &OwnerService,
    activation: Option<u64>,
    validator: Option<&str>,
    unavailable: bool,
) -> Result<ProtocolId> {
    let mut parameters = genesis();
    if let Some(validator) = validator {
        parameters.validators[0].x_only_pubkey = validator.into();
    }
    initialize_parameters(
        path,
        service,
        activation,
        parameters,
        unavailable,
        &[PrivateKey::from([7; 32])],
    )
    .await
}

pub(super) async fn initialize_parameters(
    path: &Path,
    service: &OwnerService,
    activation: Option<u64>,
    parameters: GenesisParameters,
    unavailable: bool,
    signers: &[PrivateKey],
) -> Result<ProtocolId> {
    let conn = new_connection(path, DATABASE).await?;
    let genesis = envelope(&parameters);
    let (baseline, fresh) = bootstrap::prepare(&conn, NETWORK, 1, &genesis).await?;
    ensure!(fresh);
    insert_block(
        &conn,
        BlockRow::builder()
            .height(0)
            .hash(BlockHash::all_zeros())
            .build(),
    )
    .await?;
    let session = canonical_session(conn.clone(), NETWORK).await?;
    initialize(service, &session, NETWORK, 1, genesis).await?;
    let target = match activation {
        Some(height) => {
            let mut manifest = successor::manifest(baseline.context.chain)?;
            if unavailable {
                manifest.executor = ExecutionDefinitionId([238; 32]);
            }
            accepted_manifest_schedule(&conn, &baseline, height, manifest).await?
        }
        None => successor::manifest(baseline.context.chain)?.id()?,
    };
    bootstrap::complete(service, &session, NETWORK, &baseline).await?;
    let input = ExactInput::block(baseline.context, 1, serialize(&genesis_block(NETWORK)))?;
    let input =
        match control::expected_transition(&conn, baseline.context, &input.descriptor().command, 1)
            .await?
        {
            Some(transition) => input.with_transition(transition.descriptor)?,
            None => input,
        };
    append_signed(&conn, input, signers).await?;
    Ok(target)
}

pub(super) async fn append(conn: &Connection, input: ExactInput) -> Result<u64> {
    append_signed(conn, input, &[PrivateKey::from([7; 32])]).await
}

pub(super) async fn append_signed(
    conn: &Connection,
    input: ExactInput,
    signers: &[PrivateKey],
) -> Result<u64> {
    let certified = certify(conn, input, signers).await?;
    let height = certified.decision().height;
    certified_history::append(conn, &certified).await?;
    Ok(height)
}

pub(super) async fn certify(
    conn: &Connection,
    input: ExactInput,
    signers: &[PrivateKey],
) -> Result<AuthenticatedDecision> {
    let height = certified_history::frontier(conn)
        .await?
        .authenticated_height
        + 1;
    let value = Value::from_input(input)?;
    let authority = certified_history::committee(conn, height).await?;
    let commit_signatures = signers
        .iter()
        .map(|key| {
            let address = Address::from_public_key(&key.public_key());
            let vote = Vote::new_precommit(
                Height::new(height),
                Round::new(0),
                NilOrVal::Val(value.id()),
                address,
            );
            CommitSignature {
                address,
                signature: key.sign(&vote.to_sign_bytes()),
            }
        })
        .collect();
    let proof = CommitCertificate::<Ctx> {
        height: Height::new(height),
        round: Round::new(0),
        value_id: value.id(),
        commit_signatures,
    };
    AuthenticatedDecision::verify(
        Decision {
            height,
            predecessor: authority.decision,
            committee: authority.id()?,
            descriptor: value.descriptor().clone(),
        },
        value.input().clone(),
        encode_commit_certificate(&proof)?.encode_to_vec(),
        &authority,
    )
}

pub(super) async fn open(
    path: &Path,
    service: &OwnerService,
) -> Result<ExecutionContext<RuntimeExecutor>> {
    let conn = new_connection(path, DATABASE).await?;
    let context = certified_history::frontier(&conn)
        .await?
        .context
        .context("missing context")?;
    let session = canonical_session(conn, NETWORK).await?;
    Ok(ExecutionContext::new(
        RuntimeExecutor::new(Client::new(
            "http://127.0.0.1:1".into(),
            String::new(),
            String::new(),
        )?),
        session,
        NETWORK,
        service.clone(),
        context,
        PruneConfig {
            enabled: false,
            retain_blocks: 144,
        },
        0,
        None,
    ))
}

pub(super) async fn snapshot(conn: &Connection, path: &Path) -> Result<()> {
    ensure!(conn.is_autocommit());
    conn.execute(
        "VACUUM INTO ?1",
        [path.join(DATABASE).to_str().context("snapshot path")?],
    )
    .await?;
    Ok(())
}
