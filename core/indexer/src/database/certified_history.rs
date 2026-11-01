use anyhow::{Context, Result, ensure};
use bitcoin::hashes::Hash;
use libsql::{Connection, TransactionBehavior, params};

use super::canonical_history::{self, HistoryState};
use crate::protocol::canonical_codec::{Decoder, Encoder};
use crate::protocol::coordinator::baseline::Baseline;
use crate::protocol::coordinator::certified_decision::{
    AuthenticatedDecision, CommitteeRecord, Decision, verify_certificate,
};
use crate::protocol::coordinator::certified_input::{EraContext, ExactInput};
use crate::protocol::coordinator::manifest::ProtocolManifest;
use crate::protocol::coordinator::registration_history::RegistrationSnapshot;
use crate::protocol::identity::{ProtocolId, domain_digest};

pub(crate) mod branch;
pub(crate) mod closure;
pub(crate) mod completion;
pub(crate) mod finality;
mod proof_read;
pub(crate) mod registrations;
pub(crate) mod replay;
pub(crate) mod replay_input;
pub(crate) mod work;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Status {
    Pending,
    Initializing,
    Ready,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Frontier {
    pub(crate) status: Status,
    pub(crate) context: Option<EraContext>,
    pub(crate) genesis: Option<[u8; 32]>,
    pub(crate) authenticated_height: u64,
    pub(crate) authenticated_id: Option<[u8; 32]>,
    pub(crate) closed_height: u64,
    pub(crate) closure_id: Option<[u8; 32]>,
}

fn fixed<const N: usize>(bytes: Vec<u8>) -> Result<[u8; N]> {
    bytes
        .try_into()
        .map_err(|_| anyhow::anyhow!("invalid certified history field length"))
}

fn context_bytes(context: EraContext) -> Result<Vec<u8>> {
    let mut encoded = Encoder::default();
    context.encode(&mut encoded)?;
    Ok(encoded.finish())
}

pub(crate) fn genesis_predecessor(context: EraContext) -> Result<[u8; 32]> {
    Ok(domain_digest(
        b"kontor/certified-genesis/v1",
        &context_bytes(context)?,
    ))
}

async fn durable_writer(conn: &Connection) -> Result<()> {
    ensure!(
        conn.is_autocommit(),
        "certified history requires an idle writer"
    );
    // Acknowledgement promises persistence even across power loss. NORMAL WAL
    // commits alone do not establish that promise. Set before opening the unit.
    conn.execute_batch("PRAGMA synchronous = FULL;").await?;
    Ok(())
}

pub(crate) async fn initialize(conn: &Connection) -> Result<()> {
    durable_writer(conn).await?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    tx.execute_batch(include_str!("sql/certified_history.sql"))
        .await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn frontier(conn: &Connection) -> Result<Frontier> {
    let row = conn.query("SELECT status, context, genesis_id, authenticated_height,
        authenticated_id, closed_height, closure_id FROM certified_history_state WHERE singleton = 1", ())
        .await?.next().await?.context("missing certified history state")?;
    let status = match row.get::<String>(0)?.as_str() {
        "pending" => Status::Pending,
        "initializing" => Status::Initializing,
        "ready" => Status::Ready,
        "unavailable" => Status::Unavailable,
        _ => anyhow::bail!("invalid certified history status"),
    };
    let context = row
        .get::<Option<Vec<u8>>>(1)?
        .map(|bytes| -> Result<EraContext> {
            let mut decoder = Decoder::new(&bytes);
            let context = EraContext::decode(&mut decoder)?;
            decoder.finish()?;
            ensure!(context.codec == 1, "unsupported history codec");
            Ok(context)
        })
        .transpose()?;
    let result = Frontier {
        status,
        context,
        genesis: row.get::<Option<Vec<u8>>>(2)?.map(fixed).transpose()?,
        authenticated_height: u64::from_be_bytes(fixed(row.get(3)?)?),
        authenticated_id: row.get::<Option<Vec<u8>>>(4)?.map(fixed).transpose()?,
        closed_height: u64::from_be_bytes(fixed(row.get(5)?)?),
        closure_id: row.get::<Option<Vec<u8>>>(6)?.map(fixed).transpose()?,
    };
    ensure!(
        result.closed_height <= result.authenticated_height,
        "closed history exceeds authenticated history"
    );
    if let Some(context) = result.context {
        ensure!(
            result.genesis == Some(genesis_predecessor(context)?),
            "genesis predecessor differs"
        );
        if result.authenticated_height == 0 {
            ensure!(
                result.authenticated_id == result.genesis,
                "invalid empty decision frontier"
            );
        }
    }
    Ok(result)
}

#[cfg(test)]
pub(crate) async fn begin_genesis(conn: &Connection, context: EraContext) -> Result<()> {
    reserve_genesis(conn, context, None, 1).await
}

pub(crate) async fn begin_baseline(
    conn: &Connection,
    baseline: &Baseline,
    first_bitcoin_height: u64,
) -> Result<()> {
    ensure!(
        baseline.manifest.chain == baseline.context.chain
            && baseline.manifest.id()? == baseline.context.protocol,
        "baseline manifest/context binding differs"
    );
    reserve_genesis(
        conn,
        baseline.context,
        Some(&baseline.manifest),
        first_bitcoin_height,
    )
    .await
}

pub(crate) async fn protocol(conn: &Connection, id: ProtocolId) -> Result<ProtocolManifest> {
    let row = conn
        .query(
            "SELECT manifest FROM certified_protocols WHERE protocol_id = ?1",
            [id.0.to_vec()],
        )
        .await?
        .next()
        .await?
        .context("certified protocol manifest unavailable")?;
    let manifest = ProtocolManifest::decode(&row.get::<Vec<u8>>(0)?)?;
    ensure!(
        manifest.id()? == id,
        "stored protocol manifest identity differs"
    );
    Ok(manifest)
}

async fn reserve_genesis(
    conn: &Connection,
    context: EraContext,
    manifest: Option<&ProtocolManifest>,
    first_bitcoin_height: u64,
) -> Result<()> {
    ensure!(context.codec == 1, "unsupported genesis history codec");
    ensure!(
        first_bitcoin_height > 0,
        "Bitcoin start height must be positive"
    );
    durable_writer(conn).await?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let state = frontier(&tx).await?;
    match state.status {
        Status::Pending => {
            let history = canonical_history::state(&tx).await?;
            ensure!(
                matches!(history, HistoryState::PendingGenesis)
                    || matches!(history, HistoryState::Ready(cursor) if cursor.chain == context.chain && cursor.ordinal == 0 && cursor.authentic),
                "cannot reserve certified genesis over execution history"
            );
            let populated: i64 = tx
                .query(
                    "SELECT EXISTS(SELECT 1 FROM blocks)
                OR EXISTS(SELECT 1 FROM contracts) OR EXISTS(SELECT 1 FROM contract_state)
                OR EXISTS(SELECT 1 FROM transactions) OR EXISTS(SELECT 1 FROM signers)
                OR EXISTS(SELECT 1 FROM checkpoints) OR EXISTS(SELECT 1 FROM batches)",
                    (),
                )
                .await?
                .next()
                .await?
                .context("missing genesis emptiness check")?
                .get(0)?;
            ensure!(
                populated == 0,
                "cannot reserve certified genesis over populated state"
            );
            tx.execute(
                "UPDATE certified_history_state SET status = 'initializing', context = ?1,
                genesis_id = ?2, authenticated_id = ?2 WHERE singleton = 1",
                params![
                    context_bytes(context)?,
                    genesis_predecessor(context)?.to_vec()
                ],
            )
            .await?;
        }
        Status::Initializing | Status::Ready => ensure!(
            state.context == Some(context),
            "certified genesis context changed"
        ),
        Status::Unavailable => {
            anyhow::bail!("certified history unavailable; authentic rebuild required")
        }
    }
    if let Some(manifest) = manifest {
        if state.status == Status::Pending {
            tx.execute(
                "INSERT INTO certified_protocols (protocol_id, manifest) VALUES (?1, ?2)",
                params![context.protocol.0.to_vec(), manifest.encode()?],
            )
            .await?;
        } else {
            ensure!(
                protocol(&tx, context.protocol).await? == *manifest,
                "certified baseline manifest changed on restart"
            );
        }
    }
    branch::reserve(
        &tx,
        context,
        first_bitcoin_height,
        state.status == Status::Pending,
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn finish_genesis(
    conn: &Connection,
    observation: &RegistrationSnapshot,
) -> Result<()> {
    observation.verify_successor(None)?;
    let authority = observation.authority()?;
    let record = authority.encode()?;
    let id = authority.id()?;
    durable_writer(conn).await?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let state = frontier(&tx).await?;
    ensure!(
        matches!(state.status, Status::Initializing | Status::Ready),
        "certified genesis was not reserved"
    );
    ensure!(
        state.context == Some(authority.context)
            && authority.height == 1
            && Some(authority.decision) == state.genesis
            && authority.stage == 0,
        "invalid genesis authority provenance"
    );
    if state.status == Status::Ready {
        ensure!(
            committee(&tx, 1).await? == authority
                && registrations::at(&tx, 0, 0).await? == *observation,
            "genesis authority changed on retry"
        );
    } else {
        let HistoryState::Ready(cursor) = canonical_history::state(&tx).await? else {
            anyhow::bail!("genesis lacks authentic canonical lineage");
        };
        ensure!(
            cursor.authentic
                && cursor.chain == authority.context.chain
                && cursor.lineage == authority.lineage,
            "genesis authority lineage differs"
        );
        registrations::record(&tx, observation).await?;
        tx.execute(
            "INSERT INTO historical_committees (height, committee_id, record) VALUES (?1, ?2, ?3)",
            params![1u64.to_be_bytes().to_vec(), id.to_vec(), record.clone()],
        )
        .await?;
        let closure = domain_digest(b"kontor/genesis-closure/v1", &record);
        tx.execute("UPDATE certified_history_state SET status = 'ready', closure_id = ?1 WHERE singleton = 1",
            [closure.to_vec()]).await?;
    }
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn committee(conn: &Connection, height: u64) -> Result<CommitteeRecord> {
    let row = conn
        .query(
            "SELECT committee_id, record FROM historical_committees WHERE height = ?1",
            [height.to_be_bytes().to_vec()],
        )
        .await?
        .next()
        .await?
        .context("historical committee unavailable")?;
    let authority = CommitteeRecord::decode(&row.get::<Vec<u8>>(1)?)?;
    ensure!(
        authority.height == height && authority.id()? == fixed::<32>(row.get(0)?)?,
        "historical committee binding differs"
    );
    Ok(authority)
}

pub(crate) struct RetainedInput {
    decision: Decision,
    input: ExactInput,
}

impl RetainedInput {
    pub(crate) fn decision(&self) -> &Decision {
        &self.decision
    }

    pub(crate) fn input(&self) -> &ExactInput {
        &self.input
    }
}

async fn load_record(
    conn: &Connection,
    height: u64,
) -> Result<(RetainedInput, usize, Option<usize>)> {
    let row = conn.query("SELECT d.decision_id, d.record, i.body, length(d.original_proof), length(d.proof_augmentation),
        d.committee_id, d.body_digest, d.bitcoin_height, d.bitcoin_hash, d.is_block FROM certified_decisions d JOIN certified_inputs i ON d.body_digest = i.body_digest
        WHERE d.height = ?1", [height.to_be_bytes().to_vec()]).await?.next().await?.context("certified decision unavailable")?;
    let decision = Decision::decode(&row.get::<Vec<u8>>(1)?)?;
    ensure!(
        decision.height == height
            && decision.id()? == fixed::<32>(row.get(0)?)?
            && decision.committee == fixed::<32>(row.get(5)?)?
            && decision.descriptor.body_digest == fixed::<32>(row.get(6)?)?,
        "certified decision binding differs"
    );
    let position = decision.descriptor.command.position();
    ensure!(
        u64::from_be_bytes(fixed(row.get(7)?)?) == position.0
            && fixed::<32>(row.get(8)?)? == position.1.to_byte_array()
            && row.get::<i64>(9)? == i64::from(position.2),
        "certified execution index differs"
    );
    let input = ExactInput::validate(decision.descriptor.clone(), row.get(2)?)?;
    let original_length = usize::try_from(row.get::<i64>(3)?)?;
    let augmentation_length = row
        .get::<Option<i64>>(4)?
        .map(usize::try_from)
        .transpose()?;
    Ok((
        RetainedInput { decision, input },
        original_length,
        augmentation_length,
    ))
}

pub(crate) async fn load(conn: &Connection, height: u64) -> Result<AuthenticatedDecision> {
    let (retained, original_length, augmentation_length) = load_record(conn, height).await?;
    let authority = committee(conn, height).await?;
    let maximum = authority.maximum_proof_bytes()?;
    ensure!(
        original_length <= maximum && augmentation_length.is_none_or(|length| length <= maximum),
        "certificate exceeds committee size bound"
    );
    let row = conn
        .query(
            "SELECT original_proof, proof_augmentation FROM certified_decisions WHERE height = ?1",
            [height.to_be_bytes().to_vec()],
        )
        .await?
        .next()
        .await?
        .context("certified decision unavailable")?;
    if let Some(augmentation) = row.get::<Option<Vec<u8>>>(1)? {
        verify_certificate(&retained.decision, &augmentation, &authority)?;
    }
    AuthenticatedDecision::verify(retained.decision, retained.input, row.get(0)?, &authority)
}

pub(crate) async fn load_verified_input(conn: &Connection, height: u64) -> Result<RetainedInput> {
    let (retained, original_length, augmentation_length) = load_record(conn, height).await?;
    let authority = committee(conn, height).await?;
    proof_read::verify(conn, &retained.decision, &authority, original_length, false).await?;
    if let Some(length) = augmentation_length {
        proof_read::verify(conn, &retained.decision, &authority, length, true).await?;
    }
    Ok(retained)
}

pub(crate) async fn append(conn: &Connection, certified: &AuthenticatedDecision) -> Result<()> {
    durable_writer(conn).await?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let state = frontier(&tx).await?;
    let decision = certified.decision();
    ensure!(
        state.status == Status::Ready && state.context == Some(decision.descriptor.context),
        "certified decision context unavailable"
    );
    ensure!(
        committee(&tx, decision.height).await?.id()? == decision.committee,
        "certificate used another historical authority"
    );
    if decision.height <= state.authenticated_height {
        let existing = load(&tx, decision.height).await?;
        ensure!(
            existing.decision() == decision
                && existing.input() == certified.input()
                && existing.proof() == certified.proof(),
            "conflicting certified decision retry"
        );
    } else {
        ensure!(
            state.authenticated_height.checked_add(1) == Some(decision.height)
                && state.authenticated_id == Some(decision.predecessor),
            "certified decision gap or predecessor conflict"
        );
        ensure!(
            state.closed_height == state.authenticated_height,
            "previous decision closure unfinished"
        );
        tx.execute(
            "INSERT OR IGNORE INTO certified_inputs (body_digest, body) VALUES (?1, ?2)",
            params![
                decision.descriptor.body_digest.to_vec(),
                certified.input().body()
            ],
        )
        .await?;
        let body: Vec<u8> = tx
            .query(
                "SELECT body FROM certified_inputs WHERE body_digest = ?1",
                [decision.descriptor.body_digest.to_vec()],
            )
            .await?
            .next()
            .await?
            .context("missing retained input")?
            .get(0)?;
        ensure!(
            body == certified.input().body(),
            "retained input digest conflict"
        );
        let position = decision.descriptor.command.position();
        tx.execute("INSERT INTO certified_decisions (height, decision_id, record, body_digest, committee_id, original_proof, bitcoin_height, bitcoin_hash, is_block)
            VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)", params![decision.height.to_be_bytes().to_vec(), decision.id()?.to_vec(),
                decision.encode()?, decision.descriptor.body_digest.to_vec(), decision.committee.to_vec(), certified.proof(), position.0.to_be_bytes().to_vec(), position.1.to_byte_array().to_vec(), position.2]).await?;
        branch::record(&tx, decision).await?;
        tx.execute("UPDATE certified_history_state SET authenticated_height = ?1, authenticated_id = ?2 WHERE singleton = 1",
            params![decision.height.to_be_bytes().to_vec(), decision.id()?.to_vec()]).await?;
    }
    tx.commit().await?;
    Ok(())
}

pub(crate) async fn augment(conn: &Connection, certified: &AuthenticatedDecision) -> Result<()> {
    durable_writer(conn).await?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let decision = certified.decision();
    let original = load(&tx, decision.height).await?;
    ensure!(
        original.decision() == decision && original.input() == certified.input(),
        "proof augmentation changed decision"
    );
    if original.proof() != certified.proof() {
        tx.execute("UPDATE certified_decisions SET proof_augmentation = ?1 WHERE height = ?2 AND proof_augmentation IS NULL",
            params![certified.proof(), decision.height.to_be_bytes().to_vec()]).await?;
    }
    tx.commit().await?;
    Ok(())
}

#[cfg(test)]
mod tests;
