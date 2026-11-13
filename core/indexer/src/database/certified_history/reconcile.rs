use std::collections::{BTreeMap, HashMap, HashSet};

use anyhow::{Context, Result, ensure};
use bitcoin::hashes::Hash;
use bitcoin::{BlockHash, OutPoint, Transaction, Txid, Wtxid};
use libsql::{Connection, TransactionBehavior, Value, params, params::Params};

use super::{
    RetainedInput, branch, closure, durable_writer, fixed, frontier, load_verified_input, replay,
    replay_input, work,
};
use crate::database::queries::outpoint_owners;
use crate::protocol::canonical_application::DecisionExclusions;
use crate::protocol::canonical_codec::{Decoder, Encoder};
use crate::protocol::coordinator::application_closure::{ReconciliationPlan, WorkItem};
use crate::protocol::coordinator::certified_input::Command;
use crate::protocol::coordinator::certified_input::CommandKind;
use crate::protocol::coordinator::closure_work::WorkOrigin;
use crate::protocol::coordinator::replay_input::ReplayInput;
use crate::protocol::coordinator::v1::{FINALITY_WINDOW, deadline_for};
use crate::protocol::identity::domain_digest;

struct ProofIndex {
    id: [u8; 32],
    input: [u8; 32],
    command: Command,
    witnesses: HashSet<(Txid, Wtxid)>,
    spends: HashSet<(Txid, Wtxid, OutPoint)>,
    outpoint_witnesses: HashMap<OutPoint, HashSet<Wtxid>>,
}

impl ProofIndex {
    fn new(retained: RetainedInput) -> Result<Self> {
        let mut witnesses = HashSet::new();
        let mut spends = HashSet::new();
        let mut outpoint_witnesses = HashMap::new();
        for transaction in retained.input().transactions()? {
            let txid = transaction.compute_txid();
            let wtxid = transaction.compute_wtxid();
            witnesses.insert((txid, wtxid));
            for input in transaction.input {
                spends.insert((txid, wtxid, input.previous_output));
                outpoint_witnesses
                    .entry(input.previous_output)
                    .or_insert_with(HashSet::new)
                    .insert(wtxid);
            }
        }
        Ok(Self {
            id: retained.decision().id()?,
            input: retained.input().descriptor().id()?,
            command: retained.decision().descriptor.command.clone(),
            witnesses,
            spends,
            outpoint_witnesses,
        })
    }
}

async fn proof_index<'a>(
    conn: &Connection,
    cache: &'a mut HashMap<u64, ProofIndex>,
    decision: u64,
) -> Result<&'a ProofIndex> {
    if let std::collections::hash_map::Entry::Vacant(entry) = cache.entry(decision) {
        entry.insert(ProofIndex::new(load_verified_input(conn, decision).await?)?);
    }
    Ok(cache.get(&decision).expect("indexed certified input"))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ConflictSeed {
    pub(crate) a_decision: u64,
    pub(crate) a_id: [u8; 32],
    pub(crate) a_input: [u8; 32],
    pub(crate) a_txid: Txid,
    pub(crate) a_wtxid: Wtxid,
    pub(crate) a_anchor: u64,
    pub(crate) b_decision: u64,
    pub(crate) b_id: [u8; 32],
    pub(crate) b_input: [u8; 32],
    pub(crate) b_hash: BlockHash,
    pub(crate) b_height: u64,
    pub(crate) outpoint: OutPoint,
}

impl ConflictSeed {
    fn encode(self) -> Result<Vec<u8>> {
        ensure!(
            self.a_decision < self.b_decision && self.a_anchor <= self.b_height,
            "invalid conflict seed position"
        );
        let mut out = Encoder::default();
        out.fixed(b"KCF1")?;
        out.u64(self.a_decision)?;
        out.fixed(&self.a_id)?;
        out.fixed(&self.a_input)?;
        out.fixed(&self.a_txid.to_byte_array())?;
        out.fixed(&self.a_wtxid.to_byte_array())?;
        out.u64(self.a_anchor)?;
        out.u64(self.b_decision)?;
        out.fixed(&self.b_id)?;
        out.fixed(&self.b_input)?;
        out.fixed(&self.b_hash.to_byte_array())?;
        out.u64(self.b_height)?;
        out.fixed(&self.outpoint.txid.to_byte_array())?;
        out.fixed(&self.outpoint.vout.to_be_bytes())?;
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Decoder::new(bytes);
        ensure!(
            input.fixed::<4>()? == *b"KCF1",
            "unknown conflict seed encoding"
        );
        let seed = Self {
            a_decision: input.u64()?,
            a_id: input.fixed()?,
            a_input: input.fixed()?,
            a_txid: Txid::from_byte_array(input.fixed()?),
            a_wtxid: Wtxid::from_byte_array(input.fixed()?),
            a_anchor: input.u64()?,
            b_decision: input.u64()?,
            b_id: input.fixed()?,
            b_input: input.fixed()?,
            b_hash: BlockHash::from_byte_array(input.fixed()?),
            b_height: input.u64()?,
            outpoint: OutPoint {
                txid: Txid::from_byte_array(input.fixed()?),
                vout: u32::from_be_bytes(input.fixed()?),
            },
        };
        input.finish()?;
        seed.encode()?;
        Ok(seed)
    }

    fn id(self) -> Result<[u8; 32]> {
        Ok(domain_digest(
            b"kontor/closure-conflict/v1",
            &self.encode()?,
        ))
    }

    fn verify_with(self, a: &ProofIndex, b: &ProofIndex) -> Result<()> {
        ensure!(
            a.id == self.a_id
                && a.input == self.a_input
                && b.id == self.b_id
                && b.input == self.b_input,
            "conflict seed certified input differs"
        );
        let Command::Batch { anchor_height, .. } = &a.command else {
            anyhow::bail!("conflict victim is not a batch");
        };
        let Command::Block { height, hash, .. } = &b.command else {
            anyhow::bail!("conflict proof is not a block");
        };
        ensure!(
            *anchor_height == self.a_anchor && *height == self.b_height && *hash == self.b_hash,
            "conflict seed anchor differs"
        );
        ensure!(
            a.spends
                .contains(&(self.a_txid, self.a_wtxid, self.outpoint)),
            "conflict victim witness or outpoint differs"
        );
        ensure!(
            b.outpoint_witnesses
                .get(&self.outpoint)
                .is_some_and(|wtxids| wtxids.iter().any(|wtxid| *wtxid != self.a_wtxid)),
            "conflict proof does not spend the victim outpoint"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct HealingSeed {
    a_decision: u64,
    a_id: [u8; 32],
    a_input: [u8; 32],
    a_txid: Txid,
    a_wtxid: Wtxid,
    a_anchor: u64,
    deadline: u64,
    b_decision: u64,
    b_id: [u8; 32],
    b_input: [u8; 32],
    b_hash: BlockHash,
    b_height: u64,
}

impl HealingSeed {
    fn encode(self) -> Result<Vec<u8>> {
        ensure!(
            self.a_decision < self.b_decision
                && self.a_anchor <= self.b_height
                && self.b_height <= self.deadline,
            "invalid healing seed position"
        );
        let mut out = Encoder::default();
        out.fixed(b"KHL1")?;
        out.u64(self.a_decision)?;
        out.fixed(&self.a_id)?;
        out.fixed(&self.a_input)?;
        out.fixed(&self.a_txid.to_byte_array())?;
        out.fixed(&self.a_wtxid.to_byte_array())?;
        out.u64(self.a_anchor)?;
        out.u64(self.deadline)?;
        out.u64(self.b_decision)?;
        out.fixed(&self.b_id)?;
        out.fixed(&self.b_input)?;
        out.fixed(&self.b_hash.to_byte_array())?;
        out.u64(self.b_height)?;
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Decoder::new(bytes);
        ensure!(
            input.fixed::<4>()? == *b"KHL1",
            "unknown healing seed encoding"
        );
        let seed = Self {
            a_decision: input.u64()?,
            a_id: input.fixed()?,
            a_input: input.fixed()?,
            a_txid: Txid::from_byte_array(input.fixed()?),
            a_wtxid: Wtxid::from_byte_array(input.fixed()?),
            a_anchor: input.u64()?,
            deadline: input.u64()?,
            b_decision: input.u64()?,
            b_id: input.fixed()?,
            b_input: input.fixed()?,
            b_hash: BlockHash::from_byte_array(input.fixed()?),
            b_height: input.u64()?,
        };
        input.finish()?;
        seed.encode()?;
        Ok(seed)
    }

    fn id(self) -> Result<[u8; 32]> {
        Ok(domain_digest(b"kontor/closure-healing/v1", &self.encode()?))
    }

    async fn verify_with(self, conn: &Connection, a: &ProofIndex, b: &ProofIndex) -> Result<()> {
        ensure!(
            a.id == self.a_id
                && a.input == self.a_input
                && b.id == self.b_id
                && b.input == self.b_input,
            "healing seed certified input differs"
        );
        let Command::Batch { anchor_height, .. } = &a.command else {
            anyhow::bail!("healing target is not a batch");
        };
        let Command::Block { height, hash, .. } = &b.command else {
            anyhow::bail!("healing proof is not a block");
        };
        ensure!(
            *anchor_height == self.a_anchor
                && *height == self.b_height
                && *hash == self.b_hash
                && self.deadline == deadline_for(*anchor_height),
            "healing seed anchor or deadline differs"
        );
        let row = conn
            .query(
                "SELECT deadline FROM excluded_batch_txids WHERE batch_height = ?1 AND txid = ?2",
                params![self.a_decision, self.a_txid.to_string()],
            )
            .await?
            .next()
            .await?
            .context("healing seed lacks deadline exclusion")?;
        ensure!(
            row.get::<u64>(0)? == self.deadline,
            "healing seed deadline differs from recorded exclusion"
        );
        ensure!(
            a.witnesses.contains(&(self.a_txid, self.a_wtxid))
                && b.witnesses.contains(&(self.a_txid, self.a_wtxid)),
            "healing seed lacks exact retained witness inclusion"
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ReconciliationSeed {
    Conflict(ConflictSeed),
    Healing(HealingSeed),
}

impl ReconciliationSeed {
    fn kind(self) -> i64 {
        match self {
            Self::Conflict(_) => 0,
            Self::Healing(_) => 1,
        }
    }

    fn encode(self) -> Result<Vec<u8>> {
        match self {
            Self::Conflict(seed) => seed.encode(),
            Self::Healing(seed) => seed.encode(),
        }
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        if bytes.starts_with(b"KCF1") {
            Ok(Self::Conflict(ConflictSeed::decode(bytes)?))
        } else if bytes.starts_with(b"KHL1") {
            Ok(Self::Healing(HealingSeed::decode(bytes)?))
        } else {
            anyhow::bail!("unknown reconciliation seed encoding")
        }
    }

    fn id(self) -> Result<[u8; 32]> {
        match self {
            Self::Conflict(seed) => seed.id(),
            Self::Healing(seed) => seed.id(),
        }
    }

    fn a_decision(self) -> u64 {
        match self {
            Self::Conflict(seed) => seed.a_decision,
            Self::Healing(seed) => seed.a_decision,
        }
    }

    fn a_txid(self) -> Txid {
        match self {
            Self::Conflict(seed) => seed.a_txid,
            Self::Healing(seed) => seed.a_txid,
        }
    }

    fn a_anchor(self) -> u64 {
        match self {
            Self::Conflict(seed) => seed.a_anchor,
            Self::Healing(seed) => seed.a_anchor,
        }
    }

    fn b_decision(self) -> u64 {
        match self {
            Self::Conflict(seed) => seed.b_decision,
            Self::Healing(seed) => seed.b_decision,
        }
    }

    fn b_height(self) -> u64 {
        match self {
            Self::Conflict(seed) => seed.b_height,
            Self::Healing(seed) => seed.b_height,
        }
    }

    fn b_id(self) -> [u8; 32] {
        match self {
            Self::Conflict(seed) => seed.b_id,
            Self::Healing(seed) => seed.b_id,
        }
    }

    fn b_hash(self) -> BlockHash {
        match self {
            Self::Conflict(seed) => seed.b_hash,
            Self::Healing(seed) => seed.b_hash,
        }
    }

    async fn verify_with(self, conn: &Connection, a: &ProofIndex, b: &ProofIndex) -> Result<()> {
        match self {
            Self::Conflict(seed) => seed.verify_with(a, b),
            Self::Healing(seed) => seed.verify_with(conn, a, b).await,
        }
    }
}

fn summary(
    seeds: &BTreeMap<[u8; 32], ReconciliationSeed>,
    from_height: u64,
) -> Result<ReconciliationPlan> {
    let mut digest = domain_digest(b"kontor/reconciliation-seeds/v1", &[]);
    for id in seeds.keys() {
        let mut out = Encoder::default();
        out.fixed(&digest)?;
        out.fixed(id)?;
        digest = domain_digest(b"kontor/reconciliation-seed/v1", &out.finish());
    }
    Ok(ReconciliationPlan {
        from_height,
        seed_count: u64::try_from(seeds.len())?,
        seed_digest: digest,
    })
}

pub(crate) async fn discover(
    conn: &Connection,
    decision: u64,
    replacement_rollback: Option<u64>,
    raw: &[Transaction],
) -> Result<Option<(ReconciliationPlan, BTreeMap<[u8; 32], ReconciliationSeed>)>> {
    let retained_b = load_verified_input(conn, decision).await?;
    let Command::Block { height, hash, .. } = retained_b.decision().descriptor.command else {
        return Ok(None);
    };
    ensure!(
        retained_b.input().transactions()? == raw,
        "reconciliation input differs from retained certified block"
    );
    let b = ProofIndex::new(retained_b)?;
    let mut a_cache = HashMap::new();
    let mut seeds = BTreeMap::new();
    let mut victims = HashSet::new();
    let owners = outpoint_owners(conn, raw).await?;
    for transaction in raw {
        let b_wtxid = transaction.compute_wtxid();
        for input in &transaction.input {
            let Some(owner) = owners.get(&input.previous_output) else {
                continue;
            };
            let Some(a_decision) = owner.batch_height else {
                continue;
            };
            if owner.wtxid == b_wtxid {
                continue;
            }
            if !victims.insert((a_decision, owner.txid)) {
                continue;
            }
            if replay::eligible(conn, decision, a_decision)
                .await?
                .is_none()
            {
                continue;
            }
            let a = proof_index(conn, &mut a_cache, a_decision).await?;
            let seed = ReconciliationSeed::Conflict(ConflictSeed {
                a_decision,
                a_id: a.id,
                a_input: a.input,
                a_txid: owner.txid,
                a_wtxid: owner.wtxid,
                a_anchor: owner.anchor_height,
                b_decision: decision,
                b_id: b.id,
                b_input: b.input,
                b_hash: hash,
                b_height: height,
                outpoint: input.previous_output,
            });
            seed.verify_with(conn, a, &b).await?;
            seeds.insert(seed.id()?, seed);
        }
    }

    let mut deadline_candidates: HashMap<Txid, Vec<(u64, u64)>> = HashMap::new();
    for chunk in raw.chunks(900) {
        let placeholders = vec!["?"; chunk.len()].join(", ");
        let sql = format!(
            "SELECT batch_height, txid, deadline FROM excluded_batch_txids WHERE txid IN ({placeholders}) AND deadline >= ?"
        );
        let mut values: Vec<Value> = chunk
            .iter()
            .map(|tx| Value::Text(tx.compute_txid().to_string()))
            .collect();
        values.push(Value::Integer(i64::try_from(height)?));
        let mut rows = conn.query(&sql, Params::Positional(values)).await?;
        while let Some(row) = rows.next().await? {
            deadline_candidates
                .entry(row.get::<String>(1)?.parse::<Txid>()?)
                .or_default()
                .push((row.get(0)?, row.get(2)?));
        }
    }
    for transaction in raw {
        let txid = transaction.compute_txid();
        for &(a_decision, deadline) in deadline_candidates.get(&txid).into_iter().flatten() {
            let Some(selected) = replay::eligible(conn, decision, a_decision).await? else {
                continue;
            };
            if selected.kind != CommandKind::Batch || selected.position.bitcoin_height > height {
                continue;
            }
            let a = proof_index(conn, &mut a_cache, a_decision).await?;
            if !a.witnesses.contains(&(txid, transaction.compute_wtxid())) {
                continue;
            }
            let seed = ReconciliationSeed::Healing(HealingSeed {
                a_decision,
                a_id: a.id,
                a_input: a.input,
                a_txid: txid,
                a_wtxid: transaction.compute_wtxid(),
                a_anchor: selected.position.bitcoin_height,
                deadline,
                b_decision: decision,
                b_id: b.id,
                b_input: b.input,
                b_hash: hash,
                b_height: height,
            });
            seed.verify_with(conn, a, &b).await?;
            seeds.insert(seed.id()?, seed);
        }
    }

    if replacement_rollback.is_some() {
        let floor = height.saturating_sub(FINALITY_WINDOW);
        let mut proof_cache = HashMap::new();
        let mut rows = conn.query(
            "SELECT seed_id, kind, a_anchor, b_height, record FROM closure_reconcile_reasons WHERE b_height >= ?1 AND a_anchor >= ?2 ORDER BY seed_id",
            params![height.to_be_bytes().to_vec(), floor.to_be_bytes().to_vec()],
        ).await?;
        while let Some(row) = rows.next().await? {
            let id = fixed::<32>(row.get(0)?)?;
            let seed = ReconciliationSeed::decode(&row.get::<Vec<u8>>(4)?)?;
            ensure!(
                seed.id()? == id
                    && seed.kind() == row.get::<i64>(1)?
                    && seed.a_anchor() == u64::from_be_bytes(fixed::<8>(row.get(2)?)?)
                    && seed.b_height() == u64::from_be_bytes(fixed::<8>(row.get(3)?)?),
                "retained reconciliation seed index differs"
            );
            if seed.a_anchor() > height || height > deadline_for(seed.a_anchor()) {
                continue;
            }
            if replay::eligible(conn, decision, seed.b_decision())
                .await?
                .is_some_and(|selected| {
                    selected.id == seed.b_id() && selected.hash == seed.b_hash()
                })
                || replay::eligible(conn, decision, seed.a_decision())
                    .await?
                    .is_none()
            {
                continue;
            }
            let active = conn
                .query(
                    "SELECT 1 FROM transactions WHERE txid = ?1 AND batch_height = ?2",
                    params![seed.a_txid().to_string(), seed.a_decision()],
                )
                .await?
                .next()
                .await?
                .is_some();
            if matches!(seed, ReconciliationSeed::Conflict(_)) && !active
                || matches!(seed, ReconciliationSeed::Healing(_)) && active
            {
                proof_index(conn, &mut proof_cache, seed.a_decision()).await?;
                proof_index(conn, &mut proof_cache, seed.b_decision()).await?;
                seed.verify_with(
                    conn,
                    proof_cache
                        .get(&seed.a_decision())
                        .context("indexed expired target")?,
                    proof_cache
                        .get(&seed.b_decision())
                        .context("indexed expired proof")?,
                )
                .await?;
                seeds.insert(id, seed);
            }
        }
    }

    if seeds.is_empty() {
        return Ok(None);
    }
    let earliest = seeds
        .values()
        .map(|seed| seed.a_anchor())
        .min()
        .context("missing conflict anchor")?;
    let from_height = replacement_rollback.map_or(earliest, |rollback| earliest.min(rollback + 1));
    Ok(Some((summary(&seeds, from_height)?, seeds)))
}

pub(crate) async fn persist(
    conn: &Connection,
    height: u64,
    seeds: &BTreeMap<[u8; 32], ReconciliationSeed>,
) -> Result<()> {
    for (&id, seed) in seeds {
        conn.execute(
            "INSERT OR IGNORE INTO closure_reconcile_reasons (seed_id, kind, a_decision, a_txid, a_anchor, b_decision, b_height, record) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
            params![id.to_vec(), seed.kind(), seed.a_decision().to_be_bytes().to_vec(), seed.a_txid().to_byte_array().to_vec(),
                seed.a_anchor().to_be_bytes().to_vec(), seed.b_decision().to_be_bytes().to_vec(),
                seed.b_height().to_be_bytes().to_vec(), seed.encode()?],
        ).await?;
        conn.execute(
            "INSERT OR IGNORE INTO closure_reconcile_seeds (height, seed_id) VALUES (?1, ?2)",
            params![height.to_be_bytes().to_vec(), id.to_vec()],
        )
        .await?;
    }
    Ok(())
}

pub(crate) async fn verify_plan(
    conn: &Connection,
    height: u64,
    expected: ReconciliationPlan,
) -> Result<Vec<ReconciliationSeed>> {
    let mut rows = conn.query(
        "SELECT s.seed_id, s.kind, s.a_decision, s.a_txid, s.a_anchor, s.b_decision, s.b_height, s.record FROM closure_reconcile_seeds p JOIN closure_reconcile_reasons s ON s.seed_id = p.seed_id WHERE p.height = ?1 ORDER BY s.seed_id",
        [height.to_be_bytes().to_vec()],
    ).await?;
    let mut seeds = BTreeMap::new();
    while let Some(row) = rows.next().await? {
        let id = fixed::<32>(row.get(0)?)?;
        let seed = ReconciliationSeed::decode(&row.get::<Vec<u8>>(7)?)?;
        ensure!(
            seed.id()? == id
                && seed.kind() == row.get::<i64>(1)?
                && seed.a_decision() == u64::from_be_bytes(fixed::<8>(row.get(2)?)?)
                && seed.a_txid().to_byte_array() == fixed::<32>(row.get(3)?)?
                && seed.a_anchor() == u64::from_be_bytes(fixed::<8>(row.get(4)?)?)
                && seed.b_decision() == u64::from_be_bytes(fixed::<8>(row.get(5)?)?)
                && seed.b_height() == u64::from_be_bytes(fixed::<8>(row.get(6)?)?),
            "reconciliation seed index differs"
        );
        seeds.insert(id, seed);
    }
    let mut proof_cache = HashMap::new();
    for seed in seeds.values().copied() {
        proof_index(conn, &mut proof_cache, seed.a_decision()).await?;
        proof_index(conn, &mut proof_cache, seed.b_decision()).await?;
        seed.verify_with(
            conn,
            proof_cache
                .get(&seed.a_decision())
                .context("indexed reconciliation target")?,
            proof_cache
                .get(&seed.b_decision())
                .context("indexed reconciliation proof")?,
        )
        .await?;
    }
    ensure!(
        summary(&seeds, expected.from_height)? == expected,
        "reconciliation seeds differ from closure plan"
    );
    Ok(seeds.into_values().collect())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ReconcileVerdict {
    origin: WorkOrigin,
    from_height: u64,
    seed_digest: [u8; 32],
    evidence_count: u64,
    evidence_digest: [u8; 32],
    work_count: u64,
    work_digest: [u8; 32],
}

impl ReconcileVerdict {
    fn encode(self) -> Result<Vec<u8>> {
        let mut out = Encoder::default();
        out.fixed(b"KRV2")?;
        out.bytes(&self.origin.encode()?)?;
        out.u64(self.from_height)?;
        out.fixed(&self.seed_digest)?;
        out.u64(self.evidence_count)?;
        out.fixed(&self.evidence_digest)?;
        out.u64(self.work_count)?;
        out.fixed(&self.work_digest)?;
        Ok(out.finish())
    }

    fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Decoder::new(bytes);
        ensure!(input.fixed::<4>()? == *b"KRV2", "unknown reconcile verdict");
        let verdict = Self {
            origin: WorkOrigin::decode(input.bytes()?)?,
            from_height: input.u64()?,
            seed_digest: input.fixed()?,
            evidence_count: input.u64()?,
            evidence_digest: input.fixed()?,
            work_count: input.u64()?,
            work_digest: input.fixed()?,
        };
        input.finish()?;
        verdict.encode()?;
        Ok(verdict)
    }

    fn id(self) -> Result<[u8; 32]> {
        Ok(domain_digest(
            b"kontor/reconcile-verdict/v2",
            &self.encode()?,
        ))
    }
}

fn evidence_start(origin: WorkOrigin) -> Result<[u8; 32]> {
    Ok(domain_digest(
        b"kontor/reconcile-evidence-start/v1",
        &origin.encode()?,
    ))
}

fn evidence_next(
    digest: [u8; 32],
    count: u64,
    txid: [u8; 32],
    wtxid: [u8; 32],
    height: u64,
    decision: u64,
    input_id: [u8; 32],
) -> Result<[u8; 32]> {
    let mut entry = Encoder::default();
    entry.fixed(&digest)?;
    entry.u64(count)?;
    entry.fixed(&txid)?;
    entry.fixed(&wtxid)?;
    entry.u64(height)?;
    entry.u64(decision)?;
    entry.fixed(&input_id)?;
    Ok(domain_digest(
        b"kontor/reconcile-evidence/v1",
        &entry.finish(),
    ))
}

async fn evidence_commitment(conn: &Connection, origin: WorkOrigin) -> Result<(u64, [u8; 32])> {
    let mut rows = conn.query(
        "SELECT txid, wtxid, bitcoin_height, decision, input_id FROM closure_reconcile_confirmed WHERE plan_key = ?1 ORDER BY decision, txid",
        [origin.key()?.to_vec()],
    ).await?;
    let mut count = 0u64;
    let mut digest = evidence_start(origin)?;
    let mut block: Option<(u64, u64, [u8; 32], HashSet<([u8; 32], [u8; 32])>)> = None;
    while let Some(row) = rows.next().await? {
        let txid = fixed::<32>(row.get(0)?)?;
        let wtxid = fixed::<32>(row.get(1)?)?;
        let height = u64::from_be_bytes(fixed::<8>(row.get(2)?)?);
        let decision = u64::from_be_bytes(fixed::<8>(row.get(3)?)?);
        let input_id = fixed::<32>(row.get(4)?)?;
        if block.as_ref().is_none_or(|current| current.0 != decision) {
            ensure!(
                block.as_ref().is_none_or(|previous| previous.3.is_empty()),
                "frozen inclusion omitted certified block transactions"
            );
            let selected = replay::eligible(conn, origin.height, decision)
                .await?
                .context("frozen inclusion is on a superseded interval")?;
            ensure!(
                selected.kind == CommandKind::Block && selected.position.bitcoin_height == height,
                "frozen inclusion block position differs"
            );
            let certified = load_verified_input(conn, decision).await?;
            ensure!(
                certified.decision().id()? == selected.id
                    && certified.input().descriptor().id()? == input_id,
                "frozen inclusion input differs"
            );
            let raw = certified
                .input()
                .transactions()?
                .iter()
                .map(|tx| {
                    (
                        tx.compute_txid().to_byte_array(),
                        tx.compute_wtxid().to_byte_array(),
                    )
                })
                .collect();
            block = Some((decision, height, input_id, raw));
        }
        let current = block
            .as_mut()
            .context("frozen inclusion block unavailable")?;
        ensure!(
            current.1 == height && current.2 == input_id && current.3.remove(&(txid, wtxid)),
            "frozen inclusion differs from certified raw block"
        );
        digest = evidence_next(digest, count, txid, wtxid, height, decision, input_id)?;
        count = count
            .checked_add(1)
            .context("reconciliation evidence count exhausted")?;
    }
    ensure!(
        block.as_ref().is_none_or(|last| last.3.is_empty()),
        "frozen inclusion omitted certified block transactions"
    );
    Ok((count, digest))
}

pub(super) async fn has_plan(conn: &Connection, origin: WorkOrigin) -> Result<bool> {
    Ok(conn
        .query(
            "SELECT 1 FROM closure_reconcile_plans WHERE plan_key = ?1",
            [origin.key()?.to_vec()],
        )
        .await?
        .next()
        .await?
        .is_some())
}

pub(super) async fn verify(conn: &Connection, origin: WorkOrigin, id: [u8; 32]) -> Result<()> {
    let row = conn
        .query(
            "SELECT record, evidence_count, evidence_digest FROM closure_reconcile_plans WHERE plan_key = ?1 AND phase = 3",
            [origin.key()?.to_vec()],
        )
        .await?
        .next()
        .await?
        .context("reconcile verdict is unavailable")?;
    let verdict = ReconcileVerdict::decode(&row.get::<Vec<u8>>(0)?)?;
    let progress = closure::progress(conn, origin.height).await?;
    let summary = progress
        .plan
        .reconciliation
        .context("closure lacks reconciliation summary")?;
    let draft = work::for_origin(conn, origin).await?;
    ensure!(
        verdict.id()? == id
            && verdict.origin == origin
            && verdict.from_height == summary.from_height
            && verdict.seed_digest == summary.seed_digest
            && verdict.work_count == draft.count
            && verdict.work_digest == draft.digest,
        "reconcile verdict differs from frozen plan or work"
    );
    ensure!(
        evidence_commitment(conn, origin).await?
            == (verdict.evidence_count, verdict.evidence_digest)
            && u64::from_be_bytes(fixed::<8>(row.get(1)?)?) == verdict.evidence_count
            && fixed::<32>(row.get(2)?)? == verdict.evidence_digest,
        "reconciliation inclusion evidence differs"
    );
    verify_plan(conn, origin.height, summary).await?;
    Ok(())
}

async fn prestate(conn: &Connection, origin: WorkOrigin) -> Result<ReconciliationPlan> {
    let progress = closure::progress(conn, origin.height).await?;
    ensure!(
        progress.work_origin()? == origin
            && progress
                .next
                .is_some_and(|next| next.0 == WorkItem::Reconcile)
            && closure::canonical_position(conn, progress.plan.context.chain).await?
                == origin.input,
        "reconciliation pre-state changed"
    );
    progress
        .plan
        .reconciliation
        .context("missing reconciliation summary")
}

fn position(
    row: &libsql::Row,
    height_column: i32,
    decision_column: i32,
) -> Result<Option<replay::ReplayPosition>> {
    let height = row.get::<Option<Vec<u8>>>(height_column)?;
    let decision = row.get::<Option<Vec<u8>>>(decision_column)?;
    match (height, decision) {
        (None, None) => Ok(None),
        (Some(height), Some(decision)) => Ok(Some(replay::ReplayPosition {
            bitcoin_height: u64::from_be_bytes(fixed(height)?),
            decision: u64::from_be_bytes(fixed(decision)?),
        })),
        _ => anyhow::bail!("reconciliation cursor is incomplete"),
    }
}

async fn scan_one(
    conn: &Connection,
    origin: WorkOrigin,
    from: u64,
    after: Option<replay::ReplayPosition>,
) -> Result<()> {
    let current = load_verified_input(conn, origin.height).await?;
    let Command::Block {
        height: current_height,
        ..
    } = current.decision().descriptor.command
    else {
        anyhow::bail!("reconciliation is not a block decision");
    };
    let selected = replay::page(conn, origin.height, from, after)
        .await?
        .into_iter()
        .next();
    let key = origin.key()?;
    let Some(selected) = selected else {
        anyhow::bail!("reconciliation evidence scan did not reach incoming block");
    };
    ensure!(
        (selected.position.bitcoin_height, selected.position.decision)
            <= (current_height, origin.height),
        "reconciliation evidence passed incoming block"
    );
    if selected.kind == CommandKind::Block {
        let input = load_verified_input(conn, selected.position.decision).await?;
        ensure!(
            input.decision().id()? == selected.id,
            "reconciliation selected block differs"
        );
        let input_id = input.input().descriptor().id()?;
        let expected = conn.query(
            "SELECT evidence_count, evidence_digest FROM closure_reconcile_plans WHERE plan_key = ?1",
            [key.to_vec()],
        ).await?.next().await?.context("reconciliation evidence cursor unavailable")?;
        let mut count = u64::from_be_bytes(fixed::<8>(expected.get(0)?)?);
        let mut digest = fixed::<32>(expected.get(1)?)?;
        let mut transactions = input.input().transactions()?;
        transactions.sort_by_key(|tx| tx.compute_txid().to_byte_array());
        for tx in transactions {
            let txid = tx.compute_txid().to_byte_array();
            let wtxid = tx.compute_wtxid().to_byte_array();
            conn.execute(
                "INSERT INTO closure_reconcile_confirmed (plan_key, txid, wtxid, bitcoin_height, decision, input_id) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                params![key.to_vec(), txid.to_vec(), wtxid.to_vec(),
                    selected.position.bitcoin_height.to_be_bytes().to_vec(), selected.position.decision.to_be_bytes().to_vec(), input_id.to_vec()],
            ).await?;
            digest = evidence_next(
                digest,
                count,
                txid,
                wtxid,
                selected.position.bitcoin_height,
                selected.position.decision,
                input_id,
            )?;
            count = count
                .checked_add(1)
                .context("reconciliation evidence count exhausted")?;
        }
        conn.execute(
            "UPDATE closure_reconcile_plans SET evidence_count = ?2, evidence_digest = ?3 WHERE plan_key = ?1",
            params![key.to_vec(), count.to_be_bytes().to_vec(), digest.to_vec()],
        ).await?;
    }
    conn.execute(
        "UPDATE closure_reconcile_plans SET scan_height = ?2, scan_decision = ?3, phase = ?4 WHERE plan_key = ?1",
        params![key.to_vec(), selected.position.bitcoin_height.to_be_bytes().to_vec(),
            selected.position.decision.to_be_bytes().to_vec(),
            if selected.position.bitcoin_height == current_height && selected.position.decision == origin.height { 1 } else { 0 }],
    ).await?;
    Ok(())
}

async fn initialize_replay(conn: &Connection, origin: WorkOrigin, from: u64) -> Result<()> {
    ensure!(from > 0, "reconciliation cannot roll back native genesis");
    let context = frontier(conn)
        .await?
        .context
        .context("missing reconciliation context")?;
    ensure!(
        from >= branch::boundary(conn, context).await?.first_height,
        "reconciliation rollback crosses baseline"
    );
    let draft = work::for_origin(conn, origin).await?;
    work::append(conn, draft, &[WorkItem::Rollback { height: from - 1 }]).await?;
    conn.execute(
        "UPDATE closure_reconcile_plans SET phase = 2 WHERE plan_key = ?1",
        [origin.key()?.to_vec()],
    )
    .await?;
    Ok(())
}

async fn capture_early_unavailable(
    conn: &Connection,
    origin: WorkOrigin,
    from: u64,
    after: Option<replay::ExclusionCursor>,
) -> Result<()> {
    let page = replay::exclusion_page(conn, origin.height, after.as_ref()).await?;
    let key = origin.key()?;
    for entry in page.entries {
        let selected = replay::eligible(conn, origin.height, entry.decision)
            .await?
            .context("early exclusion became ineligible")?;
        if selected.position.bitcoin_height < from {
            let txid = entry.txid.parse::<Txid>()?;
            conn.execute(
                "INSERT OR IGNORE INTO closure_reconcile_unavailable (plan_key, txid) VALUES (?1, ?2)",
                params![key.to_vec(), txid.to_byte_array().to_vec()],
            ).await?;
        }
    }
    if let Some(next) = page.next {
        conn.execute(
            "UPDATE closure_reconcile_plans SET exclusion_after_decision = ?2, exclusion_after_txid = ?3 WHERE plan_key = ?1",
            params![key.to_vec(), next.decision.to_be_bytes().to_vec(), next.txid],
        ).await?;
    } else {
        conn.execute(
            "UPDATE closure_reconcile_plans SET exclusion_done = 1 WHERE plan_key = ?1",
            [key.to_vec()],
        )
        .await?;
    }
    Ok(())
}

pub(super) async fn prior_active_conflict(
    conn: &Connection,
    verdict: u64,
    from: u64,
    txid: Txid,
) -> Result<bool> {
    let mut rows = conn.query(
        "SELECT seed_id, record FROM closure_reconcile_reasons WHERE kind = 0 AND a_txid = ?1 AND a_anchor < ?2",
        params![txid.to_byte_array().to_vec(), from.to_be_bytes().to_vec()],
    ).await?;
    let mut candidates = Vec::new();
    while let Some(row) = rows.next().await? {
        candidates.push((
            fixed::<32>(row.get(0)?)?,
            ConflictSeed::decode(&row.get::<Vec<u8>>(1)?)?,
        ));
    }
    for (id, seed) in candidates {
        ensure!(
            seed.id()? == id && seed.a_txid == txid && seed.a_anchor < from,
            "prior conflict index differs from seed"
        );
        if replay::eligible(conn, verdict, seed.a_decision)
            .await?
            .is_some_and(|selected| selected.id == seed.a_id)
            && replay::eligible(conn, verdict, seed.b_decision)
                .await?
                .is_some_and(|selected| selected.id == seed.b_id && selected.hash == seed.b_hash)
        {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn unavailable(conn: &Connection, origin: WorkOrigin, from: u64, txid: Txid) -> Result<bool> {
    if conn
        .query(
            "SELECT 1 FROM closure_reconcile_unavailable WHERE plan_key = ?1 AND txid = ?2",
            params![origin.key()?.to_vec(), txid.to_byte_array().to_vec()],
        )
        .await?
        .next()
        .await?
        .is_some()
    {
        return Ok(true);
    }
    prior_active_conflict(conn, origin.height, from, txid).await
}

pub(super) async fn active_conflicts(
    conn: &Connection,
    verdict: u64,
    a_decision: u64,
) -> Result<HashSet<Txid>> {
    let mut rows = conn
        .query(
            "SELECT record FROM closure_reconcile_reasons WHERE kind = 0 AND a_decision = ?1",
            [a_decision.to_be_bytes().to_vec()],
        )
        .await?;
    let mut candidates = Vec::new();
    while let Some(row) = rows.next().await? {
        candidates.push(ConflictSeed::decode(&row.get::<Vec<u8>>(0)?)?);
    }
    let mut active = HashSet::new();
    for seed in candidates {
        ensure!(
            seed.a_decision == a_decision,
            "conflict decision index differs from retained seed"
        );
        if replay::eligible(conn, verdict, seed.b_decision)
            .await?
            .is_some_and(|selected| selected.id == seed.b_id && selected.hash == seed.b_hash)
        {
            active.insert(seed.a_txid);
        }
    }
    Ok(active)
}

async fn exact_included_by_deadline(
    conn: &Connection,
    key: [u8; 32],
    tx: &Transaction,
    deadline: u64,
) -> Result<bool> {
    let mut rows = conn.query(
        "SELECT wtxid, bitcoin_height FROM closure_reconcile_confirmed WHERE plan_key = ?1 AND txid = ?2 ORDER BY bitcoin_height, decision",
        params![key.to_vec(), tx.compute_txid().to_byte_array().to_vec()],
    ).await?;
    while let Some(row) = rows.next().await? {
        if fixed::<32>(row.get(0)?)? == tx.compute_wtxid().to_byte_array()
            && u64::from_be_bytes(fixed::<8>(row.get(1)?)?) <= deadline
        {
            return Ok(true);
        }
    }
    Ok(false)
}

async fn direct_exclusions(
    conn: &Connection,
    origin: WorkOrigin,
    decision: u64,
    original: &[Transaction],
) -> Result<Vec<[u8; 32]>> {
    let mut direct = Vec::new();
    let by_txid: HashMap<Txid, &Transaction> = original
        .iter()
        .map(|transaction| (transaction.compute_txid(), transaction))
        .collect();
    ensure!(
        by_txid.len() == original.len(),
        "certified batch repeats a txid"
    );
    let active = active_conflicts(conn, origin.height, decision).await?;
    for txid in active {
        ensure!(
            by_txid.contains_key(&txid),
            "active conflict victim absent from certified batch"
        );
        direct.push(txid.to_byte_array());
    }
    let mut rows = conn
        .query(
            "SELECT txid, deadline FROM excluded_batch_txids WHERE batch_height = ?1 ORDER BY txid",
            [decision],
        )
        .await?;
    let mut deadlines = Vec::new();
    while let Some(row) = rows.next().await? {
        deadlines.push((row.get::<String>(0)?.parse::<Txid>()?, row.get::<u64>(1)?));
    }
    let key = origin.key()?;
    for (txid, deadline) in deadlines {
        let transaction = by_txid
            .get(&txid)
            .context("deadline exclusion absent from certified batch")?;
        if !exact_included_by_deadline(conn, key, transaction, deadline).await? {
            direct.push(txid.to_byte_array());
        }
    }
    direct.sort_unstable();
    direct.dedup();
    Ok(direct)
}

async fn build_one(
    conn: &Connection,
    origin: WorkOrigin,
    summary: ReconciliationPlan,
    after: Option<replay::ReplayPosition>,
) -> Result<()> {
    let selected = replay::page(conn, origin.height, summary.from_height, after)
        .await?
        .into_iter()
        .next();
    let Some(selected) = selected else {
        anyhow::bail!("reconciliation replay did not reach incoming block");
    };
    if selected.position.decision == origin.height {
        ensure!(
            selected.kind == CommandKind::Block,
            "reconciliation terminal decision is not a block"
        );
        return seal(conn, origin, summary).await;
    }
    let decision = selected.position.decision;
    let key = origin.key()?;
    let item = if selected.kind != CommandKind::Batch {
        WorkItem::Execute { decision }
    } else {
        let certified = load_verified_input(conn, decision).await?;
        let original = certified.input().transactions()?;
        let direct = direct_exclusions(conn, origin, decision, &original).await?;
        let mut dropped_positions = Vec::new();
        let mut kept = Vec::new();
        for (index, transaction) in original.iter().enumerate() {
            let txid = transaction.compute_txid();
            let mut drop = direct.binary_search(&txid.to_byte_array()).is_ok();
            for input in &transaction.input {
                if drop {
                    break;
                }
                drop = unavailable(
                    conn,
                    origin,
                    summary.from_height,
                    input.previous_output.txid,
                )
                .await?;
            }
            if drop {
                dropped_positions.push(index as u64);
                conn.execute(
                    "INSERT OR IGNORE INTO closure_reconcile_unavailable (plan_key, txid) VALUES (?1, ?2)",
                    params![key.to_vec(), txid.to_byte_array().to_vec()],
                ).await?;
            } else {
                kept.push(transaction.clone());
                conn.execute(
                    "DELETE FROM closure_reconcile_unavailable WHERE plan_key = ?1 AND txid = ?2",
                    params![key.to_vec(), txid.to_byte_array().to_vec()],
                )
                .await?;
            }
        }
        let exclusions = DecisionExclusions::for_batch(decision, &original, &kept, &direct)?;
        let input = ReplayInput {
            origin,
            decision: selected.id,
            interval_since: selected.interval_since,
            exclusions,
            dropped_positions,
        };
        WorkItem::Replay {
            decision,
            input: replay_input::insert(conn, &input, replay_input::PlanningCause::Reconcile)
                .await?,
        }
    };
    let mut items = vec![item];
    if selected.kind == CommandKind::Block {
        items.push(WorkItem::Activate { decision });
    }
    let draft = work::for_origin(conn, origin).await?;
    work::append(conn, draft, &items).await?;
    conn.execute(
        "UPDATE closure_reconcile_plans SET replay_height = ?2, replay_decision = ?3 WHERE plan_key = ?1",
        params![key.to_vec(), selected.position.bitcoin_height.to_be_bytes().to_vec(), decision.to_be_bytes().to_vec()],
    ).await?;
    Ok(())
}

async fn seal(conn: &Connection, origin: WorkOrigin, summary: ReconciliationPlan) -> Result<()> {
    let mut draft = work::for_origin(conn, origin).await?;
    draft = work::append(
        conn,
        draft,
        &[
            WorkItem::Execute {
                decision: origin.height,
            },
            WorkItem::Finality,
        ],
    )
    .await?;
    let (evidence_count, evidence_digest) = evidence_commitment(conn, origin).await?;
    let expected = conn.query(
        "SELECT evidence_count, evidence_digest, scan_height, scan_decision FROM closure_reconcile_plans WHERE plan_key = ?1",
        [origin.key()?.to_vec()],
    ).await?.next().await?.context("reconciliation evidence summary unavailable")?;
    let incoming = load_verified_input(conn, origin.height).await?;
    let Command::Block { height, .. } = incoming.decision().descriptor.command else {
        anyhow::bail!("reconciliation terminal input is not a block");
    };
    ensure!(
        u64::from_be_bytes(fixed::<8>(expected.get(0)?)?) == evidence_count
            && fixed::<32>(expected.get(1)?)? == evidence_digest
            && u64::from_be_bytes(fixed::<8>(expected.get(2)?)?) == height
            && u64::from_be_bytes(fixed::<8>(expected.get(3)?)?) == origin.height,
        "reconciliation scan omitted certified block evidence"
    );
    let verdict = ReconcileVerdict {
        origin,
        from_height: summary.from_height,
        seed_digest: summary.seed_digest,
        evidence_count,
        evidence_digest,
        work_count: draft.count,
        work_digest: draft.digest,
    };
    conn.execute(
        "UPDATE closure_reconcile_plans SET phase = 3, record = ?2 WHERE plan_key = ?1",
        params![origin.key()?.to_vec(), verdict.encode()?],
    )
    .await?;
    work::bind_verdict(conn, draft, verdict.id()?).await?;
    Ok(())
}

pub(crate) async fn step(conn: &Connection, height: u64) -> Result<bool> {
    durable_writer(conn).await?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .await?;
    let progress = closure::progress(&tx, height).await?;
    let origin = progress.work_origin()?;
    let summary = prestate(&tx, origin).await?;
    work::begin(&tx, origin).await?;
    let key = origin.key()?;
    tx.execute(
        "INSERT OR IGNORE INTO closure_reconcile_plans (plan_key, phase, evidence_count, evidence_digest) VALUES (?1, 0, ?2, ?3)",
        params![key.to_vec(), 0u64.to_be_bytes().to_vec(), evidence_start(origin)?.to_vec()],
    )
    .await?;
    let row = tx.query(
        "SELECT phase, scan_height, scan_decision, exclusion_done, exclusion_after_decision, exclusion_after_txid, replay_height, replay_decision FROM closure_reconcile_plans WHERE plan_key = ?1",
        [key.to_vec()],
    ).await?.next().await?.context("reconciliation plan disappeared")?;
    match row.get::<u64>(0)? {
        0 => scan_one(&tx, origin, summary.from_height, position(&row, 1, 2)?).await?,
        1 if row.get::<i64>(3)? == 0 => {
            let after = row
                .get::<Option<Vec<u8>>>(4)?
                .map(|bytes| -> Result<_> {
                    Ok(replay::ExclusionCursor {
                        decision: u64::from_be_bytes(fixed(bytes)?),
                        txid: row.get::<String>(5)?,
                    })
                })
                .transpose()?;
            capture_early_unavailable(&tx, origin, summary.from_height, after).await?;
        }
        1 => initialize_replay(&tx, origin, summary.from_height).await?,
        2 => build_one(&tx, origin, summary, position(&row, 6, 7)?).await?,
        3 => (),
        _ => anyhow::bail!("invalid reconciliation phase"),
    }
    let ready = work::for_origin(&tx, origin).await?.verdict.is_some();
    tx.commit().await?;
    Ok(ready)
}
