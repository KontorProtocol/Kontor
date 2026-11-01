use anyhow::{Result, ensure};

use super::certified_input::EraContext;
use super::closure_work::WorkCursor;
use crate::protocol::canonical_application::CanonicalApplication;
use crate::protocol::canonical_codec::{Decoder, Encoder};
use crate::protocol::identity::domain_digest;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct CanonicalPosition {
    pub(crate) ordinal: u64,
    pub(crate) lineage: [u8; 32],
    pub(crate) storage_height: u64,
}

impl CanonicalPosition {
    pub(super) fn encode(self, output: &mut Encoder) -> Result<()> {
        output.u64(self.ordinal)?;
        output.fixed(&self.lineage)?;
        output.u64(self.storage_height)?;
        Ok(())
    }

    pub(super) fn decode(input: &mut Decoder<'_>) -> Result<Self> {
        Ok(Self {
            ordinal: input.u64()?,
            lineage: input.fixed()?,
            storage_height: input.u64()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkItem {
    Execute { decision: u64 },
    Replay { decision: u64, input: [u8; 32] },
    Rollback { height: u64 },
    Finality,
    Observe,
}

impl WorkItem {
    pub(super) fn encode(self, output: &mut Encoder) -> Result<()> {
        match self {
            Self::Execute { decision } => {
                output.tag(0)?;
                output.u64(decision)?;
            }
            Self::Rollback { height } => {
                output.tag(1)?;
                output.u64(height)?;
            }
            Self::Replay { decision, input } => {
                output.tag(4)?;
                output.u64(decision)?;
                output.fixed(&input)?;
            }
            Self::Finality => output.tag(2)?,
            Self::Observe => output.tag(3)?,
        }
        Ok(())
    }

    pub(super) fn decode(input: &mut Decoder<'_>) -> Result<Self> {
        Ok(match input.tag()? {
            0 => Self::Execute {
                decision: input.u64()?,
            },
            1 => Self::Rollback {
                height: input.u64()?,
            },
            2 => Self::Finality,
            3 => Self::Observe,
            4 => Self::Replay {
                decision: input.u64()?,
                input: input.fixed()?,
            },
            _ => anyhow::bail!("unknown closure work item"),
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ClosurePlan {
    pub(crate) context: EraContext,
    pub(crate) height: u64,
    pub(crate) decision: [u8; 32],
    pub(crate) previous_closure: [u8; 32],
    pub(crate) input: CanonicalPosition,
    pub(crate) replacement_rollback: Option<u64>,
}

impl ClosurePlan {
    pub(crate) fn initial_work(&self) -> Vec<WorkItem> {
        let mut work = Vec::new();
        if let Some(height) = self.replacement_rollback {
            work.push(WorkItem::Rollback { height });
        }
        work.push(WorkItem::Execute {
            decision: self.height,
        });
        work.push(WorkItem::Finality);
        work
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        ensure!(
            self.height > 0 && self.context.codec == 1,
            "invalid closure plan position"
        );
        let mut output = Encoder::default();
        output.fixed(b"KCP1")?;
        self.context.encode(&mut output)?;
        output.u64(self.height)?;
        output.fixed(&self.decision)?;
        output.fixed(&self.previous_closure)?;
        self.input.encode(&mut output)?;
        match self.replacement_rollback {
            None => output.tag(0)?,
            Some(height) => {
                ensure!(
                    height < self.input.storage_height,
                    "replacement rollback must remove a block"
                );
                output.tag(1)?;
                output.u64(height)?;
            }
        }
        Ok(output.finish())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Decoder::new(bytes);
        ensure!(
            input.fixed::<4>()? == *b"KCP1",
            "unknown closure plan encoding"
        );
        let plan = Self {
            context: EraContext::decode(&mut input)?,
            height: input.u64()?,
            decision: input.fixed()?,
            previous_closure: input.fixed()?,
            input: CanonicalPosition::decode(&mut input)?,
            replacement_rollback: match input.tag()? {
                0 => None,
                1 => Some(input.u64()?),
                _ => anyhow::bail!("invalid replacement rollback tag"),
            },
        };
        input.finish()?;
        plan.encode()?;
        Ok(plan)
    }

    pub(crate) fn id(&self) -> Result<[u8; 32]> {
        Ok(domain_digest(b"kontor/closure-plan/v1", &self.encode()?))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum StageOutcome {
    Applied,
    UnrecognizedBatch,
    ReplacedAnchorBatch,
    RolledBack,
    FinalityEvaluated,
    Observed,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct StageRecord {
    pub(crate) height: u64,
    pub(crate) stage: u64,
    pub(crate) plan: [u8; 32],
    pub(crate) previous: [u8; 32],
    pub(crate) action: WorkItem,
    pub(crate) input: CanonicalPosition,
    pub(crate) output: CanonicalPosition,
    pub(crate) outcome: StageOutcome,
    pub(crate) applications: Vec<CanonicalApplication>,
    pub(crate) observation: [u8; 32],
    pub(crate) remaining: WorkCursor,
}

impl StageRecord {
    pub(crate) fn validate(&self) -> Result<()> {
        ensure!(
            self.height > 0 && self.stage > 0,
            "invalid closure stage position"
        );
        ensure!(
            matches!(
                (self.action, self.outcome),
                (
                    WorkItem::Execute { .. } | WorkItem::Replay { .. },
                    StageOutcome::Applied
                        | StageOutcome::UnrecognizedBatch
                        | StageOutcome::ReplacedAnchorBatch
                ) | (WorkItem::Rollback { .. }, StageOutcome::RolledBack)
                    | (WorkItem::Finality, StageOutcome::FinalityEvaluated)
                    | (WorkItem::Observe, StageOutcome::Observed)
            ),
            "stage outcome does not match action"
        );
        if let WorkItem::Execute { decision } | WorkItem::Replay { decision, .. } = self.action {
            ensure!(
                decision > 0 && decision <= self.height,
                "closure work refers to future decision"
            );
        }
        ensure!(
            self.remaining.index <= self.remaining.count,
            "work cursor exceeds plan"
        );
        if self.outcome == StageOutcome::Applied {
            ensure!(
                !self.applications.is_empty(),
                "applied stage has no application records"
            );
            let mut position = self.input;
            for application in &self.applications {
                ensure!(
                    position.ordinal.checked_add(1) == Some(application.ordinal)
                        && position.lineage == application.parent_lineage
                        && application.storage_height >= position.storage_height
                        && application.input.is_none_or(|input| input.authentic()),
                    "stage application lineage is not contiguous and authentic"
                );
                position = CanonicalPosition {
                    ordinal: application.ordinal,
                    lineage: application.lineage()?,
                    storage_height: application.storage_height,
                };
            }
            ensure!(
                position == self.output,
                "stage output does not match application lineage"
            );
        } else {
            ensure!(
                self.applications.is_empty(),
                "non-application stage contains applications"
            );
            if let WorkItem::Rollback { height } = self.action {
                ensure!(
                    self.output.ordinal <= self.input.ordinal
                        && self.output.storage_height <= height
                        && self.output.storage_height <= self.input.storage_height,
                    "rollback advanced canonical state"
                );
                if self.input.ordinal == self.output.ordinal {
                    ensure!(self.input == self.output, "no-op rollback changed lineage");
                }
            } else {
                ensure!(
                    self.input == self.output,
                    "metadata stage changed canonical lineage"
                );
            }
        }
        Ok(())
    }

    pub(crate) fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut output = Encoder::default();
        output.fixed(b"KCS1")?;
        output.u64(self.height)?;
        output.u64(self.stage)?;
        output.fixed(&self.plan)?;
        output.fixed(&self.previous)?;
        self.action.encode(&mut output)?;
        self.input.encode(&mut output)?;
        self.output.encode(&mut output)?;
        output.tag(match self.outcome {
            StageOutcome::Applied => 0,
            StageOutcome::UnrecognizedBatch => 1,
            StageOutcome::RolledBack => 2,
            StageOutcome::FinalityEvaluated => 3,
            StageOutcome::Observed => 4,
            StageOutcome::ReplacedAnchorBatch => 5,
        })?;
        output.count(self.applications.len())?;
        for application in &self.applications {
            output.bytes(&application.encode()?)?;
        }
        output.fixed(&self.observation)?;
        self.remaining.encode(&mut output)?;
        Ok(output.finish())
    }

    pub(crate) fn decode(bytes: &[u8]) -> Result<Self> {
        let mut input = Decoder::new(bytes);
        ensure!(
            input.fixed::<4>()? == *b"KCS1",
            "unknown closure stage encoding"
        );
        let height = input.u64()?;
        let stage = input.u64()?;
        let plan = input.fixed()?;
        let previous = input.fixed()?;
        let action = WorkItem::decode(&mut input)?;
        let before = CanonicalPosition::decode(&mut input)?;
        let output = CanonicalPosition::decode(&mut input)?;
        let outcome = match input.tag()? {
            0 => StageOutcome::Applied,
            1 => StageOutcome::UnrecognizedBatch,
            2 => StageOutcome::RolledBack,
            3 => StageOutcome::FinalityEvaluated,
            4 => StageOutcome::Observed,
            5 => StageOutcome::ReplacedAnchorBatch,
            _ => anyhow::bail!("unknown closure stage outcome"),
        };
        let count = input.count(4)?;
        let mut applications = Vec::new();
        for _ in 0..count {
            applications.push(CanonicalApplication::decode(input.bytes()?)?);
        }
        let observation = input.fixed()?;
        let remaining = WorkCursor::decode(&mut input)?;
        input.finish()?;
        let record = Self {
            height,
            stage,
            plan,
            previous,
            action,
            input: before,
            output,
            outcome,
            applications,
            observation,
            remaining,
        };
        record.validate()?;
        Ok(record)
    }

    pub(crate) fn id(&self) -> Result<[u8; 32]> {
        Ok(domain_digest(b"kontor/closure-stage/v1", &self.encode()?))
    }
}
