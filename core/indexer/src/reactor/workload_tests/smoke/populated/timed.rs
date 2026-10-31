use std::ops::Range;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};

use super::super::ANCHOR_HEIGHT;

mod archive;
mod dispatch;
mod run;
mod tests;
mod work;

const BLOCK_SECONDS: u64 = 600;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum Profile {
    Representative,
    Stress,
}

impl Profile {
    pub(super) fn fresh_transactions(self) -> usize {
        match self {
            Self::Representative => 50,
            Self::Stress => 500,
        }
    }

    fn batch_seconds(self) -> u64 {
        match self {
            Self::Representative => 30,
            Self::Stress => 15,
        }
    }

    fn batch_transactions(self) -> usize {
        match self {
            Self::Representative => 10,
            Self::Stress => 20,
        }
    }

    fn simulation_seconds(self) -> u64 {
        match self {
            Self::Representative => 10,
            Self::Stress => 1,
        }
    }

    pub(super) fn simulation_operations(self) -> usize {
        match self {
            Self::Representative => 2,
            Self::Stress => 4,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Spec {
    pub(super) profile: Profile,
    pub(super) fresh_backlog: usize,
    pub(super) intervals: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Block {
    pub(super) height: u64,
    pub(super) confirmations: Range<usize>,
    pub(super) fresh: Range<usize>,
}

impl Block {
    pub(super) fn transactions(&self) -> Range<usize> {
        self.confirmations.start..self.fresh.end
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Action {
    Block {
        block: usize,
    },
    Batch {
        block: usize,
        anchor_height: u64,
        transactions: Range<usize>,
    },
    Simulation {
        request: usize,
        anchor_height: u64,
        operations: usize,
    },
}

impl Action {
    fn priority(&self) -> u8 {
        match self {
            Self::Block { .. } => 0,
            Self::Batch { .. } => 1,
            Self::Simulation { .. } => 2,
        }
    }

    pub(super) fn canonical(&self) -> bool {
        !matches!(self, Self::Simulation { .. })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Event {
    pub(super) ordinal: usize,
    pub(super) at_seconds: u64,
    pub(super) depends_on: Option<usize>,
    pub(super) action: Action,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Schedule {
    schema_version: u8,
    pub(super) spec: Spec,
    pub(super) horizon_seconds: u64,
    pub(super) blocks: Vec<Block>,
    pub(super) events: Vec<Event>,
}

impl Schedule {
    pub(super) fn new(spec: Spec) -> Result<Self> {
        ensure!(matches!(spec.fresh_backlog, 0 | 6));
        ensure!((1..=100).contains(&spec.intervals));
        let horizon_seconds = u64::try_from(spec.intervals)? * BLOCK_SECONDS;
        let mut blocks = Vec::new();
        let mut events = Vec::new();
        let mut offset = 0;
        let mut request = 0;
        let mut append = |at_seconds, action| {
            events.push(Event {
                ordinal: 0,
                at_seconds,
                depends_on: None,
                action,
            });
        };
        for block in 0..spec.fresh_backlog {
            let end = offset + spec.profile.fresh_transactions();
            blocks.push(Block {
                height: ANCHOR_HEIGHT + u64::try_from(block)? + 1,
                confirmations: offset..offset,
                fresh: offset..end,
            });
            append(0, Action::Block { block });
            offset = end;
        }
        for interval in 0..spec.intervals {
            let block = blocks.len();
            let anchor_height = ANCHOR_HEIGHT + u64::try_from(block)?;
            let start_second = u64::try_from(interval)? * BLOCK_SECONDS;
            let batch_count = usize::try_from(BLOCK_SECONDS / spec.profile.batch_seconds())?;
            let batch_transactions = spec.profile.batch_transactions();
            let fresh_start = offset + batch_count * batch_transactions;
            let end = fresh_start + spec.profile.fresh_transactions();
            blocks.push(Block {
                height: anchor_height + 1,
                confirmations: offset..fresh_start,
                fresh: fresh_start..end,
            });
            for batch in 0..batch_count {
                let first = offset + batch * batch_transactions;
                append(
                    start_second + u64::try_from(batch)? * spec.profile.batch_seconds(),
                    Action::Batch {
                        block,
                        anchor_height,
                        transactions: first..first + batch_transactions,
                    },
                );
            }
            for second in (0..BLOCK_SECONDS).step_by(spec.profile.simulation_seconds() as usize) {
                append(
                    start_second + second,
                    Action::Simulation {
                        request,
                        anchor_height,
                        operations: spec.profile.simulation_operations(),
                    },
                );
                request += 1;
            }
            append(start_second + BLOCK_SECONDS, Action::Block { block });
            offset = end;
        }
        ensure!(
            offset <= 20_000,
            "schedule exceeds bounded initial funding capacity"
        );
        // Stable sorting keeps simultaneous backlog blocks in height order.
        events.sort_by_key(|event| (event.at_seconds, event.action.priority()));
        let mut previous = None;
        for (ordinal, event) in events.iter_mut().enumerate() {
            event.ordinal = ordinal;
            event.depends_on = previous;
            if event.action.canonical() {
                previous = Some(ordinal);
            }
        }
        Ok(Self {
            schema_version: 1,
            spec,
            horizon_seconds,
            blocks,
            events,
        })
    }

    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            *self == Self::new(self.spec)?,
            "event schedule differs from declared workload"
        );
        Ok(())
    }

    pub(super) fn funding_counts(&self) -> Result<Vec<usize>> {
        self.validate()?;
        Ok(self
            .blocks
            .iter()
            .map(|block| block.transactions().len())
            .collect())
    }

    pub(super) fn required_before(&self, elapsed: Duration) -> Result<usize> {
        self.validate()?;
        self.required_before_validated(elapsed)
    }

    fn required_before_validated(&self, elapsed: Duration) -> Result<usize> {
        ensure!(
            elapsed <= Duration::from_secs(self.horizon_seconds),
            "workload event horizon exhausted"
        );
        Ok(self
            .events
            .partition_point(|event| Duration::from_secs(event.at_seconds) < elapsed))
    }

    pub(super) fn event(&self, ordinal: usize) -> Result<&Event> {
        self.events
            .get(ordinal)
            .context("workload event horizon exhausted")
    }
}
