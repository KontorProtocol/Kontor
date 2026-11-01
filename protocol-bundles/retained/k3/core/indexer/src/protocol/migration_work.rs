use std::error::Error;
use std::fmt;

use super::canonical_codec::{CodecError, Decoder, Encoder};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct MigrationWork {
    pub(crate) computation_steps: u64,
    pub(crate) read_operations: u64,
    pub(crate) read_bytes: u64,
    pub(crate) write_operations: u64,
    pub(crate) write_bytes: u64,
}

impl MigrationWork {
    pub(crate) fn from_values(values: [u64; 5]) -> Self {
        Self {
            computation_steps: values[0],
            read_operations: values[1],
            read_bytes: values[2],
            write_operations: values[3],
            write_bytes: values[4],
        }
    }

    pub(crate) fn values(self) -> [u64; 5] {
        [
            self.computation_steps,
            self.read_operations,
            self.read_bytes,
            self.write_operations,
            self.write_bytes,
        ]
    }

    pub(crate) fn encode(self, output: &mut Encoder) -> Result<(), CodecError> {
        for value in self.values() {
            output.u64(value)?;
        }
        Ok(())
    }

    pub(crate) fn decode(input: &mut Decoder<'_>) -> Result<Self, CodecError> {
        Ok(Self {
            computation_steps: input.u64()?,
            read_operations: input.u64()?,
            read_bytes: input.u64()?,
            write_operations: input.u64()?,
            write_bytes: input.u64()?,
        })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MigrationBudgetExceeded;

impl fmt::Display for MigrationBudgetExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("migration work budget exhausted")
    }
}

impl Error for MigrationBudgetExceeded {}

// One meter belongs to the entire migration, outside nested storage savepoints.
pub(crate) struct MigrationMeter {
    limit: MigrationWork,
    used: MigrationWork,
    exhausted: bool,
}

impl MigrationMeter {
    pub(crate) fn new(limit: MigrationWork) -> Self {
        Self {
            limit,
            used: MigrationWork::default(),
            exhausted: false,
        }
    }

    pub(crate) fn charge(&mut self, work: MigrationWork) -> Result<(), MigrationBudgetExceeded> {
        if self.exhausted {
            return Err(MigrationBudgetExceeded);
        }
        let mut next = [0; 5];
        for (index, ((used, charge), limit)) in self
            .used
            .values()
            .into_iter()
            .zip(work.values())
            .zip(self.limit.values())
            .enumerate()
        {
            let Some(total) = used.checked_add(charge).filter(|value| *value <= limit) else {
                self.exhausted = true;
                return Err(MigrationBudgetExceeded);
            };
            next[index] = total;
        }
        self.used = MigrationWork {
            computation_steps: next[0],
            read_operations: next[1],
            read_bytes: next[2],
            write_operations: next[3],
            write_bytes: next[4],
        };
        Ok(())
    }

    pub(crate) fn finish(&self) -> Result<MigrationWork, MigrationBudgetExceeded> {
        if self.exhausted {
            Err(MigrationBudgetExceeded)
        } else {
            Ok(self.used)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{MigrationBudgetExceeded, MigrationMeter, MigrationWork};

    #[test]
    fn exact_limits_are_allowed_and_exhaustion_is_sticky() {
        let work = MigrationWork {
            computation_steps: 2,
            read_operations: 1,
            read_bytes: 3,
            write_operations: 1,
            write_bytes: 4,
        };
        let mut meter = MigrationMeter::new(work);
        meter.charge(work).unwrap();
        assert_eq!(meter.finish(), Ok(work));
        assert_eq!(
            meter.charge(MigrationWork {
                read_bytes: 1,
                ..MigrationWork::default()
            }),
            Err(MigrationBudgetExceeded)
        );
        assert_eq!(
            meter.charge(MigrationWork::default()),
            Err(MigrationBudgetExceeded)
        );
        assert_eq!(meter.finish(), Err(MigrationBudgetExceeded));
    }

    #[test]
    fn overflow_does_not_wrap_or_partially_charge() {
        let mut meter = MigrationMeter::new(MigrationWork {
            computation_steps: 10,
            write_bytes: u64::MAX,
            ..MigrationWork::default()
        });
        meter
            .charge(MigrationWork {
                write_bytes: u64::MAX,
                ..MigrationWork::default()
            })
            .unwrap();
        assert_eq!(
            meter.charge(MigrationWork {
                computation_steps: 1,
                write_bytes: 1,
                ..MigrationWork::default()
            }),
            Err(MigrationBudgetExceeded)
        );
        assert_eq!(meter.used.computation_steps, 0);
        assert_eq!(meter.used.write_bytes, u64::MAX);
    }

    #[test]
    fn every_work_dimension_is_independently_bounded() {
        for work in [
            MigrationWork {
                computation_steps: 1,
                ..MigrationWork::default()
            },
            MigrationWork {
                read_operations: 1,
                ..MigrationWork::default()
            },
            MigrationWork {
                read_bytes: 1,
                ..MigrationWork::default()
            },
            MigrationWork {
                write_operations: 1,
                ..MigrationWork::default()
            },
            MigrationWork {
                write_bytes: 1,
                ..MigrationWork::default()
            },
        ] {
            let mut meter = MigrationMeter::new(MigrationWork::default());
            meter.charge(MigrationWork::default()).unwrap();
            assert_eq!(meter.charge(work), Err(MigrationBudgetExceeded));
        }
    }
}
