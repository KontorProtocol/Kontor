use std::error::Error;
use std::fmt;

use super::storage_session;
use crate::protocol::migration_input::{INPUT_CHUNK_BYTES, InputCallbacks, InputRow};
use crate::protocol::migration_work::{MigrationMeter, MigrationWork};
use crate::protocol::storage_footprint::FootprintCallbacks;
use crate::protocol::storage_point::PointCallbacks;
use crate::protocol::storage_session::SessionCallbacks;
use crate::protocol::storage_state::WriteState;
use crate::runtime::Storage;
use crate::runtime::bundle_ownership::BundleOwner;
use crate::runtime::counter::Counter;
use crate::runtime::stack::Stack;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum MigrationFailure {
    Budget,
    Infrastructure(String),
    InvalidOperation(&'static str),
}

impl fmt::Display for MigrationFailure {
    fn fmt(&self, output: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Budget => output.write_str("migration work budget exhausted"),
            Self::Infrastructure(message) => output.write_str(message),
            Self::InvalidOperation(message) => output.write_str(message),
        }
    }
}

impl Error for MigrationFailure {}

type Result<T> = std::result::Result<T, MigrationFailure>;

pub(crate) struct InputEntry(InputRow);

impl InputEntry {
    pub(crate) fn deposit(&self) -> (Option<u64>, Option<u64>) {
        (self.0.3, self.0.4)
    }
}

// Compiled routines receive only this interface. In particular they cannot
// commit the canonical unit, spawn work, or obtain a Runtime/SQL connection.
pub(crate) struct MigrationContext {
    input: InputCallbacks,
    current: PointCallbacks,
    write: WriteState,
    footprint: FootprintCallbacks,
    session: SessionCallbacks,
    stack: Stack<u64>,
    counter: Counter,
    owner: BundleOwner,
    height: u64,
    depth: u64,
    meter: MigrationMeter,
    failure: Option<MigrationFailure>,
}

impl MigrationContext {
    pub(crate) async fn new(
        storage: &Storage,
        input: InputCallbacks,
        budget: MigrationWork,
        owner: BundleOwner,
    ) -> Result<Self> {
        if storage.savepoint_stack.peek().await != Some(0) {
            return Err(MigrationFailure::InvalidOperation(
                "migration requires its outer unit",
            ));
        }
        owner
            .ensure_commit_authorized()
            .map_err(|(_, message)| MigrationFailure::Infrastructure(message))?;
        Ok(Self {
            input,
            current: storage.host.point.clone(),
            write: storage.host.state.0.clone(),
            footprint: storage.host.footprint.clone(),
            session: storage.host.session.clone(),
            stack: storage.savepoint_stack.clone(),
            counter: storage.savepoint_counter.clone(),
            owner,
            height: storage.height,
            depth: 0,
            meter: MigrationMeter::new(budget),
            failure: None,
        })
    }

    fn fail<T>(&mut self, failure: MigrationFailure) -> Result<T> {
        Err(self.failure.get_or_insert(failure).clone())
    }

    fn host<T>(&mut self, result: std::result::Result<T, String>) -> Result<T> {
        match result {
            Ok(value) => Ok(value),
            Err(error) => self.fail(MigrationFailure::Infrastructure(error)),
        }
    }

    fn charge(&mut self, work: MigrationWork) -> Result<()> {
        if let Some(failure) = &self.failure {
            return Err(failure.clone());
        }
        if let Err((_, message)) = self.owner.ensure_commit_authorized() {
            return self.fail(MigrationFailure::Infrastructure(message));
        }
        if self.meter.charge(work).is_err() {
            return self.fail(MigrationFailure::Budget);
        }
        Ok(())
    }

    pub(crate) fn step(&mut self, count: u64) -> Result<()> {
        self.charge(MigrationWork {
            computation_steps: count,
            ..MigrationWork::default()
        })
    }

    pub(crate) async fn input_point(
        &mut self,
        contract: u64,
        key: &[u8],
    ) -> Result<Option<InputEntry>> {
        self.charge(MigrationWork {
            read_operations: 1,
            read_bytes: key.len() as u64,
            ..MigrationWork::default()
        })?;
        let result = self.input.0(contract, key.to_vec()).await;
        self.host(result).map(|row| row.map(InputEntry))
    }

    pub(crate) async fn input_next(
        &mut self,
        contract: u64,
        after: Option<&[u8]>,
    ) -> Result<Option<InputEntry>> {
        // Count every visited row and unsuccessful seek, even if the routine
        // chooses not to materialize the row or later rolls its writes back.
        self.charge(MigrationWork {
            read_operations: 1,
            read_bytes: after.map_or(0, |key| key.len() as u64),
            ..MigrationWork::default()
        })?;
        let result = self.input.1(contract, after.map(<[u8]>::to_vec)).await;
        self.host(result).map(|row| row.map(InputEntry))
    }

    pub(crate) async fn input_key(&mut self, entry: &InputEntry) -> Result<Vec<u8>> {
        self.input_bytes(entry, true).await
    }

    pub(crate) async fn input_value(&mut self, entry: &InputEntry) -> Result<Vec<u8>> {
        self.input_bytes(entry, false).await
    }

    async fn input_bytes(&mut self, entry: &InputEntry, key: bool) -> Result<Vec<u8>> {
        let size = if key { entry.0.1 } else { entry.0.2 };
        self.charge(MigrationWork {
            read_bytes: size,
            computation_steps: size.div_ceil(u64::from(INPUT_CHUNK_BYTES)).max(1),
            ..MigrationWork::default()
        })?;
        let Ok(capacity) = usize::try_from(size) else {
            return self.fail(MigrationFailure::Budget);
        };
        let mut bytes = Vec::new();
        if let Err(error) = bytes.try_reserve_exact(capacity) {
            return self.fail(MigrationFailure::Infrastructure(error.to_string()));
        }
        if size == 0 {
            let result = self.input.2(entry.0.0.clone(), key, 0, 0).await;
            let chunk = self.host(result)?;
            if !chunk.is_empty() {
                return self.fail(MigrationFailure::InvalidOperation(
                    "migration input length changed",
                ));
            }
        }
        while (bytes.len() as u64) < size {
            self.step(0)?;
            let offset = bytes.len() as u64;
            let length = (size - offset).min(u64::from(INPUT_CHUNK_BYTES)) as u32;
            let result = self.input.2(entry.0.0.clone(), key, offset, length).await;
            let chunk = self.host(result)?;
            if chunk.len() != length as usize {
                return self.fail(MigrationFailure::InvalidOperation(
                    "migration input length changed",
                ));
            }
            bytes.extend_from_slice(&chunk);
        }
        Ok(bytes)
    }

    pub(crate) async fn current_value(
        &mut self,
        contract: u64,
        key: &[u8],
    ) -> Result<Option<Vec<u8>>> {
        self.charge(MigrationWork {
            read_operations: 1,
            read_bytes: key.len() as u64,
            ..MigrationWork::default()
        })?;
        let result = self.current.0(contract, key.to_vec()).await;
        let Some((row, height)) = self.host(result)? else {
            return Ok(None);
        };
        let result = self.current.1(row).await;
        let (row, size) = self.host(result)?;
        self.charge(MigrationWork {
            read_bytes: size,
            ..MigrationWork::default()
        })?;
        let result = self.current.2(row, height, key.to_vec()).await;
        let value = self.host(result)?;
        if value.len() as u64 != size {
            return self.fail(MigrationFailure::InvalidOperation(
                "migration current value length changed",
            ));
        }
        Ok(Some(value))
    }

    pub(crate) async fn set(
        &mut self,
        contract: u64,
        key: &[u8],
        value: &[u8],
        deposit: (Option<u64>, Option<u64>),
    ) -> Result<()> {
        self.write_value(contract, key, value, false, deposit).await
    }

    pub(crate) async fn delete(&mut self, contract: u64, key: &[u8]) -> Result<()> {
        self.write_value(contract, key, &[], true, (None, None))
            .await
    }

    async fn write_value(
        &mut self,
        contract: u64,
        key: &[u8],
        value: &[u8],
        deleted: bool,
        deposit: (Option<u64>, Option<u64>),
    ) -> Result<()> {
        let Some(size) = (key.len() as u64).checked_add(value.len() as u64) else {
            return self.fail(MigrationFailure::Budget);
        };
        if deposit.0.is_some() != deposit.1.is_some()
            || deposit.0.is_some_and(|value| value > i64::MAX as u64)
            || deposit.1.is_some_and(|value| value > i64::MAX as u64)
        {
            return self.fail(MigrationFailure::InvalidOperation(
                "invalid migration deposit",
            ));
        }
        self.charge(MigrationWork {
            read_operations: 1,
            read_bytes: key.len() as u64,
            write_operations: 1,
            write_bytes: size,
            ..MigrationWork::default()
        })?;
        let result = self.footprint.1(contract, key.to_vec()).await;
        let displaced = self.host(result)?;
        if displaced
            .is_some_and(|(depositor, gas)| depositor > i64::MAX as u64 || gas > i64::MAX as u64)
        {
            return self.fail(MigrationFailure::InvalidOperation(
                "invalid stored migration deposit",
            ));
        }
        // Each footprint read/write accounts for its u64 key and i64 total.
        // Debit both possible updates before modifying either depositor's floor.
        let updates = u64::from(displaced.is_some()) + u64::from(deposit.0.is_some());
        self.charge(MigrationWork {
            read_operations: updates,
            read_bytes: updates * 16,
            write_operations: updates,
            write_bytes: updates * 16,
            ..MigrationWork::default()
        })?;
        if let Some((depositor, gas)) = displaced {
            self.update_floor(depositor, -(gas as i64)).await?;
        }
        if let (Some(depositor), Some(gas)) = deposit {
            self.update_floor(depositor, gas as i64).await?;
        }
        let result = (self.write)((
            (contract, self.height, None),
            value.len() as u64,
            key.to_vec(),
            value.to_vec(),
            deleted,
            deposit.0,
            deposit.1,
        ))
        .await;
        self.host(result)?;
        Ok(())
    }

    async fn update_floor(&mut self, depositor: u64, delta: i64) -> Result<()> {
        let result = self.footprint.0(depositor).await;
        let total = self.host(result)?.unwrap_or(0);
        let Some(next) = total
            .checked_add(delta)
            .filter(|next| total >= 0 && *next >= 0)
        else {
            return self.fail(MigrationFailure::InvalidOperation(
                "migration footprint overflow or underflow",
            ));
        };
        let result = self.footprint.4(depositor, (next != 0).then_some(next as u64)).await;
        self.host(result)
    }

    pub(crate) async fn begin_nested(&mut self) -> Result<()> {
        self.step(1)?;
        if self.counter.get().await == u64::MAX || self.depth == u64::MAX {
            return self.fail(MigrationFailure::Budget);
        }
        let result =
            storage_session::savepoint(self.session.clone(), &self.stack, &self.counter).await;
        self.host(result.map_err(|error| error.to_string()))?;
        self.depth += 1;
        Ok(())
    }

    pub(crate) async fn finish_nested(&mut self, keep: bool) -> Result<()> {
        self.step(1)?;
        let Some(index) = self.stack.peek().await.filter(|index| *index != 0) else {
            return self.fail(MigrationFailure::InvalidOperation(
                "migration cannot settle its outer unit",
            ));
        };
        if self.depth == 0 {
            return self.fail(MigrationFailure::InvalidOperation(
                "migration has no nested unit",
            ));
        }
        if !keep {
            let result = self.session.5(index).await;
            self.host(result)?;
        }
        let result = storage_session::commit(self.session.clone(), &self.stack).await;
        self.host(result.map_err(|error| error.to_string()))?;
        self.depth -= 1;
        Ok(())
    }

    pub(crate) fn finish(mut self) -> Result<MigrationWork> {
        self.step(0)?;
        if self.depth != 0 {
            return self.fail(MigrationFailure::InvalidOperation(
                "migration left a nested unit open",
            ));
        }
        self.meter.finish().map_err(|_| MigrationFailure::Budget)
    }
}
