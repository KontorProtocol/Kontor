use std::collections::HashMap;

use super::storage_error::ReadError;
use super::storage_state::LiveRow;
use crate::protocol::storage_footprint::FootprintCallbacks;

pub struct FootprintCache {
    callbacks: FootprintCallbacks,
}

impl FootprintCache {
    pub(crate) fn new(callbacks: FootprintCallbacks) -> Self {
        Self { callbacks }
    }

    pub async fn total_gas(&self, depositor: u64) -> Result<u64, ReadError> {
        let total = self.callbacks.0(depositor)
            .await
            .map_err(ReadError::Infrastructure)?;
        match total {
            Some(total) if total < 0 => Err(ReadError::Infrastructure(format!(
                "Invalid data: depositor_footprint corrupt: negative total_gas {total} for depositor {depositor}"
            ))),
            Some(total) => Ok(total as u64),
            None => Ok(0),
        }
    }

    pub async fn on_set(
        &self,
        contract_id: u64,
        path: &[u8],
        new_depositor: Option<u64>,
        new_gas: Option<u64>,
    ) -> Result<(), ReadError> {
        if let Some((depositor, gas)) = self.callbacks.1(contract_id, path.to_vec())
            .await
            .map_err(ReadError::Infrastructure)?
        {
            self.callbacks.2(depositor, -(gas as i64))
                .await
                .map_err(ReadError::Infrastructure)?;
        }
        if let (Some(depositor), Some(gas)) = (new_depositor, new_gas) {
            self.callbacks.2(depositor, gas as i64)
                .await
                .map_err(ReadError::Infrastructure)?;
        }
        Ok(())
    }

    pub async fn on_free(&self, rows: &[LiveRow]) -> Result<(), ReadError> {
        let mut deltas: HashMap<u64, i64> = HashMap::new();
        for row in rows {
            if let (Some(depositor), Some(gas)) = (row.depositor, row.deposited_gas) {
                *deltas.entry(depositor).or_default() -= gas as i64;
            }
        }
        for (depositor, delta) in deltas {
            self.callbacks.2(depositor, delta)
                .await
                .map_err(ReadError::Infrastructure)?;
        }
        Ok(())
    }

    pub async fn reconstruct(&self) -> Result<(), ReadError> {
        if self.callbacks.5()
            .await
            .map_err(ReadError::Infrastructure)?
            == 1
        {
            return Ok(());
        }
        self.callbacks.6()
            .await
            .map_err(ReadError::Infrastructure)?;
        self.callbacks.7()
            .await
            .map_err(ReadError::Infrastructure)?;
        Ok(())
    }

    pub(crate) async fn recompute(&self, depositors: &[u64]) -> Result<(), ReadError> {
        for &depositor in depositors {
            let total = self.callbacks.3(depositor)
                .await
                .map_err(ReadError::Infrastructure)?;
            self.callbacks.4(depositor, (total != 0).then_some(total))
                .await
                .map_err(ReadError::Infrastructure)?;
        }
        Ok(())
    }
}
