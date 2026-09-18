use anyhow::{Result, anyhow};
use indexer_types::Payment;

use super::call::CallOutcome;
use super::wit::Signer;
use super::{ExecutionError, Runtime, token};
use crate::database::types::Identity;

impl Runtime {
    pub(super) async fn with_payment(
        &mut self,
        payment: &Payment,
        starting_fuel: u64,
        operation: impl AsyncFnOnce(&mut Self) -> Result<CallOutcome, ExecutionError>,
    ) -> Result<CallOutcome, ExecutionError> {
        // This boundary also encloses publication's rollback, so a failed init
        // cannot undo its fee. Infrastructure failures discard the entire scope.
        self.storage
            .savepoint()
            .await
            .map_err(ExecutionError::NonDeterministic)?;
        let result = async {
            let payer = Signer::Core(Box::new(Signer::Id(Identity::new(payment.signer_id))));
            let hold = self.pricing.gas_hold(payment.gas_limit)?;
            let reserved = Box::pin(token::api::hold(self, &payer, hold))
                .await
                .map_err(ExecutionError::NonDeterministic)?;
            if let Err(error) = reserved {
                return Ok(CallOutcome {
                    result: Err(ExecutionError::Deterministic(anyhow!(
                        "Payer {:?} does not have enough token to cover gas limit: {}",
                        payment.signer_id,
                        error
                    ))),
                    remaining_fuel: starting_fuel,
                });
            }
            self.deposit.reset().await;
            let outcome = operation(self).await?;
            if matches!(outcome.result, Err(ExecutionError::NonDeterministic(_))) {
                return Ok(outcome);
            }
            let gas = self
                .gas_consumed(starting_fuel, outcome.remaining_fuel)
                .max(1);
            let reserved_deposit = self.deposit.take().await;
            let burn = self
                .pricing
                .execution_fee(gas.saturating_sub(reserved_deposit))?;
            Box::pin(token::api::release(self, &payer, burn))
                .await
                .map_err(ExecutionError::NonDeterministic)?
                .map_err(|error| ExecutionError::NonDeterministic(anyhow!("{error:?}")))?;
            Ok(outcome)
        }
        .await;
        if result.as_ref().is_ok_and(|outcome| {
            !matches!(outcome.result, Err(ExecutionError::NonDeterministic(_)))
        }) {
            self.storage
                .commit()
                .await
                .map_err(ExecutionError::NonDeterministic)?;
        } else {
            self.deposit.reset().await;
            self.storage
                .rollback()
                .await
                .map_err(ExecutionError::NonDeterministic)?;
            // A publication may have succeeded before settlement failed. Its
            // id is now reusable, so compiled speculative state must go too.
            self.component_cache.clear();
        }
        result
    }
}
