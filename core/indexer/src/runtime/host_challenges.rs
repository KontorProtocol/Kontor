use anyhow::Result;
use wasmtime::component::Accessor;

use super::{Runtime, fuel::Fuel, wit::kontor::built_in};
use crate::database::queries::{append_challenge_status, get_challenges_by_prover};
use crate::database::types::{ChallengeStatus as DbChallengeStatus, ChallengeWithStatus};

use built_in::challenge_registry::Challenge;
use built_in::challenge_types::ChallengeStatus;

impl From<ChallengeStatus> for DbChallengeStatus {
    fn from(s: ChallengeStatus) -> Self {
        match s {
            ChallengeStatus::Active => DbChallengeStatus::Active,
            ChallengeStatus::Proven => DbChallengeStatus::Proven,
            ChallengeStatus::Expired => DbChallengeStatus::Expired,
            ChallengeStatus::Failed => DbChallengeStatus::Failed,
            ChallengeStatus::Invalid => DbChallengeStatus::Invalid,
        }
    }
}

impl From<DbChallengeStatus> for ChallengeStatus {
    fn from(s: DbChallengeStatus) -> Self {
        match s {
            DbChallengeStatus::Active => ChallengeStatus::Active,
            DbChallengeStatus::Proven => ChallengeStatus::Proven,
            DbChallengeStatus::Expired => ChallengeStatus::Expired,
            DbChallengeStatus::Failed => ChallengeStatus::Failed,
            DbChallengeStatus::Invalid => ChallengeStatus::Invalid,
        }
    }
}

impl From<ChallengeWithStatus> for Challenge {
    fn from(c: ChallengeWithStatus) -> Self {
        Challenge {
            challenge_id: c.challenge_id,
            prover_id: c.prover_id,
            agreement_id: c.agreement_id,
            num_challenges: c.num_challenges,
            seed: c.seed,
            deadline_height: c.deadline_height,
            height: c.height,
            status: c.status.into(),
        }
    }
}

impl Runtime {
    async fn _record_status<T>(
        &self,
        accessor: &Accessor<T, Self>,
        challenge_id: String,
        status: ChallengeStatus,
    ) -> Result<()> {
        Fuel::RecordStatus
            .consume(accessor, self.gauge.as_ref())
            .await?;
        // Height comes from the host context, not the caller — a contract can't
        // backdate a status transition (the row's height drives reorg cascade).
        append_challenge_status(
            &self.storage.conn,
            &challenge_id,
            status.into(),
            self.storage.height,
        )
        .await?;
        Ok(())
    }

    async fn _query_challenges<T>(
        &self,
        accessor: &Accessor<T, Self>,
        prover_id: u64,
        status: Option<ChallengeStatus>,
    ) -> Result<Vec<Challenge>> {
        Fuel::QueryChallenges
            .consume(accessor, self.gauge.as_ref())
            .await?;
        let rows =
            get_challenges_by_prover(&self.storage.conn, prover_id, status.map(Into::into)).await?;
        Ok(rows.into_iter().map(Challenge::from).collect())
    }
}

impl built_in::challenge_types::Host for Runtime {}

impl built_in::challenge_registry::Host for Runtime {}

impl built_in::challenge_registry::HostWithStore for Runtime {
    async fn record_status<T>(
        accessor: &Accessor<T, Self>,
        challenge_id: String,
        status: ChallengeStatus,
    ) -> Result<()> {
        accessor
            .with(|mut access| access.get().clone())
            ._record_status(accessor, challenge_id, status)
            .await
    }

    async fn query_challenges<T>(
        accessor: &Accessor<T, Self>,
        prover_id: u64,
        status: Option<ChallengeStatus>,
    ) -> Result<Vec<Challenge>> {
        accessor
            .with(|mut access| access.get().clone())
            ._query_challenges(accessor, prover_id, status)
            .await
    }
}
