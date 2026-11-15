use anyhow::{Context, Result, ensure};
use libsql::Row;

use super::Verdict;
use crate::database::certified_history::{fixed, replay};

pub(super) enum Phase {
    Probe {
        after: i64,
        from: Option<u64>,
    },
    Capture {
        from: u64,
        after: Option<replay::ExclusionCursor>,
    },
    Build {
        from: u64,
        after: Option<replay::ReplayPosition>,
    },
    Sealed(Verdict),
}

impl Phase {
    pub(super) fn decode(row: &Row) -> Result<Self> {
        let from = row
            .get::<Option<Vec<u8>>>(6)?
            .map(|bytes| fixed(bytes).map(u64::from_be_bytes))
            .transpose()?;
        let seed_decision = row.get::<Option<Vec<u8>>>(2)?;
        let seed_txid = row.get::<Option<String>>(3)?;
        ensure!(
            seed_decision.is_some() == seed_txid.is_some(),
            "incomplete exclusion cursor"
        );
        let seed = seed_decision
            .zip(seed_txid)
            .map(|(decision, txid)| -> Result<_> {
                Ok(replay::ExclusionCursor {
                    decision: u64::from_be_bytes(fixed(decision)?),
                    txid,
                })
            })
            .transpose()?;
        let replay_height = row.get::<Option<Vec<u8>>>(4)?;
        let replay_decision = row.get::<Option<Vec<u8>>>(5)?;
        ensure!(
            replay_height.is_some() == replay_decision.is_some(),
            "incomplete replay cursor"
        );
        let replay = replay_height
            .zip(replay_decision)
            .map(|(height, decision)| -> Result<_> {
                Ok(replay::ReplayPosition {
                    bitcoin_height: u64::from_be_bytes(fixed(height)?),
                    decision: u64::from_be_bytes(fixed(decision)?),
                })
            })
            .transpose()?;
        let record = row.get::<Option<Vec<u8>>>(7)?;
        let phase = row.get::<u64>(0)?;
        ensure!(
            (phase == 3) == record.is_some(),
            "finality phase and verdict differ"
        );
        Ok(match phase {
            0 => {
                let after = row.get(1)?;
                ensure!(after >= 0, "negative finality probe cursor");
                Self::Probe { after, from }
            }
            1 => Self::Capture {
                from: from.context("exclusion scan lacks rollback anchor")?,
                after: seed,
            },
            2 => Self::Build {
                from: from.context("replay lacks rollback anchor")?,
                after: replay,
            },
            3 => Self::Sealed(Verdict::decode(
                &record.context("finality verdict unavailable")?,
            )?),
            _ => anyhow::bail!("invalid finality plan phase"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::protocol::coordinator::application_closure::CanonicalPosition;
    use crate::protocol::coordinator::closure_work::WorkOrigin;
    use libsql::{Builder, Value};

    async fn decode(values: Vec<Value>) -> Result<Phase> {
        let db = Builder::new_local(":memory:").build().await?;
        let conn = db.connect()?;
        let row = conn
            .query("SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8", values)
            .await?
            .next()
            .await?
            .unwrap();
        Phase::decode(&row)
    }

    #[tokio::test]
    async fn phase_rows_preserve_cursors_and_require_rollback_anchors() -> Result<()> {
        let mut row = vec![
            Value::Integer(0),
            Value::Integer(42),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
        ];
        assert!(matches!(
            decode(row.clone()).await?,
            Phase::Probe {
                after: 42,
                from: None
            }
        ));
        row[0] = Value::Integer(1);
        assert!(decode(row.clone()).await.is_err());
        row[6] = Value::Blob(7u64.to_be_bytes().to_vec());
        row[2] = Value::Blob(8u64.to_be_bytes().to_vec());
        assert!(decode(row.clone()).await.is_err());
        row[3] = Value::Text("old cursor".into());
        assert!(matches!(
            decode(row.clone()).await?,
            Phase::Capture {
                from: 7,
                after: Some(_)
            }
        ));
        row[0] = Value::Integer(2);
        assert!(matches!(
            decode(row.clone()).await?,
            Phase::Build {
                from: 7,
                after: None
            }
        ));
        row[4] = Value::Blob(9u64.to_be_bytes().to_vec());
        assert!(decode(row.clone()).await.is_err());
        row[5] = Value::Blob(10u64.to_be_bytes().to_vec());
        assert!(matches!(
            decode(row.clone()).await?,
            Phase::Build { after: Some(_), .. }
        ));
        row[0] = Value::Integer(3);
        assert!(decode(row.clone()).await.is_err());
        let verdict = Verdict {
            origin: WorkOrigin {
                height: 10,
                closure: [1; 32],
                previous: [2; 32],
                input: CanonicalPosition {
                    ordinal: 1,
                    lineage: [3; 32],
                    storage_height: 9,
                },
            },
            from: Some(7),
            seeds: 0,
            seed_digest: [4; 32],
        };
        row[7] = Value::Blob(verdict.encode()?);
        assert!(matches!(decode(row.clone()).await?, Phase::Sealed(_)));
        row[0] = Value::Integer(4);
        assert!(decode(row).await.is_err());
        Ok(())
    }
}
