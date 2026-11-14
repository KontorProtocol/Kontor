use anyhow::{Context, Result, ensure};
use libsql::Row;

use super::{ReconcileVerdict, position};
use crate::database::certified_history::{fixed, replay};

pub(super) enum Phase {
    ScanEvidence {
        after: Option<replay::ReplayPosition>,
    },
    CaptureUnavailable {
        after: Option<replay::ExclusionCursor>,
    },
    InitializeReplay,
    Build {
        after: Option<replay::ReplayPosition>,
    },
    Sealed(ReconcileVerdict),
}

impl Phase {
    pub(super) fn decode(row: &Row) -> Result<Self> {
        let scan = position(row, 1, 2)?;
        let replay = position(row, 6, 7)?;
        let decision = row.get::<Option<Vec<u8>>>(4)?;
        let txid = row.get::<Option<String>>(5)?;
        ensure!(
            decision.is_some() == txid.is_some(),
            "incomplete early exclusion cursor"
        );
        let after = decision
            .zip(txid)
            .map(|(decision, txid)| -> Result<_> {
                Ok(replay::ExclusionCursor {
                    decision: u64::from_be_bytes(fixed(decision)?),
                    txid,
                })
            })
            .transpose()?;
        let done = row.get::<u64>(3)?;
        ensure!(done <= 1, "invalid early exclusion completion");
        let record = row.get::<Option<Vec<u8>>>(8)?;
        let phase = row.get::<u64>(0)?;
        ensure!(
            (phase == 3) == record.is_some(),
            "reconciliation phase and verdict differ"
        );
        Ok(match phase {
            0 => Self::ScanEvidence { after: scan },
            1 if done == 0 => Self::CaptureUnavailable { after },
            // The final capture page retains its cursor when it commits done=1.
            1 => Self::InitializeReplay,
            2 => Self::Build { after: replay },
            3 => Self::Sealed(ReconcileVerdict::decode(
                &record.context("reconciliation verdict unavailable")?,
            )?),
            _ => anyhow::bail!("invalid reconciliation phase"),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsql::{Builder, Value};

    async fn decode(values: Vec<Value>) -> Result<Phase> {
        let db = Builder::new_local(":memory:").build().await?;
        let conn = db.connect()?;
        let row = conn
            .query("SELECT ?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9", values)
            .await?
            .next()
            .await?
            .unwrap();
        Phase::decode(&row)
    }

    #[tokio::test]
    async fn capture_completion_is_a_distinct_restart_state() -> Result<()> {
        let mut row = vec![
            Value::Integer(0),
            Value::Null,
            Value::Null,
            Value::Integer(0),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
        ];
        assert!(matches!(
            decode(row.clone()).await?,
            Phase::ScanEvidence { after: None }
        ));
        row[1] = Value::Blob(4u64.to_be_bytes().to_vec());
        assert!(decode(row.clone()).await.is_err());
        row[2] = Value::Blob(7u64.to_be_bytes().to_vec());
        assert!(matches!(
            decode(row.clone()).await?,
            Phase::ScanEvidence { after: Some(_) }
        ));
        row[0] = Value::Integer(1);
        row[4] = Value::Blob(3u64.to_be_bytes().to_vec());
        assert!(decode(row.clone()).await.is_err());
        row[5] = Value::Text("retained exclusion cursor".into());
        assert!(matches!(
            decode(row.clone()).await?,
            Phase::CaptureUnavailable { after: Some(_) }
        ));
        row[3] = Value::Integer(1);
        assert!(matches!(
            decode(row.clone()).await?,
            Phase::InitializeReplay
        ));
        row[0] = Value::Integer(2);
        assert!(matches!(
            decode(row.clone()).await?,
            Phase::Build { after: None }
        ));
        row[6] = Value::Blob(4u64.to_be_bytes().to_vec());
        assert!(decode(row.clone()).await.is_err());
        row[7] = Value::Blob(7u64.to_be_bytes().to_vec());
        assert!(matches!(
            decode(row.clone()).await?,
            Phase::Build { after: Some(_) }
        ));
        row[3] = Value::Integer(2);
        assert!(decode(row.clone()).await.is_err());
        row[3] = Value::Integer(1);
        row[0] = Value::Integer(3);
        assert!(decode(row.clone()).await.is_err());
        row[8] = Value::Blob(vec![0]);
        assert!(decode(row).await.is_err());
        Ok(())
    }
}
