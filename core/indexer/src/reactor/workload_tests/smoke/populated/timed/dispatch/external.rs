use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;
use tokio::sync::mpsc::unbounded_channel;

use super::super::super::clock::monotonic_ns;
use super::{Arrival, Arrivals, Clock, Schedule};

#[derive(Serialize)]
struct Offered {
    ordinal: usize,
    at_ns: u64,
}

#[derive(Serialize)]
struct Request<'a> {
    schema_version: u32,
    epoch_ns: u64,
    events: &'a [Offered],
}

#[derive(Deserialize)]
struct Emitted {
    ordinal: usize,
    enqueued_ns: u64,
}

pub(super) async fn connect(
    path: &str,
    schedule: Arc<Schedule>,
    api_only: bool,
) -> Result<Arrivals> {
    let offered = schedule
        .events
        .iter()
        .filter(|event| !api_only || !event.action.canonical())
        .map(|event| {
            Ok(Offered {
                ordinal: event.ordinal,
                at_ns: event
                    .at_seconds
                    .checked_mul(1_000_000_000)
                    .context("arrival deadline overflow")?,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    ensure!(!offered.is_empty());
    let mut stream = UnixStream::connect(path).await?;
    let epoch_ns = monotonic_ns()?;
    let mut request = serde_json::to_vec(&Request {
        schema_version: 1,
        epoch_ns,
        events: &offered,
    })?;
    request.push(b'\n');
    stream.write_all(&request).await?;
    let (sender, receiver) = unbounded_channel();
    let producer = tokio::spawn(async move {
        let mut reader = BufReader::new(stream);
        let mut previous = 0;
        for event in offered {
            let mut line = String::new();
            ensure!(
                reader.read_line(&mut line).await? > 0,
                "external arrival stream ended early"
            );
            let emitted: Emitted = serde_json::from_str(&line)?;
            let observed = monotonic_ns()?
                .checked_sub(epoch_ns)
                .context("arrival clock regressed")?;
            ensure!(
                emitted.ordinal == event.ordinal
                    && emitted.enqueued_ns >= event.at_ns
                    && emitted.enqueued_ns >= previous
                    && emitted.enqueued_ns <= observed,
                "external arrival ordinal or clock differs"
            );
            previous = emitted.enqueued_ns;
            sender
                .send(Arrival {
                    ordinal: emitted.ordinal,
                    enqueued: Duration::from_nanos(emitted.enqueued_ns),
                })
                .context("arrival receiver closed")?;
        }
        Ok(())
    });
    eprintln!(
        "workload_external_arrivals={}",
        serde_json::json!({
            "epoch_ns":epoch_ns, "api_only":api_only, "socket":path,
            "clock":"CLOCK_MONOTONIC"
        })
    );
    Ok(Arrivals {
        schedule,
        start: Clock::External(epoch_ns),
        receiver,
        producer: Some(producer),
    })
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::time::Duration;

    use anyhow::{Error, Result, ensure};
    use tempfile::TempDir;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
    use tokio::net::UnixListener;
    use tokio::time::timeout;

    use super::connect;
    use crate::reactor::workload_tests::smoke::populated::timed::{Profile, Schedule, Spec};

    #[tokio::test]
    async fn workload_external_arrivals_reject_wrong_order_and_invalid_clock() -> Result<()> {
        for response in [
            "{\"ordinal\":999,\"enqueued_ns\":0}\n",
            "{\"ordinal\":1,\"enqueued_ns\":18446744073709551615}\n",
            "not-json\n",
        ] {
            let directory = TempDir::new()?;
            let path = directory.path().join("arrivals");
            let listener = UnixListener::bind(&path)?;
            let server = tokio::spawn(async move {
                let (stream, _) = listener.accept().await?;
                let mut reader = BufReader::new(stream);
                let mut request = String::new();
                reader.read_line(&mut request).await?;
                reader.get_mut().write_all(response.as_bytes()).await?;
                Ok::<_, Error>(())
            });
            let schedule = Arc::new(Schedule::new(Spec {
                profile: Profile::Representative,
                fresh_backlog: 0,
                intervals: 1,
            })?);
            let mut arrivals = connect(path.to_str().unwrap(), schedule, true).await?;
            ensure!(
                timeout(Duration::from_secs(2), arrivals.receiver.recv())
                    .await?
                    .is_none()
            );
            ensure!(arrivals.stop().await.is_err());
            server.await??;
        }
        Ok(())
    }
}
