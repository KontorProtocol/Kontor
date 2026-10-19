use anyhow::{Result, anyhow};
use wasmtime::{Error, OutOfMemory, Trap};

use crate::runtime::{ExecutionError, Runtime};
use crate::test_utils::test_runtime;

#[tokio::test]
async fn explicit_failure_classification_survives_nested_error_sources() -> Result<()> {
    let (runtime, _dir, _name) = test_runtime().await?;
    for deterministic in [false, true] {
        let mut error = anyhow!(Trap::OutOfFuel);
        for _ in 0..3 {
            error = if deterministic {
                ExecutionError::Deterministic(error)
            } else {
                ExecutionError::NonDeterministic(error)
            }
            .into();
            assert!(error.chain().any(|cause| cause.is::<Trap>()));
            let mut store = runtime.make_store(1_000)?;
            let result = Runtime::decode_result(
                false,
                Ok(Err(Error::from_anyhow(error).context("nested call"))),
                vec![],
                &mut store,
            )
            .await;
            assert_eq!(
                matches!(result, Err(ExecutionError::Deterministic(_))),
                deterministic,
                "{result:?}"
            );
            error = match result.unwrap_err() {
                ExecutionError::Deterministic(error) | ExecutionError::NonDeterministic(error) => {
                    error
                }
            };
        }
    }
    for error in [
        Error::from(OutOfMemory::new(1024)),
        Error::msg("unknown engine failure"),
        Error::from_anyhow(anyhow!("database unavailable")),
        Error::from_anyhow(anyhow!(
            "resource limit exceeded: instance count too high at 1"
        )),
    ] {
        let mut store = runtime.make_store(1_000)?;
        let result = Runtime::decode_result(false, Ok(Err(error)), vec![], &mut store).await;
        assert!(
            matches!(result, Err(ExecutionError::NonDeterministic(_))),
            "{result:?}"
        );
    }
    Ok(())
}

#[test]
fn nested_errors_format_linearly_and_keep_the_cause() {
    let mut error = anyhow!(Trap::OutOfFuel);
    for _ in 0..8 {
        error = anyhow!(ExecutionError::Deterministic(error)).context("nested call");
    }

    assert!(error.chain().any(|cause| cause.is::<Trap>()));
    let logged = format!("{error:#}");
    let response = format!("{:?}", ExecutionError::Deterministic(error));
    for formatted in [&logged, &response] {
        assert!(formatted.contains("nested call"));
        assert!(formatted.contains(&Trap::OutOfFuel.to_string()));
        assert!(
            formatted.len() < 10_000,
            "formatted {} bytes",
            formatted.len()
        );
    }
}
