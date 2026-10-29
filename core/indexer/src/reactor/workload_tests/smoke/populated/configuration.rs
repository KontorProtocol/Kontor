use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{Delivery, PopulationConfig, replay};

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct MixedConfig {
    pub(super) transactions: usize,
    pub(super) live_keys: usize,
    pub(super) new_files: usize,
    #[serde(default)]
    pub(super) historical_rows: usize,
    #[serde(default)]
    pub(super) batch_operations: usize,
    #[serde(default)]
    pub(super) simulation_operations: usize,
    #[serde(default)]
    pub(super) warm_simulation_cache: bool,
}

impl MixedConfig {
    pub(super) fn validate(self) -> Result<Self> {
        ensure!(
            matches!(self.transactions, 50 | 500),
            "fixture supports 50 or 500 two-operation transactions"
        );
        ensure!(
            (1..=100_000_000).contains(&self.live_keys),
            "fixture keys must retain eight-digit lexical order"
        );
        ensure!(
            self.new_files <= self.transactions / 5,
            "file registrations exceed the native-operation allocation"
        );
        ensure!(
            self.historical_rows <= self.live_keys * 12,
            "history fixture supports at most twelve versions per live key"
        );
        ensure!(
            self.batch_operations == 0
                || (matches!(self.batch_operations, 20 | 40)
                    && (self.transactions * 2).is_multiple_of(self.batch_operations)),
            "configured batches require complete groups of 20 or 40 operations"
        );
        ensure!(
            matches!(self.simulation_operations, 0 | 2 | 4),
            "configured simulations require two or four operations"
        );
        ensure!(
            !self.warm_simulation_cache || self.simulation_operations > 0,
            "simulation cache warming requires simulation requests"
        );
        Ok(self)
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Configuration {
    population: PopulationConfig,
    mixed: MixedConfig,
}

impl Configuration {
    fn parse(bytes: &[u8]) -> Result<Self> {
        let config: Self = serde_json::from_slice(bytes)?;
        config.population.validate()?;
        config.mixed.validate()?;
        Ok(config)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
#[ignore = "requires local bitcoind and KONTOR_WORKLOAD_CONFIG JSON; correctness replay, not performance acceptance"]
async fn workload_configured_mixed_replays_populations_and_accounting() -> Result<()> {
    let input = std::env::var("KONTOR_WORKLOAD_CONFIG")
        .context("configured mixed replay requires KONTOR_WORKLOAD_CONFIG")?;
    let config = Configuration::parse(input.as_bytes())?;
    eprintln!(
        "workload_configuration_sha256={}",
        hex::encode(Sha256::digest(input.as_bytes()))
    );
    eprintln!("workload_configuration={}", serde_json::to_string(&config)?);
    replay(config.population, Delivery::Configured(config.mixed)).await
}

#[test]
fn workload_mixed_configuration_rejects_invalid_shapes() -> Result<()> {
    let valid = r#"{"population":{"active_validators":4,"replacements":2,"agreements":2,"members_per_agreement":3},"mixed":{"transactions":50,"live_keys":257,"new_files":5}}"#;
    Configuration::parse(valid.as_bytes())?;
    for invalid in [
        valid.replace(
            "\"new_files\":5",
            "\"new_files\":5,\"warm_simulation_cache\":true",
        ),
        valid.replace(
            "\"new_files\":5",
            "\"new_files\":5,\"simulation_operations\":1",
        ),
        valid.replace(
            "\"new_files\":5",
            "\"new_files\":5,\"simulation_operations\":3",
        ),
        valid.replace(
            "\"new_files\":5",
            "\"new_files\":5,\"simulation_operations\":5",
        ),
        valid.replace("\"new_files\":5", "\"new_files\":5,\"batch_operations\":1"),
        valid.replace("\"new_files\":5", "\"new_files\":5,\"batch_operations\":40"),
        valid.replace("\"transactions\":50", "\"transactions\":0"),
        valid.replace("\"transactions\":50", "\"transactions\":51"),
        valid.replace("\"live_keys\":257", "\"live_keys\":0"),
        valid.replace("\"live_keys\":257", "\"live_keys\":100000001"),
        valid.replace("\"new_files\":5", "\"new_files\":11"),
        valid.replace("\"new_files\":5", "\"new_files\":5,\"new_files\":0"),
        valid.replace("\"new_files\":5", "\"new_files\":5,\"ignored\":true"),
        valid.replace("\"replacements\":2", "\"replacements\":4"),
        valid.replace(
            "\"new_files\":5",
            "\"new_files\":5,\"historical_rows\":3085",
        ),
    ] {
        ensure!(
            Configuration::parse(invalid.as_bytes()).is_err(),
            "accepted {invalid}"
        );
    }
    for count in [0, 2, 4] {
        Configuration::parse(
            valid
                .replace(
                    "\"new_files\":5",
                    &format!("\"new_files\":5,\"simulation_operations\":{count}"),
                )
                .as_bytes(),
        )?;
    }
    Configuration::parse(
        valid
            .replace(
                "\"new_files\":5",
                "\"new_files\":5,\"simulation_operations\":2,\"warm_simulation_cache\":true",
            )
            .as_bytes(),
    )?;
    Configuration::parse(
        valid
            .replace("\"new_files\":5", "\"new_files\":5,\"batch_operations\":20")
            .as_bytes(),
    )?;
    Configuration::parse(
        valid
            .replace("\"transactions\":50", "\"transactions\":500")
            .replace("\"new_files\":5", "\"new_files\":5,\"batch_operations\":40")
            .as_bytes(),
    )?;
    for count in [0, 5, 10] {
        Configuration::parse(
            valid
                .replace("\"new_files\":5", &format!("\"new_files\":{count}"))
                .as_bytes(),
        )?;
    }
    Configuration::parse(
        valid
            .replace("\"transactions\":50", "\"transactions\":500")
            .replace("\"new_files\":5", "\"new_files\":100")
            .replace("\"live_keys\":257", "\"live_keys\":100000")
            .as_bytes(),
    )?;
    Ok(())
}
