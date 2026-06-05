use std::io::IsTerminal;
use std::sync::Once;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use tracing::{Level, level_filters::LevelFilter};
use tracing_subscriber::{EnvFilter, Registry, filter, layer::SubscriberExt};

static INIT: Once = Once::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    JSON,
    Plain,
}

/// Tests and other in-process callers — defaults to plain format.
pub fn setup() {
    setup_with_format(Format::Plain);
}

/// Daemon entrypoint passes the format already-parsed from the `run`
/// subcommand. Re-parsing argv here would fail because the top-level CLI
/// requires a subcommand and `Config` no longer parses standalone.
pub fn setup_with_format(log_format: Format) {
    INIT.call_once(|| {
        let base_filter = filter::Targets::new()
            .with_default(LevelFilter::INFO)
            .with_target("arc_malachitebft", Level::WARN);

        match log_format {
            Format::JSON => {
                let layer = tracing_stackdriver::layer();
                let subscriber = Registry::default().with(layer).with(base_filter);
                let _ = tracing::subscriber::set_global_default(subscriber);
            }
            Format::Plain => {
                let env_filter = EnvFilter::builder()
                    .with_default_directive(LevelFilter::INFO.into())
                    .from_env_lossy()
                    .add_directive("arc_malachitebft=warn".parse().unwrap());
                // Emit ANSI colour codes only when stdout is a real terminal;
                // otherwise (redirected to a file or piped) they land in the
                // output as escape-sequence garbage.
                let _ = tracing_subscriber::fmt()
                    .with_env_filter(env_filter)
                    .with_ansi(std::io::stdout().is_terminal())
                    .try_init();
            }
        }
    });
}
