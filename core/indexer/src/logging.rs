use std::sync::Once;

use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};
use tracing::{Level, level_filters::LevelFilter};
use tracing_subscriber::{Registry, filter, layer::SubscriberExt};

use crate::config::Config;

static INIT: Once = Once::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Format {
    JSON,
    Plain,
}

pub fn setup() {
    INIT.call_once(|| {
        let log_format = Config::try_parse()
            .map(|c| c.log_format)
            .unwrap_or(Format::Plain);
        match log_format {
            Format::JSON => {
                let layer = tracing_stackdriver::layer();
                let filter = filter::Targets::new()
                    .with_default(LevelFilter::OFF)
                    .with_target("kontor", Level::INFO)
                    .with_target("indexer", Level::INFO);
                let subscriber = Registry::default().with(layer).with(filter);
                let _ = tracing::subscriber::set_global_default(subscriber);
            }
            Format::Plain => {
                let _ = tracing_subscriber::fmt::try_init();
            }
        }
    });
}
