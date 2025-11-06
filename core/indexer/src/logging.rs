use std::sync::Once;

use clap::{Parser, ValueEnum};
use serde::{Deserialize, Serialize};

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
        let config = Config::try_parse().expect("Failed to parse config to setup logging");
        match config.log_format {
            Format::JSON => {
                let _ = tracing_subscriber::fmt().json().try_init();
            }
            Format::Plain => {
                let _ = tracing_subscriber::fmt::try_init();
            }
        }
    });
}
