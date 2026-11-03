use std::env;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use clap::Args;
use serde_json::Value;

use super::runner::{execute, invalidate};
use crate::bundles::{ProtocolBundlesArgs, protocol_bundles};
use crate::toolchain::{Environment, TOOLCHAIN, output};

#[derive(Debug, Args)]
pub struct QualifyNodeArgs {
    /// Evidence and installed executable directory, relative to the checkout root.
    #[arg(long)]
    pub output: PathBuf,
    #[arg(long, default_value = "release", value_parser = ["release", "dev"])]
    pub profile: String,
    #[arg(long)]
    pub offline: bool,
    #[arg(long, default_value = "managed-node", value_parser = ["legacy-qualification", "k4-node", "managed-node"])]
    pub link_set: String,
}
pub fn qualify_node(root: &Path, args: QualifyNodeArgs) -> Result<Value> {
    let directory = root.join(&args.output);
    let mut environment: Environment = env::vars().collect();
    environment.insert("RUSTUP_TOOLCHAIN".into(), TOOLCHAIN.into());
    let compiler = output(
        root,
        Path::new("rustup"),
        &["run", TOOLCHAIN, "rustc", "-Vv"],
        Some(&environment),
    )?;
    let target = compiler
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .context("missing compiler host")?;
    let report = directory
        .join(target)
        .join(&args.profile)
        .join("executors")
        .join(&args.link_set)
        .join("node-build.json");
    invalidate(&report.with_file_name("node-execution.json"))?;
    protocol_bundles(ProtocolBundlesArgs {
        build_executors: false,
        build_consensus: false,
        build_node: true,
        node_qualification: true,
        install_node: Some(directory.join("kontor")),
        offline: args.offline,
        target: Some(target.into()),
        profile: args.profile,
        output: Some(directory),
        link_set: Some(args.link_set.clone()),
        jobs: 2,
    })?;
    execute(root, &report, Some(&args.link_set), root)
}
