use std::env;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, ensure};
use clap::Args;

#[derive(Debug, Args)]
pub struct ProtocolBundlesArgs {
    /// Stage production executors without linking or qualifying a node.
    #[arg(long, conflicts_with = "build_node")]
    pub build_executors: bool,
    /// Link the production node and audit native ownership.
    #[arg(long, conflicts_with = "build_executors")]
    pub build_node: bool,
    /// Require all dependencies to be present in the local Cargo cache.
    #[arg(long)]
    pub offline: bool,
    /// Target must match the current supported host platform.
    #[arg(long)]
    pub target: Option<String>,
    /// Compiler profile used for both bundles and the host.
    #[arg(long, default_value = "release", value_parser = ["release", "dev"])]
    pub profile: String,
    /// Output directory, relative to the checkout root unless absolute.
    #[arg(long)]
    pub output: Option<PathBuf>,
    /// Maximum concurrent compiler jobs across sequential graph builds.
    #[arg(short = 'j', long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(1..=2))]
    pub jobs: u32,
}

pub fn protocol_bundles(args: ProtocolBundlesArgs) -> Result<()> {
    let cwd = env::current_dir()?;
    let root = cwd
        .ancestors()
        .find(|path| path.join("tools/protocol-bundles/build.py").is_file())
        .context("run protocol-bundles inside a Kontor checkout")?;
    let mut command = Command::new("python3");
    command
        .current_dir(root)
        .arg(root.join("tools/protocol-bundles/build.py"))
        .args(["--profile", &args.profile, "--jobs", &args.jobs.to_string()]);
    if args.offline {
        command.arg("--offline");
    }
    if args.build_executors {
        command.arg("--build-executors");
    }
    if args.build_node {
        command.arg("--build-node");
    }
    if let Some(target) = args.target {
        command.args(["--target", &target]);
    }
    if let Some(output) = args.output {
        command.arg("--output").arg(output);
    }
    ensure!(
        command.status()?.success(),
        "protocol bundle qualification failed"
    );
    Ok(())
}
