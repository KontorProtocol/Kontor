use std::env;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, ensure};
use clap::Args;

#[derive(Debug, Args)]
pub struct ProtocolBundlesArgs {
    /// Require all dependencies to be present in the local Cargo cache.
    #[arg(long)]
    pub offline: bool,
    /// Target must match the current supported host platform.
    #[arg(long)]
    pub target: Option<String>,
    /// Compiler profile used for both bundles and the host.
    #[arg(long, default_value = "release", value_parser = ["release", "dev"])]
    pub profile: String,
    /// Directory for isolated build outputs and qualification evidence.
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
        .arg(root.join("tools/protocol-bundles/build.py"))
        .args(["--profile", &args.profile, "--jobs", &args.jobs.to_string()]);
    if args.offline {
        command.arg("--offline");
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
