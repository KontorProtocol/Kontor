use std::env;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use kontor_build::{
    BuildArgs, CiScope, ProtocolBundlesArgs, VerifySnapshotArgs, check_native_helper_lock,
    ci_scope, protocol_bundles, run, verify_snapshot,
};

#[derive(Parser)]
#[command(name = "kontor", about = "Repository build bootstrap")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Build reproducible contracts and SDK bindings in the pinned container.
    Build(BuildArgs),
    /// Build and qualify independently locked protocol bundles.
    ProtocolBundles(ProtocolBundlesArgs),
    /// Verify an immutable source snapshot and print its inventory as JSON.
    VerifySnapshot(VerifySnapshotArgs),
    /// Check that native helper dependencies match the core lockfile.
    CheckNativeHelperLock,
    /// Select CI checks from the GitHub event and complete Git change set.
    CiScope {
        #[arg(value_enum)]
        kind: CiScope,
    },
}

fn repository_root() -> Result<PathBuf> {
    env::current_dir()?
        .ancestors()
        .find(|path| path.join("tools/build.json").is_file())
        .map(PathBuf::from)
        .context("run this command inside a Kontor checkout")
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Command::Build(args) => run(args),
        Command::ProtocolBundles(args) => protocol_bundles(args),
        Command::VerifySnapshot(args) => {
            let root = if args.root.is_absolute() {
                args.root
            } else {
                repository_root()?.join(args.root)
            };
            let record = verify_snapshot(&root, &args.sha256)?;
            println!("{}", serde_json::to_string(&record)?);
            Ok(())
        }
        Command::CheckNativeHelperLock => {
            let version = check_native_helper_lock(&repository_root()?)?;
            println!("Helper lock matches core native build dependencies (cc {version})");
            Ok(())
        }
        Command::CiScope { kind } => ci_scope(&repository_root()?, kind),
    }
}
