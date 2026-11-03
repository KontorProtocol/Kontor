use std::env;
use std::io;
use std::path::PathBuf;
use std::process;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use kontor_build::linker_record::verify_input;
use kontor_build::provenance::{Request as ProvenanceRequest, run as provenance};
use kontor_build::source_identity::{Metadata, verify_sources};
use kontor_build::{
    BuildArgs, CiScope, DiagnosticsArgs, ProtocolBundlesArgs, VerifySnapshotArgs,
    check_native_helper_lock, ci_scope, diagnostics, protocol_bundles, run, stage_graph_wrapper,
    stage_linker_wrapper, stage_node_wrapper, verify_snapshot,
};

#[derive(Parser)]
#[command(name = "kontor", about = "Repository build bootstrap")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Locate the built CLI for transitional callers without repeated Cargo launches.
    #[command(hide = true)]
    ToolPath,
    /// Build reproducible contracts and SDK bindings in the pinned container.
    Build(BuildArgs),
    /// Build and qualify independently locked protocol bundles.
    ProtocolBundles(ProtocolBundlesArgs),
    /// Verify an immutable source snapshot and print its inventory as JSON.
    VerifySnapshot(VerifySnapshotArgs),
    /// Check that native helper dependencies match the core lockfile.
    CheckNativeHelperLock,
    /// Preserve command output and macOS crash reports for CI diagnostics.
    Diagnostics(DiagnosticsArgs),
    /// Stage Cargo's dedicated graph compiler wrapper.
    #[command(hide = true)]
    StageGraphWrapper { output: PathBuf },
    /// Stage Cargo's dedicated node compiler wrapper.
    #[command(hide = true)]
    StageNodeWrapper { output: PathBuf },
    /// Stage the node linker recording executable.
    #[command(hide = true)]
    StageLinkerWrapper { output: PathBuf },
    /// Verify linker evidence supplied as JSON on standard input.
    VerifyLinkerRecord,
    /// Verify pinned Git and registry sources from Cargo metadata on standard input.
    VerifySources,
    /// Inventory build source inputs from a JSON request on standard input.
    Provenance,
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
        Command::ToolPath => {
            println!("{}", env::current_exe()?.display());
            Ok(())
        }
        Command::Provenance => {
            let request: ProvenanceRequest = serde_json::from_reader(io::stdin().lock())?;
            println!("{}", provenance(request)?);
            Ok(())
        }
        Command::VerifySources => {
            let data: Metadata = serde_json::from_reader(io::stdin().lock())?;
            println!("{}", verify_sources(&data)?);
            Ok(())
        }
        Command::VerifyLinkerRecord => verify_input(),
        Command::StageLinkerWrapper { output } => {
            println!("{}", stage_linker_wrapper(&output)?.display());
            Ok(())
        }
        Command::StageNodeWrapper { output } => {
            println!("{}", stage_node_wrapper(&output)?.display());
            Ok(())
        }
        Command::StageGraphWrapper { output } => {
            println!("{}", stage_graph_wrapper(&output)?.display());
            Ok(())
        }
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
        Command::Diagnostics(args) => {
            let status = diagnostics(args)?;
            if status != 0 {
                process::exit(status);
            }
            Ok(())
        }
    }
}
