use std::env;
use std::io;
use std::path::PathBuf;
use std::process;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use kontor_build::build_inputs::{Request as BuildInputRequest, run as build_inputs};
use kontor_build::consensus_definition::{
    FreezeArgs as ConsensusArgs, Request as ConsensusRequest, freeze as freeze_consensus,
    run as consensus_definition,
};
use kontor_build::execution_definition::{
    FreezeArgs, Request as DefinitionRequest, freeze as freeze_execution,
    run as execution_definition,
};
use kontor_build::freeze_sources::{FreezeSourcesArgs, freeze_sources};
use kontor_build::interface::{Request as InterfaceRequest, run as interface};
use kontor_build::linker_record::verify_input;
use kontor_build::node_evidence::comparison::{
    CompareNodeArgs, Request as CompareRequest, compare_node, run as compare_evidence,
};
use kontor_build::node_evidence::runner::{Request as NodeRunRequest, run as run_node};
use kontor_build::node_evidence::{
    QualifyNodeArgs, Request as NodeEvidenceRequest, qualify_node, run as node_evidence,
};
use kontor_build::object_tools::{Request as ObjectRequest, run as inspect_object};
use kontor_build::provenance::{Request as ProvenanceRequest, run as provenance};
use kontor_build::recipes::{Request as RecipeRequest, run as recipes};
use kontor_build::shared_ownership::{Request as SharedRequest, run as audit_shared};
use kontor_build::source_identity::{Metadata, verify_sources};
use kontor_build::stack_evidence::comparison::{CompareStackArgs, compare_stack};
use kontor_build::stack_evidence::smoke::{SmokeArgs, capture as stack_smoke};
use kontor_build::stack_evidence::{Request as StackRequest, run as stack_evidence};
use kontor_build::symbol_audit::{Request as AuditRequest, run as audit_symbols};
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
    /// Compare archived stack qualification and required dev smoke evidence.
    CompareStack(CompareStackArgs),
    /// Run the bounded dev-profile ownership and resource smoke tests.
    StackSmoke(SmokeArgs),
    /// Verify stack qualification transcripts and paired observations from JSON.
    VerifyStackEvidence,
    /// Compare verified node evidence across the required platforms.
    CompareNode(CompareNodeArgs),
    /// Verify archived node evidence from a JSON request.
    VerifyNodeArchive,
    /// Build and execute the retained node integration checks.
    QualifyNode(QualifyNodeArgs),
    /// Execute an audited node or one lifecycle check from a JSON request.
    RunNodeQualification,
    /// Verify retained execution and node lifecycle evidence from a JSON request.
    VerifyNodeEvidence,
    /// Locate the built CLI for transitional callers without repeated Cargo launches.
    #[command(hide = true)]
    ToolPath,
    /// Build reproducible contracts and SDK bindings in the pinned container.
    Build(BuildArgs),
    /// Build and qualify independently locked protocol bundles.
    ProtocolBundles(ProtocolBundlesArgs),
    /// Verify an immutable source snapshot and print its inventory as JSON.
    VerifySnapshot(VerifySnapshotArgs),
    /// Preserve executor inputs from an exact commit without redefining them.
    FreezeSources(FreezeSourcesArgs),
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
    /// Inspect compiler objects with the pinned LLVM tools from a JSON request.
    InspectObject,
    /// Attribute native symbols to independently compiled graphs from JSON input.
    AuditSymbols,
    /// Verify shared runtime and graph import ownership from JSON input.
    AuditShared,
    /// Select and verify protocol graph recipes from a JSON request.
    Recipes,
    /// Verify resolved dependencies, Cargo artifacts and guest capabilities.
    BuildInputs,
    /// Run or verify independent bundle interface controls.
    Interface,
    /// Build or verify execution-reference bytes from JSON input.
    ExecutionDefinition,
    /// Verify an executor reference, or explicitly write an unreleased definition.
    FreezeExecution(FreezeArgs),
    /// Build or verify consensus-reference JSON.
    ConsensusDefinition,
    /// Verify consensus provenance, or explicitly write an unreleased reference.
    FreezeConsensus(ConsensusArgs),
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
        Command::CompareStack(args) => {
            println!("{}", compare_stack(&repository_root()?, args)?);
            Ok(())
        }
        Command::StackSmoke(args) => {
            println!("{}", stack_smoke(&repository_root()?, args)?);
            Ok(())
        }
        Command::VerifyStackEvidence => {
            let request: StackRequest = serde_json::from_reader(io::stdin().lock())?;
            println!("{}", stack_evidence(request)?);
            Ok(())
        }
        Command::CompareNode(args) => {
            println!("{}", compare_node(&repository_root()?, args)?);
            Ok(())
        }
        Command::VerifyNodeArchive => {
            let request: CompareRequest = serde_json::from_reader(io::stdin().lock())?;
            println!("{}", compare_evidence(request)?);
            Ok(())
        }
        Command::QualifyNode(args) => {
            println!("{}", qualify_node(&repository_root()?, args)?);
            Ok(())
        }
        Command::RunNodeQualification => {
            let request: NodeRunRequest = serde_json::from_reader(io::stdin().lock())?;
            println!("{}", run_node(request)?);
            Ok(())
        }
        Command::VerifyNodeEvidence => {
            let request: NodeEvidenceRequest = serde_json::from_reader(io::stdin().lock())?;
            println!("{}", node_evidence(request)?);
            Ok(())
        }
        Command::ToolPath => {
            println!("{}", env::current_exe()?.display());
            Ok(())
        }
        Command::Provenance => {
            let request: ProvenanceRequest = serde_json::from_reader(io::stdin().lock())?;
            println!("{}", provenance(request)?);
            Ok(())
        }
        Command::InspectObject => {
            let request: ObjectRequest = serde_json::from_reader(io::stdin().lock())?;
            println!("{}", inspect_object(request)?);
            Ok(())
        }
        Command::AuditSymbols => {
            let request: AuditRequest = serde_json::from_reader(io::stdin().lock())?;
            println!("{}", audit_symbols(request)?);
            Ok(())
        }
        Command::AuditShared => {
            let request: SharedRequest = serde_json::from_reader(io::stdin().lock())?;
            println!("{}", audit_shared(request)?);
            Ok(())
        }
        Command::Recipes => {
            let request: RecipeRequest = serde_json::from_reader(io::stdin().lock())?;
            println!("{}", recipes(request)?);
            Ok(())
        }
        Command::BuildInputs => {
            let request: BuildInputRequest = serde_json::from_reader(io::stdin().lock())?;
            println!("{}", build_inputs(request)?);
            Ok(())
        }
        Command::Interface => {
            let request: InterfaceRequest = serde_json::from_reader(io::stdin().lock())?;
            println!("{}", interface(request)?);
            Ok(())
        }
        Command::ExecutionDefinition => {
            let request: DefinitionRequest = serde_json::from_reader(io::stdin().lock())?;
            println!("{}", execution_definition(request)?);
            Ok(())
        }
        Command::FreezeExecution(args) => {
            println!("{}", freeze_execution(&repository_root()?, args)?);
            Ok(())
        }
        Command::ConsensusDefinition => {
            let request: ConsensusRequest = serde_json::from_reader(io::stdin().lock())?;
            println!("{}", consensus_definition(request)?);
            Ok(())
        }
        Command::FreezeConsensus(args) => {
            println!("{}", freeze_consensus(&repository_root()?, args)?);
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
        Command::FreezeSources(args) => {
            println!("{}", freeze_sources(&repository_root()?, args)?);
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
