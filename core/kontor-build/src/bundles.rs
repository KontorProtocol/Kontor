use std::env;
use std::fs::{self, File};
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use clap::Args;
use serde_json::{Value, json};

use crate::build_artifacts::{install_node, verify_staged_inputs};
use crate::build_inputs::capabilities;
use crate::compiler_wrapper::{stage_graph_wrapper, stage_linker_wrapper, stage_node_wrapper};
use crate::container::sha256;
use crate::execution_definition::resolve;
use crate::graph_build::{Options, compile_graph, fingerprint, write_json};
use crate::interface::{verify as verify_interfaces, verify_adapter};
use crate::node_build::{Options as NodeOptions, Request as NodeRequest, run as build_node};
use crate::provenance::{GraphKind, source_inputs};
use crate::recipes::{
    Graphs, Kind, consensus_graphs, executor_graphs, graph_root, proof_graphs, verify_identity,
    verify_reservations,
};
use crate::toolchain::{Environment, TOOLCHAIN, output as command_output, tools};

mod proof;

#[derive(Debug, Args)]
pub struct ProtocolBundlesArgs {
    /// Stage production executors without linking or qualifying a node.
    #[arg(long, conflicts_with = "build_node")]
    pub build_executors: bool,
    /// Stage production consensus bundles and check their typed node adapters.
    #[arg(long, conflicts_with_all = ["build_node", "build_executors"])]
    pub build_consensus: bool,
    /// Link the production node and audit native ownership.
    #[arg(long, conflicts_with = "build_executors")]
    pub build_node: bool,
    /// Include the isolated executor integration command in the node.
    #[arg(long, requires = "build_node")]
    pub node_qualification: bool,
    /// Copy the audited node executable to this path, relative to the checkout root.
    #[arg(long, requires = "build_node")]
    pub install_node: Option<PathBuf>,
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
    /// Retained executor configuration; node builds default to managed-node.
    #[arg(long, value_parser = ["legacy-qualification", "k4-node", "managed-node"])]
    pub link_set: Option<String>,
    /// Maximum concurrent compiler jobs across sequential graph builds.
    #[arg(short = 'j', long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(1..=2))]
    pub jobs: u32,
}

#[derive(Clone, Copy, Debug, PartialEq)]
enum Mode {
    Proof,
    Executors,
    Consensus,
    Node,
}
fn mode(args: &ProtocolBundlesArgs) -> Result<(Mode, Option<String>)> {
    ensure!(
        [args.build_executors, args.build_consensus, args.build_node]
            .into_iter()
            .filter(|value| *value)
            .count()
            <= 1,
        "choose only one bundle build mode"
    );
    ensure!(
        !(args.node_qualification || args.install_node.is_some()) || args.build_node,
        "node qualification and installation require --build-node"
    );
    ensure!(
        (1..=2).contains(&args.jobs) && matches!(args.profile.as_str(), "dev" | "release"),
        "invalid profile or compiler job count"
    );
    let mode = if args.build_node {
        Mode::Node
    } else if args.build_executors {
        Mode::Executors
    } else if args.build_consensus {
        Mode::Consensus
    } else {
        Mode::Proof
    };
    ensure!(
        args.link_set.is_none() || matches!(mode, Mode::Node | Mode::Executors),
        "--link-set requires --build-executors or --build-node"
    );
    let link_set = if matches!(mode, Mode::Node | Mode::Executors) {
        Some(args.link_set.clone().unwrap_or_else(|| {
            if mode == Mode::Node {
                "managed-node".into()
            } else {
                "k4-node".into()
            }
        }))
    } else {
        None
    };
    if let Some(link_set) = &link_set {
        executor_graphs(Some(link_set))?;
    }
    Ok((mode, link_set))
}
fn sanitized_environment(mut env: Environment, jobs: u32, offline: bool) -> Environment {
    env.retain(|key, _| {
        ![
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "RUSTC",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        ]
        .contains(&key.as_str())
            && !key.starts_with("CARGO_PROFILE_")
            && !(key.starts_with("CARGO_TARGET_") && key.ends_with("RUSTFLAGS"))
    });
    env.extend([
        ("RUSTUP_TOOLCHAIN".into(), TOOLCHAIN.into()),
        ("RUSTC_WRAPPER".into(), String::new()),
        ("CCACHE_DISABLE".into(), "1".into()),
        ("CARGO_BUILD_JOBS".into(), jobs.to_string()),
    ]);
    if offline {
        env.insert("CARGO_NET_OFFLINE".into(), "true".into());
    }
    env
}
fn native_target(compiler: &str, requested: Option<&str>) -> Result<String> {
    let host = compiler
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .context("missing compiler host")?;
    let target = requested.unwrap_or(host);
    ensure!(
        [
            "aarch64-unknown-linux-gnu",
            "x86_64-unknown-linux-gnu",
            "aarch64-apple-darwin"
        ]
        .contains(&target)
            && target == host,
        "qualification must execute natively on a supported target"
    );
    Ok(target.into())
}
fn output_directory(
    base: &Path,
    target: &str,
    profile: &str,
    mode: Mode,
    link_set: Option<&str>,
) -> PathBuf {
    let output = base.join(target).join(profile);
    match mode {
        Mode::Proof => output,
        Mode::Consensus => output.join("consensus"),
        Mode::Node | Mode::Executors => output
            .join("executors")
            .join(link_set.expect("executor link set")),
    }
}
fn begin_output(base: &Path, output: &Path, production: bool) -> Result<File> {
    fs::create_dir_all(output)?;
    let lock = File::options()
        .append(true)
        .create(true)
        .open(base.join(".build.lock"))?;
    lock.try_lock()
        .context("another protocol bundle builder owns this output directory")?;
    let mut names = vec!["qualification.json"];
    if production {
        names.extend([
            "executor-build.json",
            "consensus-build.json",
            "node-build.json",
        ]);
    }
    for name in names {
        match fs::remove_file(output.join(name)) {
            Ok(()) => {}
            Err(error) if error.kind() == ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
    }
    Ok(lock)
}
fn compile_graphs(
    root: &Path,
    graphs: &Graphs,
    options: &Options,
    env: &Environment,
    output: &Path,
    cargo_home: &Path,
) -> Result<Vec<Value>> {
    let mut result = Vec::new();
    for label in graphs.keys() {
        let wrapper = stage_graph_wrapper(&output.join(label))?;
        result.push(compile_graph(
            root, label, graphs, options, env, output, &wrapper, cargo_home,
        )?);
    }
    Ok(result)
}
fn check_sources(
    root: &Path,
    graphs: &Graphs,
    reports: &[Value],
    output: &Path,
    cargo_home: &Path,
) -> Result<()> {
    for report in reports {
        let label = report["graph"].as_str().context("missing graph label")?;
        let recipe = graphs.get(label).context("unknown graph label")?;
        let data = serde_json::from_slice(&fs::read(output.join(label).join("metadata.json"))?)?;
        let kind = match recipe.kind {
            Kind::Proof => GraphKind::Proof,
            Kind::Executor => GraphKind::Executor,
            Kind::Consensus => GraphKind::Consensus,
        };
        let sources = source_inputs(
            &graph_root(root, recipe)?,
            &data,
            kind,
            Some(root),
            cargo_home,
        )?;
        ensure!(
            json!(fingerprint(&sources)?) == report["source_inputs_sha256"],
            "source inputs changed before qualification finished"
        );
    }
    Ok(())
}
pub fn protocol_bundles(args: ProtocolBundlesArgs) -> Result<()> {
    let cwd = env::current_dir()?;
    let root = cwd
        .ancestors()
        .find(|path| path.join("tools/build.json").is_file())
        .context("run protocol-bundles inside a Kontor checkout")?;
    let (mode, link_set) = mode(&args)?;
    let production = mode != Mode::Proof;
    let mut environment = sanitized_environment(env::vars().collect(), args.jobs, args.offline);
    let pinned = command_output(
        root,
        Path::new("rustup"),
        &["which", "--toolchain", TOOLCHAIN, "rustc"],
        Some(&environment),
    )?
    .trim()
    .to_owned();
    environment.extend([
        ("RUSTC".into(), pinned.clone()),
        ("KONTOR_PINNED_RUSTC".into(), pinned.clone()),
        ("RUSTC_WORKSPACE_WRAPPER".into(), String::new()),
    ]);
    let compiler = command_output(root, Path::new(&pinned), &["-Vv"], Some(&environment))?;
    let target = native_target(&compiler, args.target.as_deref())?;
    let toolchain = tools(root, &environment, &target)?;
    let base = resolve(
        &root.join(
            args.output
                .as_deref()
                .unwrap_or(Path::new(".build-cache/protocol-bundles")),
        ),
    )?;
    let output = output_directory(&base, &target, &args.profile, mode, link_set.as_deref());
    let _lock = begin_output(&base, &output, production)?;
    let cargo_home = root.join(match environment.get("CARGO_HOME") {
        Some(home) => PathBuf::from(home),
        None => Path::new(
            environment
                .get("HOME")
                .context("missing HOME and CARGO_HOME")?,
        )
        .join(".cargo"),
    });
    let graphs = match mode {
        Mode::Consensus => consensus_graphs(),
        Mode::Proof => proof_graphs(),
        _ => executor_graphs(link_set.as_deref())?,
    };
    verify_reservations(root, &graphs)?;
    if mode != Mode::Consensus {
        capabilities(root)?;
    }
    let options = Options {
        target: target.clone(),
        profile: args.profile.clone(),
        jobs: args.jobs,
        offline: args.offline,
    };
    let reports = compile_graphs(root, &graphs, &options, &environment, &output, &cargo_home)?;
    write_json(
        &output.join("build-inputs.json"),
        &json!({"compiler":compiler,"target":target,"profile":args.profile,"graphs":reports}),
    )?;
    let proof = if mode == Mode::Proof {
        Some(proof::qualify(
            root,
            &reports,
            &options,
            &environment,
            &output,
        )?)
    } else {
        None
    };
    let engines = consensus_graphs();
    let consensus_output = base.join(&target).join(&args.profile).join("consensus");
    let consensus = if mode == Mode::Node && link_set.as_deref() == Some("managed-node") {
        fs::create_dir_all(&consensus_output)?;
        verify_reservations(root, &engines)?;
        compile_graphs(
            root,
            &engines,
            &options,
            &environment,
            &consensus_output,
            &cargo_home,
        )?
    } else {
        vec![]
    };
    let mut node = if mode == Mode::Node {
        Some(build_node(NodeRequest {
            root: root.into(),
            graphs: reports.clone(),
            consensus: consensus.clone(),
            options: NodeOptions {
                build: options.clone(),
                link_set: link_set.clone().unwrap(),
                node_qualification: args.node_qualification,
            },
            env: environment.clone(),
            output: output.clone(),
            node_wrapper: stage_node_wrapper(&output.join("node"))?,
            linker_wrapper: stage_linker_wrapper(&output.join("node"))?,
            cargo_home: cargo_home.clone(),
        })?)
    } else {
        None
    };
    let controls = if mode == Mode::Consensus {
        proof::audit_inputs(root, &reports, &output)?;
        Some(
            json!({"interfaces":verify_interfaces(&reports,&target,&environment,&output,root)?,"node_adapter":verify_adapter(root,&reports,&target,&environment,&output,root)?,"input_ownership_sha256":sha256(&output.join("input-ownership.json"))?}),
        )
    } else {
        None
    };
    check_sources(root, &graphs, &reports, &output, &cargo_home)?;
    if !consensus.is_empty() {
        check_sources(root, &engines, &consensus, &consensus_output, &cargo_home)?;
    }
    for report in &consensus {
        verify_identity(root, report, &engines)?;
        verify_staged_inputs(report, root)?;
    }
    ensure!(
        tools(root, &environment, &target)? == toolchain,
        "common compiler inputs changed during qualification"
    );
    verify_reservations(root, &graphs)?;
    if mode != Mode::Consensus {
        capabilities(root)?;
    }
    if production {
        for report in &reports {
            verify_identity(root, report, &graphs)?;
            verify_staged_inputs(report, root)?;
        }
        let mut build_report = json!({"compiler":compiler,"toolchain_inputs":toolchain,"target":target,"profile":args.profile,"link_set":link_set,"graphs":reports,"status":"staged libraries; final node link and execution qualification required"});
        if let Some(controls) = controls {
            build_report["consensus_controls"] = controls;
        }
        write_json(
            &output.join(if mode == Mode::Consensus {
                "consensus-build.json"
            } else {
                "executor-build.json"
            }),
            &build_report,
        )?;
        if let Some(node) = node.as_mut() {
            if let Some(destination) = args.install_node {
                node["installed"] = install_node(node, &root.join(destination), root)?;
            }
            write_json(
                &output.join("node-build.json"),
                &json!({"compiler":compiler,"toolchain_inputs":toolchain,"target":target,"profile":args.profile,"link_set":link_set,"graphs":reports,"consensus_graphs":consensus,"node":node}),
            )?;
            println!(
                "Node built at {}; execution qualification has not run.",
                node["executable"]
                    .as_str()
                    .context("missing node executable")?
            );
        } else {
            println!(
                "{} libraries staged at {}; node qualification has not run.",
                if mode == Mode::Consensus {
                    "Consensus"
                } else {
                    "Executor"
                },
                output.display()
            );
        }
    } else {
        write_json(
            &output.join("qualification.json"),
            &json!({"compiler":compiler,"toolchain_inputs":toolchain,"target":target,"profile":args.profile,"graphs":reports,"proof":proof}),
        )?;
        println!("{}", serde_json::to_string_pretty(&proof)?);
    }
    Ok(())
}
#[cfg(test)]
mod tests;
