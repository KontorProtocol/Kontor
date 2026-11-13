use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::build_artifacts::{
    native_archives, node_codegen_objects, node_dependencies, node_executable, node_link_inputs,
    verify_staged_inputs,
};
use crate::build_inputs::current_artifacts;
use crate::canonical_json::{Style, encode};
use crate::consensus_definition::{Request as DefinitionRequest, run as definition};
use crate::container::sha256;
use crate::graph_build::{Options as BuildOptions, fingerprint, metadata, run_logged, write_json};
use crate::interface::{verify as verify_interfaces, verify_adapter};
use crate::linker_record::validate as validate_linker;
use crate::provenance::{GraphKind, source_inputs};
use crate::recipes::{Graphs, consensus_graphs, executor_graphs, verify_identity};
use crate::shared_ownership::run as shared_ownership;
use crate::symbol_audit::run as symbol_audit;
use crate::toolchain::{Environment, runtime_libraries};

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing or invalid {key}"))
}
fn read_json(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn lockfile(manifest: &Path) -> Result<Value> {
    Ok(toml::from_str(&fs::read_to_string(
        manifest.with_file_name("Cargo.lock"),
    )?)?)
}
fn selected_graphs(
    link_set: &str,
    graphs: &[Value],
    consensus: &[Value],
) -> Result<(Graphs, Graphs)> {
    let managed = matches!(link_set, "production-node" | "managed-node");
    ensure!(
        managed != consensus.is_empty(),
        "managed node requires the pinned consensus runtime graph"
    );
    let executors = executor_graphs(Some(link_set))?;
    let engines = consensus_graphs();
    let labels = |reports: &[Value]| -> Result<Vec<String>> {
        reports
            .iter()
            .map(|report| Ok(text(report, "graph")?.to_owned()))
            .collect()
    };
    ensure!(
        labels(graphs)? == executors.keys().cloned().collect::<Vec<_>>()
            && (!managed || labels(consensus)? == engines.keys().cloned().collect::<Vec<_>>()),
        "node graph set differs from the selected build recipe"
    );
    Ok((executors, engines))
}
fn verify_graphs(root: &Path, graphs: &[Value], recipes: &Graphs) -> Result<()> {
    for graph in graphs {
        verify_identity(root, graph, recipes)?;
        verify_staged_inputs(graph, root)?;
    }
    Ok(())
}
fn environment(base: &Environment, directory: &Path) -> Result<Environment> {
    let mut env = base.clone();
    for key in [
        "KONTOR_PROTOCOL_BUNDLE",
        "KONTOR_NATIVE_NAMESPACE",
        "BUNDLE_GRAPH",
        "BUNDLE_LIFT_RATE",
    ] {
        env.remove(key);
    }
    env.insert(
        "CARGO_TARGET_DIR".into(),
        directory
            .join("target")
            .to_str()
            .context("non-UTF-8 target path")?
            .into(),
    );
    env.insert("RUSTC_WRAPPER".into(), String::new());
    env.insert("RUSTFLAGS".into(), "-Cpanic=unwind".into());
    Ok(env)
}
struct DefinitionInputs {
    node: Value,
    node_lock: Value,
    consensus: BTreeMap<String, (Value, Value)>,
}
impl DefinitionInputs {
    fn verify(&self, root: &Path, managed: bool) -> Result<Value> {
        if managed {
            let mut result = serde_json::Map::new();
            for (label, (graph, lock)) in &self.consensus {
                result.insert(
                    label.clone(),
                    definition(DefinitionRequest::Managed {
                        root: root.into(),
                        node: self.node.clone(),
                        node_lock: self.node_lock.clone(),
                        graph: graph.clone(),
                        graph_lock: lock.clone(),
                        label: label.clone(),
                        verify: true,
                        cwd: root.into(),
                    })?,
                );
            }
            Ok(Value::Object(result))
        } else {
            definition(DefinitionRequest::Coordinator {
                root: root.into(),
                metadata: self.node.clone(),
                lock: self.node_lock.clone(),
                verify: true,
                cwd: root.into(),
            })
        }
    }
}
#[derive(Clone, Deserialize)]
pub struct Options {
    #[serde(flatten)]
    pub build: BuildOptions,
    pub link_set: String,
    pub node_qualification: bool,
}
fn link_spec(
    directory: &Path,
    options: &Options,
    compiler: &Path,
    sources: &Value,
    lock_hash: &str,
    libraries: &[Value],
    graphs: &[Value],
    coordinator: &Value,
    linker: &Path,
    features: &[String],
) -> Result<Value> {
    let source_hash = fingerprint(sources)?;
    let mut spec = json!({"compiler":compiler,"features":features,"link_set":options.link_set,"source_inputs_sha256":source_hash,
        "lock_sha256":lock_hash,"root_objects":directory.join("root-objects.json"),"graphs":libraries,"linker_wrapper":linker,
        "linker_wrapper_sha256":sha256(linker)?,"linker_record":directory.join("linker-record.json")});
    if matches!(
        options.link_set.as_str(),
        "production-node" | "managed-node"
    ) {
        let mut attestations = Vec::new();
        for (index, library) in libraries.iter().enumerate() {
            let mut entry = json!({"role":library["role"],"graph":library["graph"],"facade_sha256":library["facade_sha256"],"build_inputs_sha256":library["build_inputs_sha256"]});
            entry["definition"] = if index < graphs.len() {
                graphs[index]["execution_definition"]["execution_definition_id"].clone()
            } else {
                coordinator[text(library, "graph")?]["consensus_definition"].clone()
            };
            ensure!(
                entry["definition"].is_string(),
                "missing graph definition for attestation"
            );
            entry["wire_codec"] = if index < graphs.len() {
                Value::Null
            } else {
                json!(1)
            };
            attestations.push(entry);
        }
        spec["attestation"] = json!({"schema":1,"link_set":options.link_set,"target":options.build.target,"profile":options.build.profile,
            "compiler_sha256":sha256(compiler)?,"source_inputs_sha256":source_hash,"lock_sha256":lock_hash,"graphs":attestations});
    }
    Ok(spec)
}
fn completed_link(directory: &Path, spec_path: &Path, executable: &Path) -> Result<()> {
    let record_path = directory.join("linker-record.json");
    let record = read_json(&record_path)?;
    let compiler = read_json(&directory.join("root-objects.json"))?;
    let output = compiler
        .get("compiler_output")
        .filter(|value| value.is_object())
        .context("missing completed compiler output")?;
    validate_linker(
        &record,
        &sha256(spec_path)?,
        &sha256(executable)?,
        Some(output),
    )?;
    ensure!(
        text(&compiler, "linker_record_sha256")? == sha256(&record_path)?,
        "node compiler and linker records disagree"
    );
    Ok(())
}
pub fn linker_source_hash(root: &Path) -> Result<String> {
    let mut sources = serde_json::Map::new();
    for name in [
        "core/kontor-build/src/bin/kontor-node-linker.rs",
        "core/kontor-build/src/linker_record.rs",
    ] {
        sources.insert(name.into(), json!(sha256(&root.join(name))?));
    }
    fingerprint(&Value::Object(sources))
}
fn write_audit(path: &Path, value: &Value) -> Result<()> {
    fs::write(path, format!("{}\n", encode(value, Style::Spaced)?))?;
    Ok(())
}
#[derive(Deserialize)]
pub struct Request {
    pub root: PathBuf,
    pub graphs: Vec<Value>,
    pub consensus: Vec<Value>,
    pub options: Options,
    pub env: Environment,
    pub output: PathBuf,
    pub node_wrapper: PathBuf,
    pub linker_wrapper: PathBuf,
    pub cargo_home: PathBuf,
}
pub fn run(request: Request) -> Result<Value> {
    let Request {
        root,
        graphs,
        consensus,
        options,
        env: base_env,
        output,
        node_wrapper,
        linker_wrapper,
        cargo_home,
    } = request;
    ensure!(
        matches!(options.build.profile.as_str(), "dev" | "release")
            && (1..=2).contains(&options.build.jobs),
        "invalid node build profile or job count"
    );
    let (recipes, engines) = selected_graphs(&options.link_set, &graphs, &consensus)?;
    let managed = matches!(
        options.link_set.as_str(),
        "production-node" | "managed-node"
    );
    ensure!(
        !managed || options.node_qualification == (options.link_set == "managed-node"),
        "production and qualification link sets must match the node feature configuration"
    );
    let manifest = root.join("protocol-bundles/node/Cargo.toml");
    let recipe: Value = toml::from_str(&fs::read_to_string(&manifest)?)?;
    ensure!(
        ["dev", "release"]
            .iter()
            .all(|profile| recipe["profile"][profile]["panic"] == "unwind"),
        "node profiles must use the common unwind runtime"
    );
    let directory = output.join("node");
    fs::create_dir_all(&directory)?;
    let mut env = environment(&base_env, &directory)?;
    let features = if options.node_qualification {
        vec!["protocol-qualification".into()]
    } else {
        vec![]
    };
    let args = &options.build;
    let data = metadata(
        &manifest,
        Some(&args.target),
        &env,
        args.offline,
        &features,
        &root,
    )?;
    node_dependencies(&root, &data, &root)?;
    let mut definitions = DefinitionInputs {
        node: metadata(&manifest, None, &env, args.offline, &features, &root)?,
        node_lock: lockfile(&manifest)?,
        consensus: BTreeMap::new(),
    };
    if managed {
        for (label, recipe) in &engines {
            let manifest = root
                .join("protocol-bundles")
                .join(&recipe.directory)
                .join("Cargo.toml");
            definitions.consensus.insert(
                label.clone(),
                (
                    metadata(&manifest, None, &env, args.offline, &[], &root)?,
                    lockfile(&manifest)?,
                ),
            );
        }
    }
    let coordinator = definitions.verify(&root, managed)?;
    let source_metadata = serde_json::from_value(data.clone())?;
    let sources = source_inputs(&root, &source_metadata, GraphKind::Node, None, &cargo_home)?;
    let lock = manifest.with_file_name("Cargo.lock");
    let lock_hash = sha256(&lock)?;
    write_json(&directory.join("metadata.json"), &data)?;
    write_json(&directory.join("source-inputs.json"), &sources)?;
    verify_graphs(&root, &graphs, &recipes)?;
    verify_graphs(&root, &consensus, &engines)?;
    let inputs = node_link_inputs(&graphs, &consensus, &root)?;
    let audited = inputs["audited"]
        .as_array()
        .context("invalid audited graphs")?;
    let libraries = inputs["libraries"]
        .as_array()
        .context("invalid link libraries")?;
    let audit = symbol_audit(serde_json::from_value(
        json!({"operation":"inputs","working_directory":root,"graphs":audited}),
    )?)?;
    write_audit(&directory.join("input-ownership.json"), &audit["inventory"])?;
    let linker_hash = sha256(&linker_wrapper)?;
    let compiler = Path::new(env.get("RUSTC").context("missing pinned RUSTC")?);
    let spec = link_spec(
        &directory,
        &options,
        compiler,
        &sources,
        &lock_hash,
        libraries,
        &graphs,
        &coordinator,
        &linker_wrapper,
        &features,
    )?;
    let spec_path = directory.join("link-spec.json");
    write_json(&spec_path, &spec)?;
    let wrapper_hash = sha256(&node_wrapper)?;
    // Cargo cannot see external --extern inputs. Key only the node wrapper by its link specification.
    let wrapper = directory.join(format!(
        "rustc-wrapper-{}-{wrapper_hash}",
        fingerprint(&spec)?
    ));
    fs::copy(&node_wrapper, &wrapper)?;
    fs::set_permissions(&wrapper, fs::Permissions::from_mode(0o755))?;
    env.insert(
        "RUSTC_WORKSPACE_WRAPPER".into(),
        wrapper.to_str().context("non-UTF-8 wrapper path")?.into(),
    );
    env.insert(
        "KONTOR_NODE_LINK_SPEC".into(),
        spec_path
            .to_str()
            .context("non-UTF-8 specification path")?
            .into(),
    );
    let mut command = vec![
        "cargo".into(),
        "build".into(),
        "--locked".into(),
        "--manifest-path".into(),
        manifest.to_str().context("non-UTF-8 manifest")?.into(),
        "--bin".into(),
        "kontor".into(),
        "--target".into(),
        args.target.clone(),
        "--profile".into(),
        args.profile.clone(),
        "-j".into(),
        args.jobs.to_string(),
        "--message-format=json-render-diagnostics".into(),
    ];
    if args.offline {
        command.push("--offline".into());
    }
    if options.node_qualification {
        command.extend(["--features".into(), "protocol-qualification".into()]);
    }
    let log = directory.join("build.log");
    run_logged(&command, &root, &env, &log)?;
    let executable = node_executable(&log)?;
    completed_link(&directory, &spec_path, &executable)?;
    let artifacts = current_artifacts(&log, &directory.join("target"), &args.target, "indexer")?;
    let objects = node_codegen_objects(&directory.join("root-objects.json"), &spec_path, &root)?;
    let mut node_inputs: BTreeSet<PathBuf> = serde_json::from_value(artifacts["archives"].clone())?;
    node_inputs.extend(objects.iter().cloned());
    for script in artifacts["native_outputs"]
        .as_array()
        .context("invalid native outputs")?
    {
        let mut archives = Vec::new();
        native_archives(Path::new(text(script, "out_dir")?), &mut archives)?;
        node_inputs.extend(archives);
    }
    let shared = shared_ownership(serde_json::from_value(
        json!({"operation":"verify","working_directory":root,"graphs":audited,"sets":audit["sets"],"host_objects":[],"executable":executable,"env":env,"kind":"executor","node_objects":node_inputs,"compiler_objects":objects}),
    )?)?;
    write_audit(
        &directory.join("common-reference-ownership.json"),
        &shared["report"],
    )?;
    if !shared["node_report"].is_null() {
        write_audit(
            &directory.join("node-input-ownership.json"),
            &shared["node_report"],
        )?;
    }
    let final_audit = symbol_audit(serde_json::from_value(
        json!({"operation":"final","working_directory":root,"executable":executable,"graphs":audited,"sets":audit["sets"],"versions":audit["versions"],"common":shared["common"],"kind":"executor","node":shared["node"]}),
    )?)?;
    if !final_audit["local_inventory"].is_null() {
        write_audit(
            &directory.join("input-local-ownership.json"),
            &final_audit["local_inventory"],
        )?;
    }
    write_audit(
        &directory.join("final-ownership.json"),
        &final_audit["attributed"],
    )?;
    let libraries = runtime_libraries(
        &root,
        &executable,
        &env,
        &serde_json::from_value::<Vec<_>>(json!(audited))?,
    )?;
    ensure!(
        sha256(&lock)? == lock_hash
            && source_inputs(&root, &source_metadata, GraphKind::Node, None, &cargo_home)?
                == sources,
        "node source or lock changed during compilation"
    );
    ensure!(
        metadata(
            &manifest,
            Some(&args.target),
            &env,
            args.offline,
            &features,
            &root
        )? == data,
        "node dependency metadata changed during compilation"
    );
    ensure!(
        definitions.verify(&root, managed)? == coordinator,
        "coordinator definition changed during compilation"
    );
    ensure!(
        sha256(&wrapper)? == wrapper_hash,
        "node compiler wrapper changed during compilation"
    );
    ensure!(
        sha256(&linker_wrapper)? == linker_hash,
        "node linker wrapper changed during compilation"
    );
    verify_graphs(&root, &graphs, &recipes)?;
    verify_graphs(&root, &consensus, &engines)?;
    let proc_macros: Vec<PathBuf> = serde_json::from_value(artifacts["proc_macros"].clone())?;
    let plugins = proc_macros
        .iter()
        .map(|path| Ok(json!({"path":path,"sha256":sha256(path)?})))
        .collect::<Result<Vec<_>>>()?;
    let mut ownership = serde_json::Map::new();
    for name in [
        "common-reference-ownership.json",
        "node-input-ownership.json",
        "input-ownership.json",
        "input-local-ownership.json",
        "final-ownership.json",
    ] {
        ownership.insert(name.into(), json!(sha256(&directory.join(name))?));
    }
    let mut result = json!({"coordinator_definition":coordinator,"qualification_command":options.node_qualification,"executable":executable,"executable_sha256":sha256(&executable)?,
        "source_inputs_sha256":fingerprint(&sources)?,"lock_sha256":lock_hash,"link_spec_sha256":sha256(&spec_path)?,"build_log_sha256":sha256(&log)?,
        "root_codegen_sha256":sha256(&directory.join("root-objects.json"))?,"wrapper_sha256":sha256(&root.join("core/kontor-build/src/bin/kontor-node-rustc.rs"))?,
        "wrapper":wrapper,"wrapper_binary_sha256":wrapper_hash,"linker_record_sha256":sha256(&directory.join("linker-record.json"))?,
        "linker_wrapper_sha256":linker_source_hash(&root)?,"linker_wrapper_binary_sha256":linker_hash,"native_helpers":final_audit["result"],
        "runtime_libraries":libraries,"compiler_proc_macros":plugins,"ownership":ownership,"status":"node linked and native ownership checked; execution qualification required"});
    if options.node_qualification {
        result["interface_checks"] =
            verify_interfaces(&graphs, &args.target, &env, &directory, &root)?;
        if managed {
            let controls = directory.join("consensus");
            fs::create_dir_all(&controls)?;
            result["consensus_interface_checks"] =
                verify_interfaces(&consensus, &args.target, &env, &controls, &root)?;
            result["consensus_adapter_checks"] =
                verify_adapter(&root, &consensus, &args.target, &env, &controls, &root)?;
        }
    }
    write_json(&directory.join("build-inputs.json"), &result)?;
    Ok(result)
}
#[cfg(test)]
mod tests;
