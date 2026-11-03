use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::Builder;

use crate::canonical_json::{Style, encode};
use crate::container::sha256;
use crate::execution_definition::resolve;

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing or invalid {key}"))
}
fn array<'a>(value: &'a Value, key: &str) -> Result<&'a [Value]> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(Vec::as_slice)
        .with_context(|| format!("missing or invalid {key}"))
}
fn checked_path(value: &Value, path_key: &str, cwd: &Path, message: &str) -> Result<PathBuf> {
    let path = PathBuf::from(text(value, path_key)?);
    ensure!(
        sha256(&cwd.join(&path))? == text(value, "sha256")?,
        "{message}"
    );
    Ok(path)
}
pub fn verify_staged_inputs(graph: &Value, cwd: &Path) -> Result<()> {
    ensure!(
        sha256(&cwd.join(text(graph, "wrapper")?))? == text(graph, "wrapper_binary_sha256")?,
        "staged compiler wrapper changed"
    );
    for field in ["artifacts", "native_artifacts"] {
        for item in array(graph, field)? {
            checked_path(item, "path", cwd, "staged compiler input changed")?;
        }
    }
    for item in array(graph, "compiler_proc_macros")? {
        checked_path(item, "staged", cwd, "staged compiler plugin changed")?;
    }
    Ok(())
}
pub fn node_dependencies(root: &Path, data: &Value, cwd: &Path) -> Result<()> {
    let root = root.canonicalize()?;
    for package in array(data, "packages")? {
        let name = text(package, "name")?;
        ensure!(
            !["wasmtime", "kontor-executor-", "kontor-consensus-"]
                .iter()
                .any(|prefix| name.starts_with(prefix)),
            "node Cargo graph contains a retained execution implementation"
        );
        if ["blst", "secp256k1-sys", "ring", "psm", "wit-bindgen"].contains(&name) {
            let manifest = cwd.join(text(package, "manifest_path")?);
            ensure!(
                resolve(manifest.parent().context("invalid native manifest")?)?
                    == root.join("core/vendor").join(name),
                "node is missing native patch for {name}"
            );
        }
    }
    Ok(())
}
pub fn node_executable(log: &Path) -> Result<PathBuf> {
    let mut executables = BTreeSet::new();
    for line in fs::read_to_string(log)?.lines() {
        let Ok(value) = serde_json::from_str::<Value>(line) else {
            continue;
        };
        if value["reason"] == "compiler-artifact"
            && value["target"]["name"] == "kontor"
            && array(&value["target"], "kind")?
                .iter()
                .any(|kind| kind == "bin")
            && let Some(path) = value["executable"].as_str().filter(|path| !path.is_empty())
        {
            executables.insert(PathBuf::from(path));
        }
    }
    ensure!(
        executables.len() == 1,
        "missing or ambiguous current node executable"
    );
    Ok(executables.pop_first().unwrap())
}
pub fn node_codegen_objects(record: &Path, spec: &Path, cwd: &Path) -> Result<Vec<PathBuf>> {
    let record: Value = serde_json::from_slice(&fs::read(record)?)?;
    let objects = array(&record, "objects")?;
    ensure!(
        text(&record, "spec_sha256")? == sha256(spec)? && !objects.is_empty(),
        "node codegen objects do not match this link specification"
    );
    objects
        .iter()
        .map(|item| {
            checked_path(
                item,
                "path",
                cwd,
                "node codegen object changed after compilation",
            )
        })
        .collect()
}
pub fn node_link_inputs(graphs: &[Value], consensus: &[Value], cwd: &Path) -> Result<Value> {
    let mut audited = Vec::new();
    let mut libraries = Vec::new();
    for (role, reports) in [("executor", graphs), ("consensus", consensus)] {
        for report in reports {
            let name = text(report, "graph")?;
            let mut audit = report.clone();
            // Audit ownership spans roles, but build provenance keeps its original graph label.
            if !consensus.is_empty() {
                audit["graph"] = json!(format!("{role}-{name}"));
            }
            audited.push(audit);
            libraries.push(json!({"role":role,"graph":name,"facade":text(report,"facade")?,
                "facade_sha256":sha256(&cwd.join(text(report,"facade")?))?,
                "link_inputs":text(report,"link_inputs")?,
                "build_inputs_sha256":hex::encode(Sha256::digest(encode(report,Style::Compact)?.as_bytes()))}));
        }
    }
    Ok(json!({"audited":audited,"libraries":libraries}))
}
pub fn install_node(node: &Value, destination: &Path, cwd: &Path) -> Result<Value> {
    let source = cwd.join(text(node, "executable")?);
    let destination = cwd.join(destination);
    ensure!(
        resolve(&source)? != resolve(&destination)?,
        "installation must not overwrite the audited build output"
    );
    let parent = destination.parent().context("invalid installation path")?;
    fs::create_dir_all(parent)?;
    let temporary = Builder::new().prefix(".kontor-").tempfile_in(parent)?;
    fs::copy(source, temporary.path())?;
    let digest = text(node, "executable_sha256")?;
    ensure!(
        sha256(temporary.path())? == digest,
        "node executable changed after its ownership audit"
    );
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o755))?;
    temporary
        .persist(&destination)
        .context("install audited executable")?;
    Ok(json!({"path":destination,"sha256":digest}))
}
fn native_archives(directory: &Path, paths: &mut Vec<PathBuf>) -> Result<()> {
    if !directory.is_dir() {
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let kind = entry.file_type()?;
        if entry
            .path()
            .extension()
            .is_some_and(|extension| extension == "a")
        {
            paths.push(entry.path());
        }
        if kind.is_dir() {
            native_archives(&entry.path(), paths)?;
        }
    }
    Ok(())
}
pub fn stage_artifacts(
    output: &Path,
    artifacts: &Value,
    namespace: &str,
    cwd: &Path,
) -> Result<Value> {
    let inputs = output.join("link-inputs");
    let absolute_inputs = cwd.join(&inputs);
    if absolute_inputs.exists() {
        fs::remove_dir_all(&absolute_inputs)?;
    }
    fs::create_dir_all(&absolute_inputs)?;
    let mut archives = Vec::new();
    for source in array(artifacts, "archives")? {
        let source = Path::new(source.as_str().context("invalid archive path")?);
        let path = inputs.join(source.file_name().context("missing archive name")?);
        fs::copy(cwd.join(source), cwd.join(&path))?;
        archives.push(json!({"path":path,"source_path":source,"sha256":sha256(&cwd.join(&path))?}));
    }
    let mut native = Vec::new();
    for (index, script) in array(artifacts, "native_outputs")?.iter().enumerate() {
        let directory = Path::new(text(script, "out_dir")?);
        let mut paths = Vec::new();
        // Match Cargo's archive inventory without following symlinked directories.
        native_archives(&cwd.join(directory), &mut paths)?;
        paths.sort();
        for absolute in paths {
            let source = directory.join(absolute.strip_prefix(cwd.join(directory))?);
            let path = inputs
                .join("native")
                .join(index.to_string())
                .join(source.file_name().context("missing archive name")?);
            fs::create_dir_all(cwd.join(&path).parent().unwrap())?;
            fs::copy(&absolute, cwd.join(&path))?;
            native
                .push(json!({"path":path,"source_path":source,"sha256":sha256(&cwd.join(&path))?}));
        }
    }
    let mut macros = Vec::new();
    for artifact in array(artifacts, "proc_macros")? {
        let source = Path::new(artifact.as_str().context("invalid proc-macro path")?);
        let name = source
            .file_name()
            .and_then(|name| name.to_str())
            .context("invalid proc-macro name")?;
        let (prefix, suffix) = name
            .rsplit_once('-')
            .context("missing proc-macro disambiguator")?;
        let staged = inputs.join(format!("{prefix}-{namespace}-{suffix}"));
        fs::copy(cwd.join(source), cwd.join(&staged))?;
        macros.push(json!({"path":source,"staged":staged,"sha256":sha256(&cwd.join(source))?}));
    }
    let facade = Path::new(text(artifacts, "facade")?)
        .file_name()
        .context("missing facade name")?;
    Ok(
        json!({"artifacts":archives,"native_artifacts":native,"compiler_proc_macros":macros,"facade":inputs.join(facade),"link_inputs":inputs}),
    )
}
#[derive(Deserialize)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum Request {
    VerifyStaged {
        graph: Value,
        cwd: PathBuf,
    },
    NodeDependencies {
        root: PathBuf,
        data: Value,
        cwd: PathBuf,
    },
    NodeExecutable {
        log: PathBuf,
    },
    NodeCodegen {
        record: PathBuf,
        spec: PathBuf,
        cwd: PathBuf,
    },
    NodeLinkInputs {
        graphs: Vec<Value>,
        consensus: Vec<Value>,
        cwd: PathBuf,
    },
    InstallNode {
        node: Value,
        destination: PathBuf,
        cwd: PathBuf,
    },
    Stage {
        output: PathBuf,
        artifacts: Value,
        namespace: String,
        cwd: PathBuf,
    },
}
pub fn run(request: Request) -> Result<Value> {
    match request {
        Request::VerifyStaged { graph, cwd } => {
            verify_staged_inputs(&graph, &cwd)?;
            Ok(Value::Null)
        }
        Request::NodeDependencies { root, data, cwd } => {
            node_dependencies(&root, &data, &cwd)?;
            Ok(Value::Null)
        }
        Request::NodeExecutable { log } => Ok(json!(node_executable(&log)?)),
        Request::NodeCodegen { record, spec, cwd } => {
            Ok(json!(node_codegen_objects(&record, &spec, &cwd)?))
        }
        Request::NodeLinkInputs {
            graphs,
            consensus,
            cwd,
        } => node_link_inputs(&graphs, &consensus, &cwd),
        Request::InstallNode {
            node,
            destination,
            cwd,
        } => install_node(&node, &destination, &cwd),
        Request::Stage {
            output,
            artifacts,
            namespace,
            cwd,
        } => stage_artifacts(&output, &artifacts, &namespace, &cwd),
    }
}
#[cfg(test)]
mod tests;
