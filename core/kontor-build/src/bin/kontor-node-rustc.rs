// This separate executable keeps unrelated CLI edits out of the node compiler cache key.
use std::env;
use std::ffi::{OsStr, OsString};
use std::fs;
use std::io::ErrorKind;
use std::path::{Path, PathBuf, absolute};
use std::process::{self, Command, ExitStatus};

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

use anyhow::{Context, Result, bail, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

#[derive(Deserialize)]
struct Graph {
    #[serde(default = "executor_role")]
    role: String,
    graph: String,
    facade: PathBuf,
    facade_sha256: String,
    link_inputs: PathBuf,
    build_inputs_sha256: Option<String>,
}

fn executor_role() -> String {
    "executor".into()
}

#[derive(Deserialize)]
struct Spec {
    compiler: PathBuf,
    graphs: Vec<Graph>,
    link_set: Option<String>,
    #[serde(default)]
    features: Vec<String>,
    attestation: Option<Value>,
    linker_wrapper: Option<PathBuf>,
    linker_wrapper_sha256: Option<String>,
    linker_record: Option<PathBuf>,
    root_objects: Option<PathBuf>,
}

#[derive(Debug)]
struct Capture {
    directory: PathBuf,
    stem: OsString,
}

fn digest(path: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(fs::read(path)?)))
}

fn option<'a>(arguments: &'a [OsString], name: &str) -> Result<Option<&'a OsStr>> {
    arguments
        .iter()
        .position(|arg| arg == name)
        .map(|index| {
            arguments
                .get(index + 1)
                .map(OsString::as_os_str)
                .context(format!("missing {name} argument"))
        })
        .transpose()
}

fn codegen_options(arguments: &[OsString]) -> Result<Vec<&OsStr>> {
    let mut options = Vec::new();
    let mut index = 0;
    while index < arguments.len() {
        let argument = &arguments[index];
        if argument == "-C" {
            index += 1;
            options.push(
                arguments
                    .get(index)
                    .context("missing -C argument")?
                    .as_os_str(),
            );
        } else if let Some(value) = argument.to_str().and_then(|arg| arg.strip_prefix("-C")) {
            options.push(OsStr::new(value));
        }
        index += 1;
    }
    Ok(options)
}

fn prepare(compiler: &Path, arguments: &mut Vec<OsString>, spec: &Spec) -> Result<Option<Capture>> {
    ensure!(
        compiler.canonicalize()? == spec.compiler.canonicalize()?,
        "node wrapper requires the pinned compiler"
    );
    let name = option(arguments, "--crate-name")?;
    if name != Some(OsStr::new("indexer")) && name != Some(OsStr::new("kontor")) {
        return Ok(None);
    }
    let binary = name == Some(OsStr::new("kontor"));
    let selected: Vec<_> = spec
        .graphs
        .iter()
        .map(|graph| (graph.role.as_str(), graph.graph.as_str()))
        .collect();
    if let Some(link_set) = spec.link_set.as_deref() {
        let expected = match link_set {
            "legacy-qualification" => vec![("executor", "first"), ("executor", "second")],
            "production-node" => vec![("executor", "first"), ("consensus", "first")],
            "managed-node" => vec![
                ("executor", "first"),
                ("executor", "observer"),
                ("consensus", "first"),
            ],
            _ => bail!("unknown node link set"),
        };
        ensure!(
            selected == expected,
            "node link set does not match its independent libraries"
        );
    }
    ensure!(
        selected
            .iter()
            .all(|(role, _)| matches!(*role, "executor" | "consensus")),
        "unknown independent library role"
    );
    if matches!(
        spec.link_set.as_deref(),
        Some("production-node" | "managed-node")
    ) {
        arguments.extend([
            "--cfg".into(),
            "kontor_managed".into(),
            "--cfg".into(),
            "kontor_consensus_runtime".into(),
        ]);
        let qualification = spec
            .features
            .iter()
            .any(|feature| feature == "protocol-qualification");
        ensure!(
            qualification == (spec.link_set.as_deref() == Some("managed-node")),
            "qualification feature differs from link set"
        );
        if qualification {
            arguments.extend(["--cfg".into(), "kontor_observer".into()]);
        }
    }
    for graph in &spec.graphs {
        ensure!(
            digest(&graph.facade)? == graph.facade_sha256,
            "retained facade changed before node compilation"
        );
        let mut dependency = OsString::from("dependency=");
        dependency.push(&graph.link_inputs);
        arguments.extend(["-L".into(), dependency]);
        if !binary {
            let mut external = OsString::from(format!("kontor_{}_{}=", graph.role, graph.graph));
            external.push(&graph.facade);
            arguments.extend(["--extern".into(), external]);
        }
    }
    if !binary {
        return Ok(None);
    }
    let directory =
        PathBuf::from(option(arguments, "--out-dir")?.context("missing node output directory")?);
    let mut stem = OsString::from("kontor");
    let options = codegen_options(arguments)?;
    let extra = options
        .iter()
        .rev()
        .find_map(|arg| {
            arg.to_str()
                .and_then(|arg| arg.strip_prefix("extra-filename="))
        })
        .context("missing node codegen artifact identity")?;
    stem.push(extra);
    arguments.push("-Csave-temps".into());
    Ok(Some(Capture { directory, stem }))
}

fn attestation(arguments: &[OsString], spec: &Spec) -> Result<Option<(String, String)>> {
    if !matches!(
        spec.link_set.as_deref(),
        Some("production-node" | "managed-node")
    ) {
        return Ok(None);
    }
    let record = spec
        .attestation
        .as_ref()
        .context("managed node requires its builder attestation")?;
    let graphs = record["graphs"]
        .as_array()
        .context("managed node requires its builder attestation")?;
    ensure!(
        record["schema"] == 1
            && record["link_set"].as_str() == spec.link_set.as_deref()
            && graphs.len()
                == if spec.link_set.as_deref() == Some("managed-node") {
                    3
                } else {
                    2
                }
            && spec.graphs.len() == graphs.len(),
        "managed node requires its builder attestation"
    );
    for (actual, library) in graphs.iter().zip(&spec.graphs) {
        ensure!(
            library.build_inputs_sha256.is_some()
                && actual["role"] == library.role
                && actual["graph"] == library.graph
                && actual["facade_sha256"] == library.facade_sha256
                && actual["build_inputs_sha256"].as_str() == library.build_inputs_sha256.as_deref(),
            "builder attestation differs from linked input"
        );
    }
    let target = record["target"]
        .as_str()
        .context("missing builder attestation target")?;
    ensure!(
        option(arguments, "--target")? == Some(OsStr::new(target)),
        "builder attestation target differs from compiler target"
    );
    // serde_json's default map is ordered, preserving canonical sorted-key attestation JSON.
    Ok(Some((serde_json::to_string(record)?, target.into())))
}

fn linker_driver(arguments: &[OsString]) -> Result<OsString> {
    Ok(codegen_options(arguments)?
        .iter()
        .rev()
        .find_map(|arg| {
            arg.to_str()
                .and_then(|arg| arg.strip_prefix("linker="))
                .map(OsString::from)
        })
        .unwrap_or_else(|| "cc".into()))
}

fn objects(capture: &Capture) -> Result<Vec<PathBuf>> {
    let mut prefix = capture.stem.clone();
    prefix.push(".");
    let mut paths = Vec::new();
    for entry in fs::read_dir(&capture.directory)? {
        let entry = entry?;
        let name = entry.file_name();
        if name
            .as_encoded_bytes()
            .starts_with(prefix.as_encoded_bytes())
            && name.as_encoded_bytes().ends_with(b".rcgu.o")
        {
            paths.push(entry.path());
        }
    }
    paths.sort();
    Ok(paths)
}

fn remove_if_present(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn exit_code(status: ExitStatus) -> i32 {
    #[cfg(unix)]
    if let Some(signal) = status.signal() {
        return 128 + signal;
    }
    status.code().unwrap_or(1)
}

fn run() -> Result<i32> {
    let spec_path = PathBuf::from(
        env::var_os("KONTOR_NODE_LINK_SPEC").context("missing node link specification")?,
    );
    let spec_bytes = fs::read(&spec_path)?;
    let spec_hash = hex::encode(Sha256::digest(&spec_bytes));
    let spec: Spec = serde_json::from_slice(&spec_bytes)?;
    let mut original: Vec<_> = env::args_os().skip(1).collect();
    ensure!(!original.is_empty(), "node wrapper requires a compiler");
    let compiler = PathBuf::from(original.remove(0));
    let mut arguments = original.clone();
    let capture = prepare(&compiler, &mut arguments, &spec)?;
    // Captured node evidence is JSON text. Fail before compilation instead of
    // silently dropping an option or discovering an unrecordable invocation later.
    if capture.is_some() {
        ensure!(
            arguments.iter().all(|arg| arg.to_str().is_some()),
            "node evidence requires UTF-8 compiler arguments"
        );
    }
    let mut command = Command::new(&compiler);
    command
        .env_remove("KONTOR_NODE_ATTESTATION")
        .env_remove("KONTOR_NODE_TARGET");
    if matches!(
        option(&original, "--crate-name")?.and_then(OsStr::to_str),
        Some("indexer" | "kontor")
    ) && let Some((record, target)) = attestation(&original, &spec)?
    {
        command
            .env("KONTOR_NODE_ATTESTATION", record)
            .env("KONTOR_NODE_TARGET", target);
    }
    if let Some(capture) = &capture {
        for path in objects(capture)? {
            fs::remove_file(path)?;
        }
        let wrapper = spec
            .linker_wrapper
            .as_ref()
            .context("missing linker wrapper")?;
        ensure!(
            Some(digest(wrapper)?.as_str()) == spec.linker_wrapper_sha256.as_deref(),
            "linker wrapper changed before invocation"
        );
        command.env("KONTOR_REAL_LINKER", linker_driver(&arguments)?);
        remove_if_present(
            spec.linker_record
                .as_deref()
                .context("missing linker record path")?,
        )?;
        remove_if_present(
            spec.root_objects
                .as_deref()
                .context("missing root objects path")?,
        )?;
        let mut linker = OsString::from("linker=");
        linker.push(wrapper);
        arguments.extend(["-C".into(), linker]);
    }
    // Command preserves inheritable Cargo jobserver descriptors. Waiting is necessary
    // to bind the completed compiler output, including Darwin post-link stripping.
    let status = command.args(&arguments).status()?;
    if !status.success() {
        return Ok(exit_code(status));
    }
    if let Some(capture) = &capture {
        let record_path = spec
            .linker_record
            .as_ref()
            .context("missing linker record")?;
        let record: Value = serde_json::from_slice(&fs::read(record_path)?)?;
        let output = absolute(&capture.directory)?.join(&capture.stem);
        ensure!(
            digest(&spec_path)? == spec_hash
                && record["spec_sha256"] == spec_hash
                && record["output"] == json!(output),
            "node compiler and linker output identity disagree"
        );
        let compiler_output = json!({"path": output, "sha256": digest(&output)?});
        let objects = objects(capture)?
            .into_iter()
            .map(|path| Ok(json!({"sha256": digest(&path)?, "path": path})))
            .collect::<Result<Vec<_>>>()?;
        ensure!(
            !objects.is_empty(),
            "node compiler did not retain codegen objects"
        );
        let arguments = arguments
            .iter()
            .map(|arg| {
                arg.to_str()
                    .context("node evidence requires UTF-8 compiler arguments")
            })
            .collect::<Result<Vec<_>>>()?;
        let record = json!({"spec_sha256": spec_hash, "objects": objects, "compiler": compiler,
            "arguments": arguments, "working_directory": env::current_dir()?,
            "linker_record_sha256": digest(record_path)?, "compiler_output": compiler_output});
        fs::write(
            spec.root_objects
                .as_ref()
                .context("missing root objects path")?,
            format!("{record}\n"),
        )?;
    }
    Ok(0)
}

fn main() -> Result<()> {
    let status = run()?;
    if status != 0 {
        process::exit(status);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::{TempDir, tempdir};

    fn fixture() -> Result<(TempDir, Value)> {
        let directory = tempdir()?;
        let compiler = env::current_exe()?;
        let facade = directory.path().join("retained.rlib");
        fs::write(&facade, b"compiled retained graph")?;
        let spec = json!({"compiler": compiler, "graphs": [{"graph": "first", "facade": facade,
            "facade_sha256": digest(&facade)?, "link_inputs": directory.path(), "build_inputs_sha256": "abc"}]});
        Ok((directory, spec))
    }

    fn arguments(name: &str, root: &Path) -> Vec<OsString> {
        vec![
            "--crate-name".into(),
            name.into(),
            "--out-dir".into(),
            root.as_os_str().into(),
            "-C".into(),
            "extra-filename=-abcd".into(),
        ]
    }

    #[test]
    fn library_binary_and_probe_paths_and_facade_rejection() -> Result<()> {
        let (directory, value) = fixture()?;
        let spec: Spec = serde_json::from_value(value)?;
        for name in ["indexer", "kontor"] {
            let mut args = arguments(name, directory.path());
            let capture = prepare(&spec.compiler, &mut args, &spec)?;
            assert!(
                args.iter()
                    .any(|arg| arg.as_encoded_bytes().starts_with(b"dependency="))
            );
            assert_eq!(args.contains(&"--extern".into()), name == "indexer");
            assert_eq!(capture.is_some(), name == "kontor");
            if let Some(capture) = capture {
                assert_eq!(capture.stem, "kontor-abcd");
                assert!(args.contains(&"-Csave-temps".into()));
            }
        }
        for mut args in [
            vec!["-vV".into()],
            vec!["--crate-name".into(), "build_script_build".into()],
        ] {
            let original = args.clone();
            assert!(prepare(&spec.compiler, &mut args, &spec)?.is_none());
            assert_eq!(args, original);
        }
        fs::write(&spec.graphs[0].facade, "modified")?;
        assert!(
            prepare(
                &spec.compiler,
                &mut arguments("indexer", directory.path()),
                &spec
            )
            .unwrap_err()
            .to_string()
            .contains("facade changed")
        );
        let wrong = directory.path().join("different compiler");
        fs::write(&wrong, "another compiler")?;
        assert!(
            prepare(&wrong, &mut vec![], &spec)
                .unwrap_err()
                .to_string()
                .contains("pinned compiler")
        );
        Ok(())
    }

    #[test]
    fn supported_link_sets_require_exact_roles_and_order() -> Result<()> {
        let (directory, mut value) = fixture()?;
        let prototype = value["graphs"][0].clone();
        for (link_set, roles) in [
            (
                "production-node",
                vec![("executor", "first"), ("consensus", "first")],
            ),
            (
                "managed-node",
                vec![
                    ("executor", "first"),
                    ("executor", "observer"),
                    ("consensus", "first"),
                ],
            ),
            (
                "legacy-qualification",
                vec![("executor", "first"), ("executor", "second")],
            ),
        ] {
            value["link_set"] = json!(link_set);
            value["features"] = if link_set == "managed-node" {
                json!(["protocol-qualification"])
            } else {
                json!([])
            };
            value["graphs"] = roles
                .iter()
                .map(|(role, graph)| {
                    let mut entry = prototype.clone();
                    entry["role"] = json!(role);
                    entry["graph"] = json!(graph);
                    entry
                })
                .collect();
            let spec: Spec = serde_json::from_value(value.clone())?;
            let mut args = arguments("indexer", directory.path());
            prepare(&spec.compiler, &mut args, &spec)?;
            assert_eq!(
                args.iter().filter(|arg| *arg == "--extern").count(),
                roles.len()
            );
            assert_eq!(
                args.contains(&"kontor_managed".into()),
                link_set != "legacy-qualification"
            );
            assert_eq!(
                args.contains(&"kontor_consensus_runtime".into()),
                link_set != "legacy-qualification"
            );
            assert_eq!(
                args.contains(&"kontor_observer".into()),
                link_set == "managed-node"
            );
            for index in 0..roles.len() {
                for mutation in ["missing", "role", "graph", "extra"] {
                    let mut changed = value.clone();
                    match mutation {
                        "missing" => {
                            changed["graphs"].as_array_mut().unwrap().remove(index);
                        }
                        "extra" => changed["graphs"]
                            .as_array_mut()
                            .unwrap()
                            .push(prototype.clone()),
                        key => changed["graphs"][index][key] = json!("wrong"),
                    }
                    let spec: Spec = serde_json::from_value(changed)?;
                    assert!(
                        prepare(
                            &spec.compiler,
                            &mut arguments("indexer", directory.path()),
                            &spec
                        )
                        .is_err()
                    );
                }
            }
        }
        value["link_set"] = json!("k4-node");
        let spec: Spec = serde_json::from_value(value)?;
        assert!(
            prepare(
                &spec.compiler,
                &mut arguments("indexer", directory.path()),
                &spec
            )
            .unwrap_err()
            .to_string()
            .contains("unknown node link set")
        );
        Ok(())
    }

    #[test]
    fn attestation_binds_target_and_every_linked_identity_field() -> Result<()> {
        let (_directory, mut value) = fixture()?;
        let prototype = value["graphs"][0].clone();
        value["link_set"] = json!("managed-node");
        value["graphs"] = [
            ("executor", "first"),
            ("executor", "observer"),
            ("consensus", "first"),
        ]
        .iter()
        .map(|(role, graph)| {
            let mut entry = prototype.clone();
            entry["role"] = json!(role);
            entry["graph"] = json!(graph);
            entry
        })
        .collect();
        let args = vec!["--target".into(), "aarch64-unknown-linux-gnu".into()];
        assert!(attestation(&args, &serde_json::from_value(value.clone())?).is_err());
        value["attestation"] = json!({"schema":1,"link_set":"managed-node","target":"aarch64-unknown-linux-gnu","graphs":value["graphs"]});
        let spec: Spec = serde_json::from_value(value.clone())?;
        let (record, target) = attestation(&args, &spec)?.unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(&record)?,
            value["attestation"]
        );
        assert_eq!(target, "aarch64-unknown-linux-gnu");
        assert!(attestation(&["--target".into(), "another".into()], &spec).is_err());
        for index in 0..3 {
            for field in ["role", "graph", "facade_sha256", "build_inputs_sha256"] {
                let mut changed = value.clone();
                changed["attestation"]["graphs"][index][field] = json!("wrong");
                assert!(attestation(&args, &serde_json::from_value(changed)?).is_err());
            }
        }
        Ok(())
    }

    #[test]
    fn linker_override_and_codegen_object_selection() -> Result<()> {
        assert_eq!(linker_driver(&[])?, "cc");
        assert_eq!(
            linker_driver(&["-Clinker=first".into(), "-C".into(), "linker=last".into()])?,
            "last"
        );
        assert!(linker_driver(&["-C".into()]).is_err());
        let directory = tempdir()?;
        for name in [
            "kontor-test.1.rcgu.o",
            "kontor-test.2.rcgu.o",
            "kontor-test-other.1.rcgu.o",
            "unrelated.rcgu.o",
        ] {
            fs::write(directory.path().join(name), "object")?;
        }
        let capture = Capture {
            directory: directory.path().into(),
            stem: "kontor-test".into(),
        };
        assert_eq!(objects(&capture)?.len(), 2);
        Ok(())
    }
}
