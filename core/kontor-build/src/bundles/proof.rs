use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use tempfile::Builder;

use crate::build_artifacts::verify_staged_inputs;
use crate::canonical_json::{Style, encode};
use crate::container::sha256;
use crate::graph_build::{Options, run_logged};
use crate::metadata_control::proc_macro_hashes;
use crate::recipes::{proof_graphs, verify_engine_observations, verify_identity};
use crate::shared_ownership::run as shared_ownership;
use crate::symbol_audit::run as symbol_audit;
use crate::toolchain::{Environment, runtime_libraries};

fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .with_context(|| format!("missing {key}"))
}
fn write_audit(path: &Path, value: &Value) -> Result<()> {
    fs::write(path, format!("{}\n", encode(value, Style::Spaced)?))?;
    Ok(())
}
pub(super) fn audit_inputs(root: &Path, graphs: &[Value], output: &Path) -> Result<Value> {
    let audit = symbol_audit(serde_json::from_value(
        json!({"operation":"inputs","working_directory":root,"graphs":graphs}),
    )?)?;
    write_audit(&output.join("input-ownership.json"), &audit["inventory"])?;
    Ok(audit)
}
fn rejected(success: bool, stderr: &str, tokens: &[&str], message: &str) -> Result<()> {
    ensure!(
        !success && tokens.iter().all(|token| stderr.contains(token)),
        "{message}"
    );
    Ok(())
}
fn capture(
    arguments: &[String],
    root: &Path,
    env: &Environment,
    log: &Path,
) -> Result<(bool, String)> {
    let (program, args) = arguments.split_first().context("missing control command")?;
    let output = Command::new(program)
        .args(args)
        .current_dir(root)
        .env_clear()
        .envs(env)
        .output()?;
    let stdout = String::from_utf8(output.stdout)?
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    let stderr = String::from_utf8(output.stderr)?
        .replace("\r\n", "\n")
        .replace('\r', "\n");
    fs::write(log, format!("{stdout}{stderr}"))?;
    Ok((output.status.success(), stderr))
}
fn unified_resolution(root: &Path, env: &Environment, output: &Path) -> Result<()> {
    let temporary = Builder::new()
        .prefix("unified-negative-")
        .tempdir_in(output)?;
    let manifest = temporary.path().join("Cargo.toml");
    fs::write(
        &manifest,
        "[package]\nname = \"kontor-unified-negative\"\nversion = \"0.0.0\"\nedition = \"2024\"\n[workspace]\n[lib]\npath = \"lib.rs\"\n[dependencies]\nfirst = { package = \"itoa\", version = \"=1.0.14\" }\nsecond = { package = \"itoa\", version = \"=1.0.15\" }\n",
    )?;
    fs::write(temporary.path().join("lib.rs"), "")?;
    let (success, stderr) = capture(
        &[
            "cargo".into(),
            "metadata".into(),
            "--offline".into(),
            "--format-version=1".into(),
            "--manifest-path".into(),
            manifest.to_str().context("non-UTF-8 manifest")?.into(),
        ],
        root,
        env,
        &output.join("unified-resolution-rejected.log"),
    )?;
    rejected(
        success,
        &stderr,
        &[
            "failed to select a version",
            "itoa",
            "1.0.14",
            "1.0.15",
            "conflict",
        ],
        "unified Cargo graph did not reject the conflicting patch requirements",
    )
}
pub(super) fn qualify(
    root: &Path,
    graphs: &[Value],
    args: &Options,
    env: &Environment,
    output: &Path,
) -> Result<Value> {
    let recipes = proof_graphs();
    for graph in graphs {
        verify_identity(root, graph, &recipes)?;
        verify_staged_inputs(graph, root)?;
    }
    let audit = audit_inputs(root, graphs, output)?;
    let host = output.join("host");
    if host.exists() {
        fs::remove_dir_all(&host)?;
    }
    fs::create_dir(&host)?;
    let executable = host.join("protocol-bundle-proof");
    let options = vec![
        "--edition=2024".into(),
        "--target".into(),
        args.target.clone(),
        "-Cpanic=unwind".into(),
        "-Cmetadata=kontor_proof_host".into(),
        "-Cdebuginfo=1".into(),
        format!(
            "-Copt-level={}",
            if args.profile == "release" { 3 } else { 1 }
        ),
    ];
    let compiler = env.get("RUSTC").context("missing pinned RUSTC")?;
    let mut command = vec![compiler.clone()];
    command.extend(options.clone());
    command.extend([
        "-Ccodegen-units=1".into(),
        "-Csave-temps".into(),
        "--emit=link,obj".into(),
        root.join("protocol-bundles/proof/host.rs")
            .display()
            .to_string(),
    ]);
    for graph in graphs {
        command.extend([
            "--extern".into(),
            format!(
                "kontor_proof_{}={}",
                text(graph, "graph")?,
                text(graph, "facade")?
            ),
            "-L".into(),
            format!("dependency={}", text(graph, "link_inputs")?),
        ]);
    }
    command.extend(["-o".into(), executable.display().to_string()]);
    run_logged(&command, &host, env, &output.join("link.log"))?;
    let mut host_objects = fs::read_dir(&host)?
        .map(|entry| entry.map(|entry| entry.path()))
        .collect::<std::io::Result<Vec<_>>>()?;
    host_objects.retain(|path| {
        path.file_name()
            .is_some_and(|name| name.to_string_lossy().ends_with(".rcgu.o"))
    });
    host_objects.sort();
    let shared = shared_ownership(serde_json::from_value(
        json!({"operation":"verify","working_directory":root,"graphs":graphs,"sets":audit["sets"],"host_objects":host_objects,"executable":executable,"env":env,"kind":"proof","node_objects":[],"compiler_objects":[]}),
    )?)?;
    write_audit(
        &output.join("common-reference-ownership.json"),
        &shared["report"],
    )?;
    let final_audit = symbol_audit(serde_json::from_value(
        json!({"operation":"final","working_directory":root,"executable":executable,"graphs":graphs,"sets":audit["sets"],"versions":audit["versions"],"common":shared["common"],"kind":"proof","node":{}}),
    )?)?;
    if !final_audit["local_inventory"].is_null() {
        write_audit(
            &output.join("input-local-ownership.json"),
            &final_audit["local_inventory"],
        )?;
    }
    write_audit(
        &output.join("final-ownership.json"),
        &final_audit["attributed"],
    )?;
    let macros = proc_macro_hashes(
        &serde_json::from_value::<Vec<_>>(json!(graphs))?,
        &options,
        env,
        output,
        root,
    )?;
    let libraries = runtime_libraries(
        root,
        &executable,
        env,
        &serde_json::from_value::<Vec<_>>(json!(graphs))?,
    )?;
    unified_resolution(root, env, output)?;
    let mut negative = vec![compiler.clone()];
    negative.extend(options);
    negative.extend([
        root.join("protocol-bundles/proof/cross_graph_rejected.rs")
            .display()
            .to_string(),
        "-o".into(),
        output
            .join("cross-graph-must-not-build")
            .display()
            .to_string(),
    ]);
    for graph in graphs {
        let artifacts = graph["artifacts"]
            .as_array()
            .context("missing graph artifacts")?
            .iter()
            .map(|item| text(item, "path"))
            .collect::<Result<Vec<_>>>()?;
        let selected = artifacts
            .into_iter()
            .filter(|path| {
                Path::new(path)
                    .file_name()
                    .is_some_and(|name| name.to_string_lossy().starts_with("libtokio-"))
            })
            .collect::<Vec<_>>();
        ensure!(
            selected.len() == 1,
            "ambiguous Tokio artifact for cross-graph negative control"
        );
        negative.extend([
            "--extern".into(),
            format!("{}_tokio={}", text(graph, "graph")?, selected[0]),
            "-L".into(),
            format!("dependency={}", text(graph, "link_inputs")?),
        ]);
    }
    let (success, stderr) = capture(
        &negative,
        root,
        env,
        &output.join("cross-graph-rejected.log"),
    )?;
    rejected(
        success,
        &stderr,
        &["E0308", "Sender"],
        "cross-graph dependency types were not rejected for the expected mismatch",
    )?;
    let wal = output.join("proof-wal");
    ensure!(
        !wal.exists(),
        "previous proof left WAL evidence at {}; inspect before removing",
        wal.display()
    );
    run_logged(
        &[executable.display().to_string(), wal.display().to_string()],
        root,
        env,
        &output.join("run.log"),
    )?;
    let result = fs::read_to_string(output.join("run.log"))?;
    let observations = verify_engine_observations(&result)?;
    for graph in graphs {
        verify_identity(root, graph, &recipes)?;
        verify_staged_inputs(graph, root)?;
    }
    Ok(
        json!({"executable_sha256":sha256(&executable)?,"native_helpers":final_audit["result"],"engine_observations":observations,"runtime_libraries":libraries,"proc_macro_metadata":macros,
        "common_reference_ownership_sha256":sha256(&output.join("common-reference-ownership.json"))?,"input_ownership_sha256":sha256(&output.join("input-ownership.json"))?,"final_ownership_sha256":sha256(&output.join("final-ownership.json"))?,
        "cross_graph_rejected_sha256":sha256(&output.join("cross-graph-rejected.log"))?,"unified_resolution_rejected_sha256":sha256(&output.join("unified-resolution-rejected.log"))?,"result":result}),
    )
}
#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;
    #[test]
    fn negative_controls_require_failure_and_the_expected_diagnostic() -> Result<()> {
        let tokens = ["E0308", "Sender"];
        rejected(false, "error E0308: mismatched Sender", &tokens, "rejected")?;
        assert!(rejected(true, "E0308 Sender", &tokens, "rejected").is_err());
        assert!(rejected(false, "linker failed", &tokens, "rejected").is_err());
        assert!(rejected(false, "E0308", &tokens, "rejected").is_err());
        Ok(())
    }
    #[test]
    fn controls_keep_stdout_and_stderr_separate_for_rejection_checks() -> Result<()> {
        let dir = tempdir()?;
        let (success, stderr) = capture(
            &[
                "/bin/sh".into(),
                "-c".into(),
                "echo 'E0308 Sender'; echo 'unrelated failure' >&2; exit 1".into(),
            ],
            dir.path(),
            &Environment::new(),
            &dir.path().join("control.log"),
        )?;
        assert!(rejected(success, &stderr, &["E0308", "Sender"], "wrong diagnostic").is_err());
        assert_eq!(
            fs::read_to_string(dir.path().join("control.log"))?,
            "E0308 Sender\nunrelated failure\n"
        );
        Ok(())
    }
}
