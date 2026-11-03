use std::collections::BTreeSet;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::LazyLock;

use anyhow::{Context, Result, ensure};
use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};
use tempfile::Builder;

use crate::toolchain::Environment;

static MISMATCH: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"Rejecting via hash: expected ([0-9a-f]+) got ([0-9a-f]+)")
        .expect("compiler mismatch expression")
});

#[derive(Deserialize)]
pub struct Graph {
    graph: String,
    compiler_proc_macros: Vec<Value>,
    link_inputs: PathBuf,
    facade: PathBuf,
}

fn artifact_path<'a>(value: &'a Value, field: &str) -> Result<&'a Path> {
    Ok(Path::new(
        value
            .get(field)
            .and_then(Value::as_str)
            .context("compiler plugin path")?,
    ))
}

fn rustversion(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("librustversion-"))
}

fn plugin(graph: &Graph) -> Result<&Value> {
    let mut selected = Vec::new();
    for item in &graph.compiler_proc_macros {
        if rustversion(artifact_path(item, "path")?) {
            selected.push(item);
        }
    }
    ensure!(
        selected.len() == 1,
        "expected one rustversion compiler plugin per graph"
    );
    Ok(selected[0])
}

fn hashes(success: bool, log: &str) -> Result<(String, String)> {
    ensure!(
        !success && log.contains("E0463"),
        "foreign proc-macro metadata was not rejected"
    );
    let mut candidate = "";
    let mut mismatches = BTreeSet::new();
    for line in log.lines() {
        if let Some((_, path)) = line.split_once("reading metadata from: ") {
            candidate = path;
        }
        if let Some(captures) = MISMATCH.captures(line)
            && rustversion(Path::new(candidate))
        {
            mismatches.insert((captures[1].to_owned(), captures[2].to_owned()));
        }
    }
    ensure!(
        mismatches.len() == 1,
        "ambiguous proc-macro metadata rejection: {mismatches:?}"
    );
    let (expected, foreign) = mismatches.pop_first().expect("one mismatch");
    ensure!(
        expected != foreign,
        "compiler plugins unexpectedly share an SVH"
    );
    Ok((expected, foreign))
}

pub fn proc_macro_hashes(
    graphs: &[Graph],
    options: &[String],
    env: &Environment,
    output: &Path,
    cwd: &Path,
) -> Result<Value> {
    ensure!(
        graphs.len() == 2 && graphs[0].graph != graphs[1].graph,
        "proc-macro metadata control requires two distinct graphs"
    );
    for graph in graphs {
        ensure!(
            !graph.graph.is_empty()
                && graph
                    .graph
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
            "invalid proof graph label"
        );
    }
    let mut values = Vec::new();
    let output = cwd.join(output);
    for (index, graph) in graphs.iter().enumerate() {
        let native = plugin(graph)?;
        let other = plugin(&graphs[1 - index])?;
        let temporary = Builder::new()
            .prefix("metadata-control-")
            .tempdir_in(&output)?;
        let root = temporary.path();
        let native_staged = cwd.join(artifact_path(native, "staged")?);
        for entry in fs::read_dir(cwd.join(&graph.link_inputs))? {
            let path = entry?.path();
            if path == native_staged {
                continue;
            }
            symlink(
                &path,
                root.join(path.file_name().context("compiler input filename")?),
            )?;
        }
        let replacement = cwd.join(artifact_path(other, "staged")?);
        symlink(
            &replacement,
            root.join(
                replacement
                    .file_name()
                    .context("replacement plugin filename")?,
            ),
        )?;
        let source = root.join("probe.rs");
        fs::write(
            &source,
            format!(
                "use kontor_proof_{} as bundle;\nfn main() {{ let _ = bundle::shape(); }}\n",
                graph.graph
            ),
        )?;
        let rustc = Path::new(env.get("RUSTC").context("missing pinned RUSTC")?);
        let rustc = if rustc.components().count() > 1 {
            cwd.join(rustc)
        } else {
            rustc.to_owned()
        };
        let checked = Command::new(rustc)
            .current_dir(cwd)
            .env_clear()
            .envs(env)
            .env("RUSTC_LOG", "rustc_metadata::locator=info")
            .stdin(Stdio::null())
            .args(options)
            .arg("--emit=metadata")
            .arg(source)
            .arg("-o")
            .arg(root.join("probe.rmeta"))
            .arg("--extern")
            .arg(format!(
                "kontor_proof_{}={}",
                graph.graph,
                graph.facade.display()
            ))
            .arg("-L")
            .arg(format!("dependency={}", root.display()))
            .output()?;
        let log = (String::from_utf8(checked.stdout)? + &String::from_utf8(checked.stderr)?)
            .replace("\r\n", "\n")
            .replace('\r', "\n");
        fs::write(
            output.join(format!("{}-wrong-proc-macro.log", graph.graph)),
            &log,
        )?;
        let (expected, foreign) = hashes(checked.status.success(), &log)?;
        values.push(json!({"graph": graph.graph, "svh": expected, "foreign_svh": foreign, "artifact": native}));
    }
    ensure!(
        values[0]["svh"] == values[1]["foreign_svh"]
            && values[1]["svh"] == values[0]["foreign_svh"],
        "bidirectional proc-macro rejection hashes do not match"
    );
    Ok(json!(values))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejection_must_bind_one_rustversion_hash_pair_and_error_code() -> Result<()> {
        let log = "E0463\nreading metadata from: /tmp/librustversion-foreign.so\nRejecting via hash: expected 123abc got 456def\n";
        assert_eq!(hashes(false, log)?, ("123abc".into(), "456def".into()));
        assert_eq!(
            hashes(
                false,
                &(log.to_owned() + "Rejecting via hash: expected 123abc got 456def\n")
            )?,
            hashes(false, log)?
        );
        for bad in [
            log.replace("E0463", "E0000"),
            log.replace("librustversion-", "libother-"),
            log.replace("456def", "123abc"),
            log.to_owned() + "Rejecting via hash: expected aaaa got bbbb\n",
        ] {
            assert!(hashes(false, &bad).is_err());
        }
        assert!(hashes(true, log).is_err());
        assert!(hashes(false, "E0463").is_err());
        Ok(())
    }
}
