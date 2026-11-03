use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::path::{Path, PathBuf};
use std::process::Stdio;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;

use super::{CRATES, Environment, capture, command, run};
use crate::build_artifacts::native_archives;
use crate::container::sha256;
use crate::source_identity::{Lockfile, Metadata};

pub(super) struct Graph {
    pub name: String,
    pub graph: String,
    pub namespace: String,
    pub project: PathBuf,
    pub native: BTreeMap<String, PathBuf>,
    pub inputs: BTreeSet<PathBuf>,
    pub facade: PathBuf,
    pub lock_sha256: String,
}

#[derive(Deserialize)]
#[serde(tag = "reason")]
enum Message {
    #[serde(rename = "build-script-executed")]
    Script {
        package_id: String,
        out_dir: PathBuf,
    },
    #[serde(rename = "compiler-artifact")]
    Artifact {
        target: Target,
        filenames: Vec<PathBuf>,
    },
    #[serde(other)]
    Other,
}
#[derive(Deserialize)]
struct Target {
    name: String,
}

fn messages(log: &Path) -> Result<Vec<Message>> {
    let mut messages = Vec::new();
    for line in fs::read_to_string(log)?.lines() {
        // Cargo mixes diagnostics with JSON. A recognized artifact record must
        // be well-formed; otherwise an omitted archive could evade the audit.
        let Ok(value) = serde_json::from_str::<serde_json::Value>(line) else {
            continue;
        };
        if value.get("reason").is_some() {
            messages.push(serde_json::from_value(value)?);
        }
    }
    Ok(messages)
}

fn inventory(
    messages: &[Message],
    metadata: &Metadata,
    namespace: &str,
) -> Result<(BTreeMap<String, PathBuf>, BTreeSet<PathBuf>, PathBuf)> {
    let packages: BTreeMap<_, _> = metadata
        .packages
        .iter()
        .map(|p| (p.id.as_str(), p.name.as_str()))
        .collect();
    let mut native = BTreeMap::new();
    let mut inputs = BTreeSet::new();
    let mut facades = Vec::new();
    for message in messages {
        match message {
            Message::Script {
                package_id,
                out_dir,
            } => {
                let package = packages
                    .get(package_id.as_str())
                    .context("unknown native archive package")?;
                let mut archives = Vec::new();
                native_archives(out_dir, &mut archives)?;
                ensure!(
                    archives.is_empty() || CRATES.contains(package),
                    "unexpected native archive owner: {package}"
                );
                for path in archives {
                    let filename = path
                        .file_name()
                        .context("archive filename")?
                        .to_str()
                        .context("archive filename UTF8")?;
                    let filename = if namespace.is_empty() {
                        filename.to_owned()
                    } else {
                        filename.replace(&format!("{namespace}_"), "")
                    };
                    let key = format!("{package}/{filename}");
                    inputs.insert(path.clone());
                    ensure!(
                        native.insert(key.clone(), path).is_none(),
                        "duplicate current archive: {key}"
                    );
                }
            }
            Message::Artifact { target, filenames } => {
                for path in filenames
                    .iter()
                    .filter(|path| path.extension().is_some_and(|ext| ext == "rlib"))
                {
                    inputs.insert(path.clone());
                    if target.name.starts_with("crypto_") {
                        facades.push(path.clone());
                    }
                }
            }
            Message::Other => {}
        }
    }
    let owners: BTreeSet<_> = native
        .keys()
        .map(|key| key.split('/').next().unwrap())
        .collect();
    ensure!(
        owners == BTreeSet::from(CRATES) && facades.len() == 1,
        "missing current native archive or facade"
    );
    Ok((native, inputs, facades.remove(0)))
}

fn check_lock(source: &Path, candidate: &Path, facade: &str) -> Result<()> {
    let source: Lockfile = toml::from_str(&fs::read_to_string(source)?)?;
    let candidate: Lockfile = toml::from_str(&fs::read_to_string(candidate)?)?;
    let allowed: BTreeSet<_> = source.package.into_iter().collect();
    for package in candidate.package {
        ensure!(
            package.name == facade || allowed.contains(&package),
            "independent graph drifted from source lock: {package:?}"
        );
    }
    Ok(())
}

pub(super) fn build(
    root: &Path,
    output: &Path,
    env: &Environment,
    pristine: &BTreeMap<String, PathBuf>,
    configuration: &str,
    variant: &str,
) -> Result<Graph> {
    let graph = if configuration == "portable" {
        if variant == "default" {
            "node"
        } else {
            "first"
        }
    } else {
        "second"
    };
    let name = format!("{configuration}-{variant}");
    let project = output.join(&name);
    fs::create_dir(&project)?;
    let sources: BTreeMap<_, _> = CRATES
        .into_iter()
        .map(|name| {
            (
                name,
                if variant == "upstream" {
                    pristine[name].clone()
                } else {
                    root.join("core/vendor").join(name)
                },
            )
        })
        .collect();
    let path = |name: &str| -> Result<String> {
        Ok(serde_json::to_string(
            sources[name].to_str().context("source path must be UTF8")?,
        )?)
    };
    let manifest = format!(
        "[package]\nname = \"crypto_{graph}\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\
        [workspace]\n[lib]\npath = \"bundle.rs\"\n[[bin]]\nname = \"vector-output\"\npath = \"main.rs\"\n\
        [profile.release]\ndebug = 0\n[dependencies]\n\
        blst = {{ path = {}, features = {} }}\nring = {{ path = {} }}\n\
        secp256k1 = {{ version = \"=0.29.1\", features = {} }}\n\
        [patch.crates-io]\nsecp256k1-sys = {{ path = {} }}\n",
        path("blst")?,
        if configuration == "portable" {
            "[\"portable\"]"
        } else {
            "[]"
        },
        path("ring")?,
        if configuration == "portable" {
            "[\"recovery\", \"lowmemory\"]"
        } else {
            "[\"recovery\"]"
        },
        path("secp256k1-sys")?
    );
    fs::write(project.join("Cargo.toml"), manifest)?;
    fs::copy(
        root.join("tools/native-crypto/fixtures/bundle.rs"),
        project.join("bundle.rs"),
    )?;
    fs::write(
        project.join("main.rs"),
        format!(
            "use std::io::{{self, Write}};\nfn main() {{ io::stdout().write_all(&crypto_{graph}::exercise()).unwrap(); }}\n"
        ),
    )?;
    fs::copy(root.join("core/Cargo.lock"), project.join("Cargo.lock"))?;
    let namespace = if variant == "namespaced" {
        format!("kontor_crypto_{graph}")
    } else {
        String::new()
    };
    let mut build_env = env.clone();
    build_env.insert(
        "CARGO_TARGET_DIR".into(),
        project.join("target").into_os_string(),
    );
    // Pristine path sources need the same cfg allowances Cargo gives registry dependencies.
    build_env.insert("RUSTFLAGS".into(),format!("-Cmetadata=kontor_crypto_{graph} --check-cfg=cfg(secp256k1_fuzz) --check-cfg=cfg(rust_secp_no_symbol_renaming)").into());
    if !namespace.is_empty() {
        build_env.insert("KONTOR_NATIVE_NAMESPACE".into(), namespace.clone().into());
        build_env.insert("KONTOR_PROTOCOL_BUNDLE".into(), "1".into());
    }
    let metadata_bytes = capture(command("cargo", &project, &build_env).args([
        "metadata",
        "--offline",
        "--format-version=1",
    ]))?;
    fs::write(project.join("metadata.json"), &metadata_bytes)?;
    let metadata: Metadata = serde_json::from_slice(&metadata_bytes)?;
    check_lock(
        &root.join("core/Cargo.lock"),
        &project.join("Cargo.lock"),
        &format!("crypto_{graph}"),
    )?;
    let lock_sha256 = sha256(&project.join("Cargo.lock"))?;
    run(
        command("cargo", &project, &build_env).args([
            "build",
            "--locked",
            "--offline",
            "--release",
            "-j2",
            "--message-format=json",
        ]),
        &project.join("build.log"),
    )?;
    ensure!(
        sha256(&project.join("Cargo.lock"))? == lock_sha256,
        "locked build changed source graph"
    );
    let messages = messages(&project.join("build.log"))?;
    let (native, inputs, facade) = inventory(&messages, &metadata, &namespace)?;
    for message in &messages {
        if let Message::Script {
            package_id,
            out_dir,
        } = message
        {
            let name = &metadata
                .packages
                .iter()
                .find(|package| &package.id == package_id)
                .context("unknown build-script package")?
                .name;
            if CRATES.contains(&name.as_str()) {
                fs::copy(
                    out_dir
                        .parent()
                        .context("build-script parent")?
                        .join("output"),
                    project.join(format!("native-{name}.log")),
                )?;
            }
        }
    }
    let status = command(
        project.join("target/release/vector-output"),
        &project,
        &build_env,
    )
    .stdout(Stdio::from(File::create(project.join("vectors.bin"))?))
    .status()?;
    ensure!(status.success(), "vector executable failed");
    Ok(Graph {
        name,
        graph: graph.into(),
        namespace,
        project,
        native,
        inputs,
        facade,
        lock_sha256,
    })
}

#[cfg(test)]
mod tests;
