mod container;
mod outputs;

use std::collections::BTreeSet;
use std::env;
use std::fs::{self, File};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, ensure};
use clap::{Args, ValueEnum};
use serde_json::{Value, json};

use container::{Config, Container, sha256};
use outputs::{differences, files, install};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd, ValueEnum)]
pub enum Target {
    Native,
    Test,
    Sdk,
    Encoder,
}

#[derive(Debug, Args)]
pub struct BuildArgs {
    /// Outputs to regenerate; defaults to native, test, sdk, and encoder.
    #[arg(value_enum)]
    pub targets: Vec<Target>,
    /// Compare staged output against the checkout without changing committed files.
    #[arg(long)]
    pub check: bool,
    /// Container runtime; defaults to podman, then docker.
    #[arg(long, value_parser = ["podman", "docker"])]
    pub runtime: Option<String>,
    /// Maximum concurrent compiler jobs.
    #[arg(short = 'j', long, default_value_t = 2, value_parser = clap::value_parser!(u32).range(1..))]
    pub jobs: u32,
}

pub fn run(args: BuildArgs) -> Result<()> {
    let cwd = env::current_dir()?;
    let root = cwd
        .ancestors()
        .find(|path| path.join("tools/build.json").is_file())
        .context("run kontor build inside a Kontor checkout")?;
    let cache = root.join(".build-cache");
    fs::create_dir_all(&cache)?;
    let lock = File::options()
        .create(true)
        .truncate(false)
        .write(true)
        .open(cache.join("build.lock"))?;
    lock.try_lock()
        .context("another kontor build is running in this checkout")?;
    ensure!(
        !cache.join("backup").exists(),
        "unfinished output recovery in .build-cache/backup; restore it before building"
    );
    let config = Config::read(root)?;
    let container = Container::new(root, &config, args.runtime, args.jobs)?;
    let targets: BTreeSet<_> = if args.targets.is_empty() {
        [Target::Native, Target::Test, Target::Sdk, Target::Encoder]
            .into_iter()
            .collect()
    } else {
        args.targets.into_iter().collect()
    };
    let stage = cache.join("generated");
    if stage.exists() {
        fs::remove_dir_all(&stage)?;
    }
    fs::create_dir_all(&stage)?;
    let provenance = json!({
        "platform": config.platform,
        "image": config.image,
        "rustc": container.text("/build", &[], &["rustc", "--version"] )?,
        "wasm_opt": container.text("/build", &[], &["wasm-opt", "--version"] )?,
        "brotli": container.text("/build", &[], &["brotli", "--version"] )?,
    });
    let mut paths = Vec::new();
    for target in targets {
        match target {
            Target::Native | Target::Test => {
                let workspace = if target == Target::Native {
                    "native-contracts"
                } else {
                    "test-contracts"
                };
                eprintln!("Building {workspace}");
                contracts(&container, &stage, workspace, &provenance)?;
                paths.push(PathBuf::from(format!("{workspace}/binaries")));
            }
            Target::Encoder => {
                eprintln!("Building runtime result encoder");
                encoder(&container, &stage, &provenance)?;
                paths.push(PathBuf::from("core/result-encoder/binaries"));
            }
            Target::Sdk => {
                eprintln!("Building SDK component and bindings");
                sdk(&container, &stage, &provenance)?;
                paths.extend([
                    PathBuf::from("sdk/src/component"),
                    PathBuf::from("sdk/src/bindings.d.ts"),
                ]);
            }
        }
    }
    if args.check {
        let mut changed = Vec::new();
        for path in &paths {
            if stage.join(path).is_dir() {
                changed.extend(
                    differences(&root.join(path), &stage.join(path))?
                        .into_iter()
                        .map(|diff| format!("{}: {diff}", path.display())),
                );
            } else if !root.join(path).is_file()
                || fs::read(root.join(path))? != fs::read(stage.join(path))?
            {
                changed.push(format!("changed or missing: {}", path.display()));
            }
        }
        ensure!(
            changed.is_empty(),
            "generated outputs differ:\n{}\nCandidates: {}",
            changed.join("\n"),
            stage.display()
        );
        eprintln!("All requested outputs reproduce byte-for-byte");
    } else {
        install(root, &stage, &paths, &cache.join("backup"))?;
        eprintln!("Updated all requested outputs");
    }
    Ok(())
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    // The node and bootstrap can enable different serde_json features. Keep
    // provenance ordering identical even when preserve_order is unified in.
    let mut value = value.clone();
    value.sort_all_objects();
    fs::write(path, format!("{}\n", serde_json::to_string_pretty(&value)?))?;
    Ok(())
}

// Cargo's artifact messages identify this invocation's outputs, including fresh
// cached results. Globbing target/ would resurrect removed workspace members.
fn wasm_artifacts(
    container: &Container,
    cwd: &str,
    env: &[(&str, &str)],
    packages: &[&str],
) -> Result<Vec<String>> {
    let metadata: Value = serde_json::from_str(&container.text(
        cwd,
        env,
        &[
            "cargo",
            "metadata",
            "--locked",
            "--no-deps",
            "--format-version=1",
        ],
    )?)?;
    let members: BTreeSet<_> = metadata["workspace_members"]
        .as_array()
        .context("workspace members")?
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let mut args = vec![
        "cargo",
        "build",
        "--locked",
        "--release",
        "--message-format=json-render-diagnostics",
    ];
    if packages.is_empty() {
        args.push("--workspace");
    }
    for package in packages {
        args.extend(["-p", package]);
    }
    let messages = container.text(cwd, env, &args)?;
    let mut artifacts = BTreeSet::new();
    for line in messages.lines() {
        let message: Value = serde_json::from_str(line).context("cargo JSON output")?;
        if message["reason"] != "compiler-artifact"
            || !members.contains(message["package_id"].as_str().unwrap_or_default())
        {
            continue;
        }
        if let Some(filenames) = message["filenames"].as_array() {
            for filename in filenames
                .iter()
                .filter_map(Value::as_str)
                .filter(|name| name.ends_with(".wasm"))
            {
                artifacts.insert(filename.to_owned());
            }
        }
    }
    ensure!(
        !artifacts.is_empty(),
        "cargo emitted no workspace wasm artifacts for {cwd}"
    );
    Ok(artifacts.into_iter().collect())
}

fn contracts(
    container: &Container,
    stage: &Path,
    workspace: &str,
    provenance: &Value,
) -> Result<()> {
    let relative = format!("{workspace}/binaries");
    let output = stage.join(&relative);
    fs::create_dir_all(&output)?;
    for (path, bytes) in files(&container.root.join(&relative))? {
        // BUILD.md and other hand-maintained files are outside generated output.
        if path.file_name().is_some_and(|name| name == "build.json")
            || path.to_string_lossy().ends_with(".wasm.br")
        {
            continue;
        }
        let destination = output.join(path);
        fs::create_dir_all(destination.parent().context("output parent")?)?;
        fs::write(destination, bytes)?;
    }
    let cwd = format!("/build/{workspace}");
    for artifact in wasm_artifacts(container, &cwd, &[], &[])? {
        let name = Path::new(&artifact)
            .file_name()
            .and_then(|name| name.to_str())
            .context("wasm filename")?;
        let optimized = format!("/build/.build-cache/{workspace}-{name}");
        container.run(
            &cwd,
            &[],
            &[
                "wasm-opt",
                "-Oz",
                "--enable-bulk-memory",
                "--enable-sign-ext",
                &artifact,
                "-o",
                &optimized,
            ],
        )?;
        container.run(
            &cwd,
            &[],
            &[
                "brotli",
                "-Zf",
                &optimized,
                "-o",
                &format!("/build/.build-cache/generated/{relative}/{name}.br"),
            ],
        )?;
    }
    write_json(&output.join("build.json"), provenance)
}

fn encoder(container: &Container, stage: &Path, provenance: &Value) -> Result<()> {
    let relative = "core/result-encoder/binaries";
    let output = stage.join(relative);
    fs::create_dir_all(&output)?;
    let artifacts = wasm_artifacts(
        container,
        "/build/core",
        &[
            ("CARGO_BUILD_TARGET", "wasm32-unknown-unknown"),
            (
                "CARGO_TARGET_DIR",
                "/build/.build-cache/target/result-encoder",
            ),
            ("RUSTFLAGS", "-C panic=abort -C link-arg=-zstack-size=65536"),
        ],
        &["result-encoder"],
    )?;
    ensure!(artifacts.len() == 1, "expected one result encoder module");
    container.run(
        "/build/core",
        &[],
        &[
            "wasm-opt",
            "-Oz",
            "--enable-bulk-memory",
            "--enable-sign-ext",
            &artifacts[0],
            "-o",
            &format!("/build/.build-cache/generated/{relative}/encoder.wasm"),
        ],
    )?;
    write_json(&output.join("build.json"), provenance)
}

fn sdk(container: &Container, stage: &Path, provenance: &Value) -> Result<()> {
    let node = container.archive(&container.config.node)?;
    let wasm_tools = container.archive(&container.config.wasm_tools)?;
    let wasi = container.archive(&container.config.wasi_sdk)?;
    let path = format!("{node}/bin:/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin");
    let cc = format!("{wasi}/bin/clang");
    let ar = format!("{wasi}/bin/llvm-ar");
    let env = [
        ("PATH", path.as_str()),
        ("CC_wasm32_unknown_unknown", cc.as_str()),
        ("AR_wasm32_unknown_unknown", ar.as_str()),
        ("CARGO_TARGET_DIR", "/build/.build-cache/target/sdk"),
    ];
    let node_version = container.text("/build", &env, &["node", "--version"])?;
    let wasm_tools_version = container.text(
        "/build",
        &env,
        &[&format!("{wasm_tools}/wasm-tools"), "--version"],
    )?;
    let clang_version = container.text("/build", &env, &[&cc, "--version"])?;
    ensure!(
        node_version == format!("v{}", container.config.node.version),
        "Node version does not match its pin"
    );
    ensure!(
        wasm_tools_version.split_whitespace().nth(1)
            == Some(container.config.wasm_tools.version.as_str()),
        "wasm-tools version does not match its pin"
    );
    let npm = container.root.join(".build-cache/sdk-npm");
    fs::create_dir_all(&npm)?;
    for name in ["package.json", "package-lock.json"] {
        fs::copy(container.root.join("sdk").join(name), npm.join(name))?;
    }
    container.run(
        "/build/.build-cache/sdk-npm",
        &env,
        &["npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund"],
    )?;
    let artifacts = wasm_artifacts(
        container,
        "/build/core/kontor-sdk-wasm",
        &env,
        &["kontor-sdk-wasm"],
    )?;
    ensure!(artifacts.len() == 1, "expected one SDK wasm artifact");
    let optimized = "/build/.build-cache/sdk-optimized.wasm";
    let component = "/build/.build-cache/sdk-component.wasm";
    container.run(
        "/build",
        &env,
        &[
            "wasm-opt",
            "-Oz",
            "--enable-bulk-memory",
            "--enable-mutable-globals",
            "--enable-nontrapping-float-to-int",
            "--enable-sign-ext",
            "--enable-reference-types",
            "--enable-multivalue",
            &artifacts[0],
            "-o",
            optimized,
        ],
    )?;
    container.run(
        "/build",
        &env,
        &[
            &format!("{wasm_tools}/wasm-tools"),
            "component",
            "new",
            optimized,
            "-o",
            component,
        ],
    )?;
    let out = "/build/.build-cache/generated/sdk/src";
    fs::create_dir_all(stage.join("sdk/src"))?;
    container.run(
        "/build/sdk",
        &env,
        &[
            "node",
            "/build/.build-cache/sdk-npm/node_modules/@bytecodealliance/jco/src/jco.js",
            "transpile",
            component,
            "--name",
            "kontor-sdk",
            "-o",
            &format!("{out}/component"),
        ],
    )?;
    let mut export_env = env.to_vec();
    export_env.push(("TS_RS_EXPORT_DIR", out));
    container.run(
        "/build/core",
        &export_env,
        &[
            "cargo",
            "test",
            "--locked",
            "--release",
            "-p",
            "indexer-types",
            "--lib",
        ],
    )?;
    ensure!(
        stage.join("sdk/src/bindings.d.ts").is_file(),
        "indexer-types did not export SDK bindings"
    );
    let lock: Value = serde_json::from_slice(&fs::read(npm.join("package-lock.json"))?)?;
    let package: Value = serde_json::from_slice(&fs::read(npm.join("package.json"))?)?;
    let jco_version = lock["packages"]["node_modules/@bytecodealliance/jco"]["version"]
        .as_str()
        .context("locked JCO version")?;
    ensure!(
        package["devDependencies"]["@bytecodealliance/jco"] == jco_version,
        "pin JCO to its locked version {jco_version}"
    );
    let mut provenance = provenance.clone();
    provenance["archives"] = json!({
        "node": container.config.node,
        "wasm_tools": container.config.wasm_tools,
        "wasi_sdk": container.config.wasi_sdk,
    });
    provenance["node"] = json!(node_version);
    provenance["wasm_tools"] = json!(wasm_tools_version);
    provenance["clang"] = json!(clang_version);
    provenance["jco"] = json!(jco_version);
    provenance["npm_lock_sha256"] = json!(sha256(&npm.join("package-lock.json"))?);
    write_json(&stage.join("sdk/src/component/build.json"), &provenance)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn provenance_is_canonical_with_or_without_preserve_order() -> Result<()> {
        let dir = tempdir()?;
        let path = dir.path().join("build.json");
        write_json(&path, &json!({"z": {"z": 2, "a": 1}, "a": 0}))?;
        assert_eq!(
            fs::read_to_string(path)?,
            "{\n  \"a\": 0,\n  \"z\": {\n    \"a\": 1,\n    \"z\": 2\n  }\n}\n"
        );
        Ok(())
    }
}
