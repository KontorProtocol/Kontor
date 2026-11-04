use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::Command;

use anyhow::{Result, ensure};
use serde_json::Value;
use tempfile::tempdir;

fn cargo(root: &Path, args: &[&str]) -> Result<Vec<Value>> {
    let output = Command::new("cargo")
        .args(args)
        .args(["--offline", "--message-format=json"])
        .current_dir(root)
        .env("CARGO_TARGET_DIR", root.join("target"))
        .env("RUSTC_WRAPPER", "")
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .output()?;
    ensure!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout)?
        .lines()
        .map(|line| Ok(serde_json::from_str(line)?))
        .collect()
}

#[test]
fn cache_preparation_preserves_dependencies_but_requires_new_node_link_records() -> Result<()> {
    let fixture = tempdir()?;
    let root = fixture.path();
    fs::create_dir(root.join("src"))?;
    fs::create_dir_all(root.join("dependency/src"))?;
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='kontor-node'\nversion='0.1.0'\nedition='2024'\n[dependencies]\nci-dependency={path='dependency'}\n",
    )?;
    fs::write(
        root.join("src/main.rs"),
        "fn main() { ci_dependency::run(); }\n",
    )?;
    fs::write(
        root.join("dependency/Cargo.toml"),
        "[package]\nname='ci-dependency'\nversion='0.1.0'\nedition='2024'\n",
    )?;
    fs::write(root.join("dependency/src/lib.rs"), "pub fn run() {}\n")?;
    cargo(root, &["build"])?;
    assert!(
        cargo(root, &["build"])?
            .iter()
            .filter(|v| v["reason"] == "compiler-artifact")
            .all(|v| v["fresh"] == true)
    );

    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ci/cache-budget.sh");
    let status = Command::new("bash")
        .arg(script)
        .arg(root.join("target"))
        .env("GITHUB_OUTPUT", root.join("cache-output"))
        .env("MAX_CACHE_KIB", "1048576")
        .status()?;
    assert!(status.success());
    assert!(fs::read_to_string(root.join("cache-output"))?.contains("save=true\n"));
    let rebuilt = cargo(root, &["build"])?;
    for (name, fresh) in [("ci_dependency", true), ("kontor-node", false)] {
        let artifact = rebuilt
            .iter()
            .find(|v| v["reason"] == "compiler-artifact" && v["target"]["name"] == name)
            .unwrap();
        assert_eq!(artifact["fresh"], fresh, "{name}");
    }
    Ok(())
}

#[test]
#[cfg(unix)]
fn test_cache_rebuilds_programs_and_changed_sources_but_reuses_dependencies() -> Result<()> {
    let fixture = tempdir()?;
    let root = fixture.path();
    fs::create_dir(root.join("src"))?;
    fs::create_dir_all(root.join("dependency/src"))?;
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='test-cache-fixture'\nversion='0.1.0'\nedition='2024'\n[dependencies]\nci-dependency={path='dependency'}\n",
    )?;
    fs::write(
        root.join("dependency/Cargo.toml"),
        "[package]\nname='ci-dependency'\nversion='0.1.0'\nedition='2024'\n",
    )?;
    fs::write(
        root.join("dependency/src/lib.rs"),
        "pub fn value() -> u8 { 1 }\n",
    )?;
    fs::write(
        root.join("src/lib.rs"),
        "#[test] fn value() { assert_eq!(ci_dependency::value(), 1); }\n",
    )?;
    let built = cargo(root, &["test", "--no-run"])?;
    let executable = built.iter().find_map(|v| v["executable"].as_str()).unwrap();
    let deps = Path::new(executable).parent().unwrap();
    for name in ["macro.so", "macro.dylib"] {
        fs::write(deps.join(name), "preserve proc macro")?;
        fs::set_permissions(deps.join(name), fs::Permissions::from_mode(0o755))?;
    }
    let generated = root.join("target/debug/build/fixture/out/deps/generator");
    fs::create_dir_all(generated.parent().unwrap())?;
    fs::write(&generated, "preserve build-script output")?;
    fs::set_permissions(&generated, fs::Permissions::from_mode(0o755))?;
    let status = Command::new("bash")
        .arg(Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ci/cache-budget.sh"))
        .arg(root.join("target"))
        .env("GITHUB_OUTPUT", root.join("cache-output"))
        .env("MAX_CACHE_KIB", "1048576")
        .env("PRUNE_TEST_EXECUTABLES", "true")
        .status()?;
    assert!(status.success());
    assert!(!Path::new(executable).exists());
    for name in ["macro.so", "macro.dylib"] {
        assert!(deps.join(name).exists());
    }
    assert!(generated.exists());
    let rebuilt = cargo(root, &["test", "--no-run"])?;
    assert!(Path::new(executable).exists());
    assert!(
        rebuilt
            .iter()
            .any(|v| v["target"]["name"] == "ci_dependency" && v["fresh"] == true)
    );
    fs::write(
        root.join("src/lib.rs"),
        "#[test] fn value() { assert_eq!(ci_dependency::value() + 1, 2); }\n",
    )?;
    let changed = cargo(root, &["test", "--no-run"])?;
    assert!(
        changed
            .iter()
            .any(|v| v["target"]["name"] == "test_cache_fixture" && v["fresh"] == false)
    );
    assert!(
        changed
            .iter()
            .any(|v| v["target"]["name"] == "ci_dependency" && v["fresh"] == true)
    );
    assert!(Command::new(executable).status()?.success());
    Ok(())
}
