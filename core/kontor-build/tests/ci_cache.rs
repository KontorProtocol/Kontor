use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Result, ensure};
use serde_json::Value;
use tempfile::tempdir;

fn build(root: &Path) -> Result<Vec<Value>> {
    let output = Command::new("cargo")
        .args(["build", "--offline", "--message-format=json"])
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
    build(root)?;
    assert!(
        build(root)?
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
    let rebuilt = build(root)?;
    for (name, fresh) in [("ci_dependency", true), ("kontor-node", false)] {
        let artifact = rebuilt
            .iter()
            .find(|v| v["reason"] == "compiler-artifact" && v["target"]["name"] == name)
            .unwrap();
        assert_eq!(artifact["fresh"], fresh, "{name}");
    }
    Ok(())
}
