use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use clap::Args;
use serde_json::{Value, json};
use toml::Value as Toml;

use crate::recipes::proof_graphs;

#[derive(Args)]
pub struct PrelaunchArgs {
    #[arg(long)]
    pub write: bool,
}

fn observer_input(source: &str, manifest: bool) -> Result<String> {
    let parsed: Toml = toml::from_str(source)?;
    let graphs = proof_graphs();
    let first = &graphs["first"];
    let second = &graphs["second"];
    let first_revision = first.revision.as_deref().context("P1 revision missing")?;
    let first_version = first.version.as_deref().context("P1 version missing")?;
    let second_revision = second.revision.as_deref().context("P2 revision missing")?;
    let second_version = second.version.as_deref().context("P2 version missing")?;
    ensure!(
        first_revision == "0f84389ecd927c2e154f8d0de31fc2dfa5ebcae7"
            && first_version == "51.0.0-kontor.2"
            && second.revision.as_deref() == Some("0dbc68b31c0bcf1a05c93122f1939fb8784e4e48")
            && second.version.as_deref() == Some("51.0.0-kontor.3"),
        "new Wasmtime revisions require review of the prelaunch identity-only overlay"
    );
    if manifest {
        ensure!(
            parsed["package"]["name"].as_str() == Some("kontor-executor-first")
                && parsed["dependencies"]["wasmtime"]["rev"].as_str() == Some(first_revision)
                && parsed["dependencies"]["wasmtime"]["version"].as_str()
                    == Some(&format!("={first_version}")),
            "prelaunch P1 graph no longer matches the explicit identity overlay"
        );
    } else {
        let packages = parsed["package"]
            .as_array()
            .context("lock packages missing")?;
        ensure!(
            packages
                .iter()
                .filter(|p| p["name"].as_str() == Some("kontor-executor-first"))
                .count()
                == 1,
            "P1 lockfile must contain exactly one executor root"
        );
        ensure!(
            packages
                .iter()
                .any(|p| p["name"].as_str() == Some("wasmtime")
                    && p["version"].as_str() == Some(first_version)),
            "P1 lockfile does not contain the pinned Wasmtime version"
        );
    }
    let mut expected = parsed.clone();
    if manifest {
        expected["package"]["name"] = Toml::String("kontor-executor-observer".into());
        expected["dependencies"]["wasmtime"]["rev"] = Toml::String(second_revision.into());
        expected["dependencies"]["wasmtime"]["version"] =
            Toml::String(format!("={second_version}"));
        expected["patch"]["crates-io"]["wasmtime"]["rev"] = Toml::String(second_revision.into());
        expected["patch"]["crates-io"]["wasmtime"]["version"] =
            Toml::String(format!("={second_version}"));
    } else {
        let first_source = format!(
            "git+https://github.com/wilfreddenton/wasmtime?rev={first_revision}#{first_revision}"
        );
        let second_source = format!(
            "git+https://github.com/wilfreddenton/wasmtime?rev={second_revision}#{second_revision}"
        );
        for package in expected["package"]
            .as_array_mut()
            .context("lock packages missing")?
        {
            if package["name"].as_str() == Some("kontor-executor-first") {
                package["name"] = Toml::String("kontor-executor-observer".into());
            }
            if package.get("source").and_then(Toml::as_str) == Some(&first_source) {
                package["source"] = Toml::String(second_source.clone());
                if package["version"].as_str() == Some(first_version) {
                    package["version"] = Toml::String(second_version.into());
                }
            }
        }
    }
    // These two pinned Wasmtime revisions have identical implementation sources.
    // Their package versions give native assembly/export symbols separate names.
    // Never normalize arbitrary dependency differences or generate source rewrites.
    let generated = source
        .replace("\"kontor-executor-first\"", "\"kontor-executor-observer\"")
        .replace(first_revision, second_revision)
        .replace(first_version, second_version);
    ensure!(
        toml::from_str::<Toml>(&generated)? == expected,
        "identity overlay would change an unrelated TOML field"
    );
    Ok(generated)
}

pub fn sync_prelaunch(root: &Path, args: PrelaunchArgs) -> Result<Value> {
    let first = root.join("protocol-bundles/executor-first");
    let observer = root.join("protocol-bundles/executor-observer");
    let candidates = ["Cargo.toml", "Cargo.lock"]
        .into_iter()
        .map(|name| {
            Ok((
                name,
                observer_input(&fs::read_to_string(first.join(name))?, name == "Cargo.toml")?,
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    let fixture = fs::read(root.join("native-contracts/binaries/upgrade_fixture.wasm.br"))?;
    let fixture_path = root.join("core/indexer/src/protocol/v2/native/upgrade_fixture.wasm.br");
    for (name, expected) in &candidates {
        let path = observer.join(name);
        if args.write {
            fs::write(&path, expected)?;
        } else {
            ensure!(
                fs::read_to_string(&path)? == *expected,
                "P2 {name} drifted from P1; run tools/kontor sync-prelaunch --write"
            );
        }
    }
    if args.write {
        fs::create_dir_all(fixture_path.parent().context("fixture directory missing")?)?;
        fs::write(&fixture_path, fixture)?;
    } else {
        ensure!(
            fs::read(&fixture_path)? == fixture,
            "P2 fixture artifact is stale"
        );
    }
    Ok(json!({"p1":"executor-first", "p2":"executor-observer", "written":args.write}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn repository() -> &'static Path {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap()
            .parent()
            .unwrap()
    }

    #[test]
    fn checked_in_successor_matches_prelaunch_p1() -> Result<()> {
        sync_prelaunch(repository(), PrelaunchArgs { write: false })?;
        Ok(())
    }

    #[test]
    fn identity_overlay_cannot_rewrite_unrelated_fields() -> Result<()> {
        let source =
            fs::read_to_string(repository().join("protocol-bundles/executor-first/Cargo.toml"))?;
        let source = format!("{source}\n[package.metadata]\nnote = \"51.0.0-kontor.2\"\n");
        assert!(observer_input(&source, true).is_err());
        Ok(())
    }

    #[test]
    fn generation_detects_feature_and_lock_drift_and_is_repeatable() -> Result<()> {
        let dir = tempdir()?;
        fs::create_dir_all(dir.path().join("native-contracts/binaries"))?;
        fs::write(
            dir.path()
                .join("native-contracts/binaries/upgrade_fixture.wasm.br"),
            [1, 2, 3],
        )?;
        for name in ["executor-first", "executor-observer"] {
            fs::create_dir_all(dir.path().join("protocol-bundles").join(name))?;
        }
        for name in ["Cargo.toml", "Cargo.lock"] {
            fs::copy(
                repository()
                    .join("protocol-bundles/executor-first")
                    .join(name),
                dir.path()
                    .join("protocol-bundles/executor-first")
                    .join(name),
            )?;
        }
        sync_prelaunch(dir.path(), PrelaunchArgs { write: true })?;
        sync_prelaunch(dir.path(), PrelaunchArgs { write: false })?;
        let manifest = dir
            .path()
            .join("protocol-bundles/executor-observer/Cargo.toml");
        let expected = fs::read_to_string(&manifest)?;
        fs::write(
            &manifest,
            expected.replace("\"async\"", "\"async\", \"addr2line\""),
        )?;
        assert!(sync_prelaunch(dir.path(), PrelaunchArgs { write: false }).is_err());
        sync_prelaunch(dir.path(), PrelaunchArgs { write: true })?;
        assert_eq!(fs::read_to_string(&manifest)?, expected);
        let lock = dir
            .path()
            .join("protocol-bundles/executor-observer/Cargo.lock");
        let expected_lock = fs::read_to_string(&lock)?;
        fs::write(
            &lock,
            expected_lock.replace("version = \"0.1.0\"", "version = \"0.2.0\""),
        )?;
        assert!(sync_prelaunch(dir.path(), PrelaunchArgs { write: false }).is_err());
        sync_prelaunch(dir.path(), PrelaunchArgs { write: true })?;
        assert_eq!(fs::read_to_string(&lock)?, expected_lock);
        Ok(())
    }
}
