use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

use super::dependencies::{docker_target_paths, validate_repro_dependencies};
use super::paths::{bundle_relevant, classify, stack_relevant};
use super::{CiScope, JOBS, changed_paths, outputs, profile_policy, select};

fn write(root: &Path, path: &str, text: &str) -> Result<()> {
    let path = root.join(path);
    fs::create_dir_all(path.parent().context("parent")?)?;
    fs::write(path, text)?;
    Ok(())
}

fn fixture() -> Result<TempDir> {
    let root = tempdir()?;
    for name in ["native-contracts", "test-contracts"] {
        write(
            root.path(),
            &format!("{name}/Cargo.toml"),
            "[workspace]\nmembers=[]",
        )?;
    }
    write(
        root.path(),
        "core/Cargo.toml",
        "[workspace]\nmembers=['kontor-build','kontor-sdk-wasm']",
    )?;
    for name in ["kontor-build", "kontor-sdk-wasm", "new-dependency"] {
        write(
            root.path(),
            &format!("core/{name}/Cargo.toml"),
            "[package]\nname='fixture'\nversion='1.0.0'",
        )?;
    }
    Ok(root)
}

fn git(root: &Path, args: &[&str]) -> Result<String> {
    let result = Command::new("git").current_dir(root).args(args).output()?;
    ensure!(
        result.status.success(),
        "git failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?.trim().into())
}

fn commit(root: &Path) -> Result<String> {
    git(root, &["add", "--all"])?;
    git(
        root,
        &[
            "-c",
            "core.hooksPath=/dev/null",
            "-c",
            "commit.gpgsign=false",
            "commit",
            "-qm",
            "Fixture",
        ],
    )?;
    git(root, &["rev-parse", "HEAD"])
}

fn git_fixture() -> Result<(TempDir, String)> {
    let root = fixture()?;
    git(root.path(), &["init", "-q"])?;
    git(root.path(), &["config", "user.name", "Test fixture"])?;
    git(
        root.path(),
        &["config", "user.email", "fixture@example.invalid"],
    )?;
    write(root.path(), "README.md", "base")?;
    write(root.path(), "core/indexer/src/runtime/old.rs", "runtime")?;
    let base = commit(root.path())?;
    Ok((root, base))
}

fn event(base: &str, head: &str) -> Value {
    json!({"pull_request": {"base": {"sha": base}, "head": {"sha": head}}})
}

#[test]
fn profiles_are_release_unless_manually_requested() -> Result<()> {
    assert_eq!(
        profile_policy("pull_request", &json!({"inputs": {"profiles": "full"}}))?,
        "release"
    );
    assert_eq!(profile_policy("push", &json!({}))?, "release");
    assert_eq!(profile_policy("workflow_dispatch", &json!({}))?, "release");
    assert_eq!(
        profile_policy(
            "workflow_dispatch",
            &json!({"inputs": {"profiles": "full"}})
        )?,
        "full"
    );
    for policy in [json!("typo"), json!(1), Value::Null] {
        assert!(
            profile_policy(
                "workflow_dispatch",
                &json!({"inputs": {"profiles": policy}})
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn scope_distinguishes_docs_sdk_node_and_build_inputs() {
    let targets = BTreeSet::new();
    let cases: &[(&str, &[&str])] = &[
        ("docs/upgrade.md", &[]),
        ("README.md", &[]),
        ("sdk/src/client.ts", &["sdk"]),
        ("core/indexer/src/reactor/engine.rs", &["rust", "sdk"]),
        ("core/indexer/src/database/init.rs", &["rust", "sdk"]),
        ("core/indexer/src/lib.rs", &["rust", "sdk", "docker_cache"]),
    ];
    for (path, expected) in cases {
        assert_eq!(
            classify(path, &targets),
            expected.iter().copied().collect(),
            "{path}"
        );
    }
    for path in [
        "core/Cargo.lock",
        "new-crate/Cargo.toml",
        "core/.cargo/config.toml",
        "rust-toolchain.toml",
        "unknown/input",
        ".github/workflows/ci.yml",
        "tools/ci/test-matrix.sh",
        ".github/actions/setup-docker/action.yml",
    ] {
        assert_eq!(
            classify(path, &targets),
            JOBS.into_iter().collect(),
            "{path}"
        );
    }
    for path in [
        "core/indexer/src/runtime/wit/deps/built-in/native.wit",
        "core/macros/src/interface.rs",
        "core/kontor-build/src/lib.rs",
        "native-contracts/binaries/token.wasm.br",
        "test-contracts/proxy/src/lib.rs",
        "sdk/src/component/kontor-sdk.core.wasm",
        "sdk/src/bindings.d.ts",
        "sdk/package-lock.json",
        "tools/build.json",
    ] {
        assert!(classify(path, &targets).contains("reproducible"), "{path}");
    }
    assert!(
        classify("core/custom.rs", &BTreeSet::from(["core/custom.rs".into()]))
            .contains("docker_cache")
    );
}

#[test]
fn stack_selection_preserves_execution_and_evidence_boundaries() {
    for path in [
        "core/indexer/src/runtime/new.rs",
        "core/indexer/src/protocol/v2/engine.rs",
        "core/indexer/proto/new.proto",
        "core/indexer/src/database/new.rs",
        "core/indexer/src/reactor/new.rs",
        "core/indexer/src/api/handlers/contracts.rs",
        "core/indexer/src/api/env.rs",
        "core/macros/src/lib.rs",
        "protocol-bundles/new/Cargo.toml",
        "tools/native-stack/new-input.json",
        "core/kontor-build/src/graph_build.rs",
        "new-executor/Cargo.lock",
        "new-executor/build.rs",
        "Dockerfile",
        "tools/kontor",
    ] {
        assert!(stack_relevant(path), "{path}");
    }
    for path in [
        "README.md",
        "docs/design/plan.md",
        "sdk/src/client.ts",
        "core/kontor-sdk/src/client.rs",
        "core/indexer/src/api/handlers/info.rs",
        "core/indexer/src/logging.rs",
        "core/indexer/src/metrics.rs",
        "core/.cargo/audit.toml",
        "core/kontor-build/src/node_evidence/comparison/manifest.rs",
        "core/kontor-build/tests/node_comparison.rs",
        "core/kontor-build/src/node_evidence/comparison/mod.rs",
        "core/kontor-build/src/ci_scope.rs",
        "core/kontor-build/src/ci_scope/tests.rs",
    ] {
        assert!(!stack_relevant(path), "{path}");
    }
}

#[test]
fn missing_history_and_unknown_events_never_skip() -> Result<()> {
    let root = fixture()?;
    for kind in [CiScope::Pr, CiScope::Stack, CiScope::Bundles] {
        for (name, value) in [
            ("pull_request", json!({})),
            ("unknown", json!({})),
            (
                "push",
                json!({"before": "0".repeat(40), "after": "a".repeat(40)}),
            ),
            (
                "push",
                json!({"before": "a".repeat(40), "after": "b".repeat(40)}),
            ),
        ] {
            let report = select(root.path(), kind, name, &value)?;
            if kind == CiScope::Pr {
                assert!(
                    report["jobs"]
                        .as_object()
                        .unwrap()
                        .values()
                        .all(|flag| flag == true)
                );
            } else {
                assert_eq!(report["required"], true);
                if kind == CiScope::Bundles {
                    assert_eq!(report["controls"], true);
                }
            }
        }
    }
    Ok(())
}

#[test]
fn git_diff_handles_large_changes_renames_newlines_and_base_advancement() -> Result<()> {
    let (root, base) = git_fixture()?;
    for number in 0..350 {
        write(root.path(), &format!("docs/{number}.md"), "documentation")?;
    }
    let docs = commit(root.path())?;
    assert_eq!(
        select(
            root.path(),
            CiScope::Stack,
            "pull_request",
            &event(&base, &docs)
        )?["required"],
        false
    );
    git(
        root.path(),
        &["mv", "core/indexer/src/runtime/old.rs", "renamed.rs"],
    )?;
    let head = commit(root.path())?;
    let report = select(
        root.path(),
        CiScope::Stack,
        "pull_request",
        &event(&base, &head),
    )?;
    assert!(
        report["paths"]
            .as_array()
            .unwrap()
            .contains(&json!("core/indexer/src/runtime/old.rs"))
    );
    fs::remove_file(root.path().join("renamed.rs"))?;
    git(
        root.path(),
        &["mv", "README.md", "core/indexer/src/runtime/new\nfile.rs"],
    )?;
    let moved = commit(root.path())?;
    assert!(
        changed_paths(root.path(), "pull_request", &event(&base, &moved))?
            .contains(&"core/indexer/src/runtime/new\nfile.rs".into())
    );
    git(root.path(), &["checkout", "-q", "--detach", &base])?;
    write(
        root.path(),
        "core/indexer/src/runtime/base.rs",
        "base advancement",
    )?;
    let advanced = commit(root.path())?;
    assert_eq!(
        select(
            root.path(),
            CiScope::Stack,
            "pull_request",
            &event(&advanced, &docs)
        )?["required"],
        false
    );
    assert_eq!(
        select(
            root.path(),
            CiScope::Stack,
            "push",
            &json!({"before":base,"after":advanced})
        )?["required"],
        true
    );
    Ok(())
}

#[test]
fn tooling_changes_use_focused_checks_and_paths_union_jobs() -> Result<()> {
    let (root, base) = git_fixture()?;
    write(
        root.path(),
        "core/kontor-build/tests/node_comparison.rs",
        "evidence",
    )?;
    write(
        root.path(),
        "core/kontor-build/src/node_evidence/comparison/mod.rs",
        "evidence",
    )?;
    let head = commit(root.path())?;
    let report = select(
        root.path(),
        CiScope::Bundles,
        "pull_request",
        &event(&base, &head),
    )?;
    assert_eq!(report["required"], false);
    assert_eq!(report["controls"], false);
    assert_eq!(
        select(
            root.path(),
            CiScope::Pr,
            "pull_request",
            &event(&base, &head)
        )?["jobs"]["tooling"],
        true
    );
    assert_eq!(
        outputs(CiScope::Bundles, &report)?["profile_policy"],
        "release"
    );
    write(root.path(), "core/indexer/src/api/handlers/info.rs", "API")?;
    let head = commit(root.path())?;
    assert_eq!(
        select(
            root.path(),
            CiScope::Bundles,
            "pull_request",
            &event(&base, &head)
        )?["required"],
        false
    );
    write(root.path(), "core/macros/src/interface.rs", "macros")?;
    let head = commit(root.path())?;
    let report = select(
        root.path(),
        CiScope::Pr,
        "pull_request",
        &event(&base, &head),
    )?;
    assert_eq!(report["jobs"]["rust"], true);
    assert_eq!(report["jobs"]["sdk"], true);
    assert_eq!(report["jobs"]["reproducible"], true);
    Ok(())
}

#[test]
fn newly_added_target_workspace_and_patch_dependencies_are_conservative() -> Result<()> {
    let root = fixture()?;
    validate_repro_dependencies(root.path())?;
    let package = "[package]\nname='fixture'\nversion='1.0.0'\n";
    for table in [
        "dependencies",
        "build-dependencies",
        "dev-dependencies",
        "target.'cfg(unix)'.dependencies",
    ] {
        write(
            root.path(),
            "core/kontor-sdk-wasm/Cargo.toml",
            &format!("{package}[{table}]\nnew={{path='../new-dependency'}}"),
        )?;
        assert!(
            validate_repro_dependencies(root.path())
                .unwrap_err()
                .to_string()
                .contains("uncovered artifact dependency")
        );
    }
    write(
        root.path(),
        "core/Cargo.toml",
        "[workspace]\nmembers=[]\n[workspace.dependencies]\nnew={path='new-dependency'}",
    )?;
    write(
        root.path(),
        "core/kontor-sdk-wasm/Cargo.toml",
        &format!("{package}[dependencies]\nnew={{workspace=true}}"),
    )?;
    assert!(
        validate_repro_dependencies(root.path())
            .unwrap_err()
            .to_string()
            .contains("uncovered artifact dependency")
    );
    write(root.path(), "core/kontor-sdk-wasm/Cargo.toml", package)?;
    write(
        root.path(),
        "core/Cargo.toml",
        "[workspace]\nmembers=[]\n[patch.crates-io]\nnew={path='new-dependency'}",
    )?;
    assert!(
        validate_repro_dependencies(root.path())
            .unwrap_err()
            .to_string()
            .contains("uncovered artifact dependency")
    );
    Ok(())
}

#[test]
fn invalid_manifests_missing_workspace_deps_and_missing_globs_select_all() -> Result<()> {
    let root = fixture()?;
    for input in [
        "invalid toml = [",
        "[package]\nname='fixture'\n[dependencies]\nnew={workspace=true}",
    ] {
        write(root.path(), "core/kontor-sdk-wasm/Cargo.toml", input)?;
        let report = select(root.path(), CiScope::Pr, "workflow_dispatch", &json!({}))?;
        assert!(
            report["reason"]
                .as_str()
                .unwrap()
                .starts_with("cannot establish scope")
        );
        assert!(
            report["jobs"]
                .as_object()
                .unwrap()
                .values()
                .all(|flag| flag == true)
        );
    }
    write(
        root.path(),
        "native-contracts/Cargo.toml",
        "[workspace]\nmembers=['missing-*']",
    )?;
    assert!(validate_repro_dependencies(root.path()).is_err());
    Ok(())
}

#[test]
fn explicit_targets_include_missing_files_without_traversing_build_outputs() -> Result<()> {
    let root = fixture()?;
    write(
        root.path(),
        "core/kontor-build/Cargo.toml",
        "[package]\nname='build'\nbuild='custom/build.rs'\n[lib]\npath='custom/library.rs'\n[[bin]]\nname='tool'\npath='custom/entry.rs'",
    )?;
    write(
        root.path(),
        "core/target/bogus/Cargo.toml",
        "not a manifest",
    )?;
    assert_eq!(
        docker_target_paths(root.path())?,
        BTreeSet::from([
            "core/kontor-build/custom/build.rs".into(),
            "core/kontor-build/custom/library.rs".into(),
            "core/kontor-build/custom/entry.rs".into()
        ])
    );
    Ok(())
}

#[test]
fn repository_dependency_coverage_remains_complete() -> Result<()> {
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned();
    validate_repro_dependencies(&root)?;
    assert!(docker_target_paths(&root)?.contains("core/indexer/src/main.rs"));
    Ok(())
}

#[test]
fn qualification_scope_is_conservative_but_tooling_does_not_launch_nodes() {
    let targets = BTreeSet::new();
    for path in [
        "core/kontor-build/src/ci_scope.rs",
        "core/kontor-build/tests/linker_wrapper.rs",
        ".github/actions/setup-kontor-tools/action.yml",
        "core/kontor-build/src/node_evidence/comparison/mod.rs",
    ] {
        assert_eq!(classify(path, &targets), BTreeSet::from(["tooling"]));
        assert!(!stack_relevant(path), "{path}");
        assert!(!bundle_relevant(path), "{path}");
    }
    for path in [
        "core/kontor-build/src/graph_build.rs",
        "core/kontor-build/src/compiler_wrapper.rs",
        "core/kontor-build/Cargo.lock",
        "core/indexer/src/runtime/ownership/mod.rs",
        "new-executor/unknown-input",
        ".github/workflows/rust-tests.yml",
    ] {
        assert!(stack_relevant(path), "{path}");
        assert!(bundle_relevant(path), "{path}");
    }
    assert!(stack_relevant(
        "core/kontor-build/src/stack_evidence/capture.rs"
    ));
    assert!(!bundle_relevant(
        "core/kontor-build/src/stack_evidence/capture.rs"
    ));
    assert!(!bundle_relevant("core/indexer/src/api/handlers/info.rs"));
    assert!(bundle_relevant(
        "core/indexer/src/api/handlers/contracts.rs"
    ));
}

#[test]
fn test_matrix_runs_the_union_without_duplicate_platform_builds() -> Result<()> {
    let script = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tools/ci/test-matrix.sh");
    for (ordinary, stack, count, workspace_count) in [
        (false, false, 0, 0),
        (true, false, 2, 2),
        (false, true, 6, 0),
        (true, true, 6, 2),
    ] {
        let root = tempdir()?;
        let output = root.path().join("outputs");
        let status = Command::new("bash")
            .arg(&script)
            .env("RUST_TESTS", ordinary.to_string())
            .env("STACK_TESTS", stack.to_string())
            .env("GITHUB_OUTPUT", &output)
            .status()?;
        assert!(status.success());
        let text = fs::read_to_string(output)?;
        let report: Value = serde_json::from_str(
            text.lines()
                .next()
                .unwrap()
                .strip_prefix("matrix=")
                .unwrap(),
        )?;
        let cells = report["include"].as_array().unwrap();
        assert_eq!(cells.len(), count);
        assert_eq!(
            cells.iter().filter(|c| c["workspace"] == true).count(),
            workspace_count
        );
        let unique: BTreeSet<_> = cells
            .iter()
            .map(|c| (c["os"].as_str().unwrap(), c["profile"].as_str().unwrap()))
            .collect();
        assert_eq!(unique.len(), cells.len());
        assert!(text.contains(&format!("required={}\n", count > 0)));
    }
    Ok(())
}
