use super::*;
use crate::execution_definition::SEMANTIC_TREES;
use crate::recipes::Graph;
use std::os::unix::fs::PermissionsExt;
use tempfile::{TempDir, tempdir};

const CARGO: &str = r#"#!/bin/sh
printf '%s\n' "$*" >> "$TRACE"
if [ "$1" = metadata ]; then
    if [ -n "$EXPECTED_CWD" ] && [ "$PWD" != "$EXPECTED_CWD" ]; then
        echo 'wrong metadata working directory' >&2
        exit 19
    fi
    cat "$METADATA"
    exit 0
fi
if [ "$MODE" = fail ]; then
    echo 'compiler stdout'
    echo 'compiler stderr' >&2
    exit 17
fi
mkdir -p "$CARGO_TARGET_DIR/$FIXTURE_TARGET/debug"
facade="$CARGO_TARGET_DIR/$FIXTURE_TARGET/debug/libfixture-abc.rlib"
printf 'compiled facade' > "$facade"
printf '{"reason":"compiler-artifact","target":{"name":"fixture","kind":["rlib"]},"filenames":["%s"]}\n' "$facade"
case "$MODE" in
    wrapper) printf 'changed' >> "$RUSTC_WRAPPER" ;;
    lock) printf '\n' >> "$GRAPH_MANIFEST_DIR/Cargo.lock" ;;
    source) printf '\n' >> "$GRAPH_MANIFEST_DIR/lib.rs" ;;
    metadata) cp "$CHANGED_METADATA" "$METADATA" ;;
esac
"#;
struct Fixture {
    temp: TempDir,
    graphs: Graphs,
    env: Environment,
    wrapper: PathBuf,
    options: Options,
}
fn file(root: &Path, name: &str, text: &str) -> Result<PathBuf> {
    let path = root.join(name);
    fs::create_dir_all(path.parent().unwrap())?;
    fs::write(&path, text)?;
    Ok(path)
}
impl Fixture {
    fn new() -> Result<Self> {
        let temp = tempdir()?;
        let root = temp.path();
        let manifest = file(
            root,
            "protocol-bundles/consensus-first/Cargo.toml",
            "[package]\nname='fixture'\nversion='1.0.0'\n[profile.dev]\npanic='unwind'\n[profile.release]\npanic='unwind'\n",
        )?;
        file(
            root,
            "protocol-bundles/consensus-first/Cargo.lock",
            "[[package]]\nname='fixture'\nversion='1.0.0'\n",
        )?;
        file(
            root,
            "protocol-bundles/consensus-first/lib.rs",
            "pub fn fixture() {}",
        )?;
        for tree in [
            "protocol-bundles/consensus",
            "core/indexer/src/consensus",
            "core/indexer/proto",
        ] {
            file(root, &format!("{tree}/fixture.rs"), "// fixture")?;
        }
        for path in [
            "identity.rs",
            "canonical_codec.rs",
            "migration_work.rs",
            "coordinator/activation.rs",
            "coordinator/certified_input.rs",
            "coordinator/certified_decision.rs",
            "coordinator/control.rs",
            "coordinator/manifest.rs",
        ] {
            file(
                root,
                &format!("core/indexer/src/protocol/{path}"),
                "// fixture",
            )?;
        }
        file(
            root,
            "core/kontor-build/src/bin/kontor-graph-rustc.rs",
            "compiler wrapper source",
        )?;
        let wrapper = file(root, "wrapper", "compiled wrapper")?;
        file(
            root,
            "core/indexer/src/protocol/coordinator/managed.rs",
            "// adapter",
        )?;
        fs::create_dir_all(root.join("core/indexer/src/protocol/coordinator/managed"))?;
        fs::create_dir_all(root.join("tools/protocol-bundles"))?;
        let graph = Graph {
            directory: "consensus-first".into(),
            revision: None,
            version: None,
            itoa: None,
            lift_rate: 0,
            kind: Kind::Consensus,
            native_patches: vec![],
            malachite_engine: false,
            source_root: ".".into(),
            source_snapshot: None,
        };
        let data = json!({"workspace_root":manifest.parent(),"packages":[{"id":"fixture","name":"fixture","version":"1.0.0","manifest_path":manifest,"source":null}],"resolve":{"root":"fixture","nodes":[{"id":"fixture","features":[],"deps":[]}]}});
        let metadata = file(root, "metadata.json", &serde_json::to_string(&data)?)?;
        let mut changed = data;
        changed["resolve"]["nodes"][0]["features"] = json!(["extra"]);
        let changed_metadata = file(root, "changed.json", &serde_json::to_string(&changed)?)?;
        let cargo = file(root, "bin/cargo", CARGO)?;
        fs::set_permissions(cargo, fs::Permissions::from_mode(0o755))?;
        let target = "x86_64-unknown-linux-gnu";
        let env = Environment::from([
            (
                "PATH".into(),
                format!("{}:/usr/bin:/bin", root.join("bin").display()),
            ),
            ("TRACE".into(), root.join("trace").display().to_string()),
            ("METADATA".into(), metadata.display().to_string()),
            (
                "CHANGED_METADATA".into(),
                changed_metadata.display().to_string(),
            ),
            (
                "GRAPH_MANIFEST_DIR".into(),
                manifest.parent().unwrap().display().to_string(),
            ),
            ("FIXTURE_TARGET".into(), target.into()),
        ]);
        Ok(Self {
            temp,
            graphs: Graphs::from([("first".into(), graph)]),
            env,
            wrapper,
            options: Options {
                target: target.into(),
                profile: "release".into(),
                jobs: 1,
                offline: true,
            },
        })
    }
    fn build(&self) -> Result<Value> {
        compile_graph(
            self.temp.path(),
            "first",
            &self.graphs,
            &self.options,
            &self.env,
            &self.temp.path().join("output"),
            &self.wrapper,
            &self.temp.path().join("cargo-home"),
        )
    }
}
#[test]
fn compiles_stages_and_records_locked_platform_specific_inputs() -> Result<()> {
    let f = Fixture::new()?;
    let report = f.build()?;
    assert_eq!(report["graph"], "first");
    assert_eq!(report["artifacts"].as_array().unwrap().len(), 1);
    assert_eq!(
        fs::read_to_string(report["facade"].as_str().unwrap())?,
        "compiled facade"
    );
    let trace = fs::read_to_string(f.temp.path().join("trace"))?;
    assert_eq!(trace.lines().count(), 3);
    assert!(
        trace
            .lines()
            .all(|line| line.contains("--locked") && line.contains("--offline"))
    );
    let build = trace.lines().nth(1).unwrap();
    assert!(build.contains("--profile release -j 1 --message-format=json-render-diagnostics"));
    assert!(
        trace
            .lines()
            .next()
            .unwrap()
            .contains("--filter-platform x86_64-unknown-linux-gnu")
    );
    assert!(!f.env.contains_key("RUSTC_WRAPPER"));
    Ok(())
}
#[test]
fn compiler_failures_and_mid_build_mutations_do_not_emit_success_reports() -> Result<()> {
    for (mode, message) in [
        ("fail", "compiler stderr"),
        ("wrapper", "wrapper changed"),
        ("lock", "modified the dependency lock"),
        ("source", "source inputs changed"),
        ("metadata", "metadata changed"),
    ] {
        let mut f = Fixture::new()?;
        f.env.insert("MODE".into(), mode.into());
        let error = f.build().unwrap_err().to_string();
        assert!(error.contains(message), "{mode}: {error}");
        assert!(
            !f.temp
                .path()
                .join("output/first/build-inputs.json")
                .exists()
        );
    }
    Ok(())
}
#[test]
fn stale_execution_definition_rejects_before_compiling_and_uses_unfiltered_metadata() -> Result<()>
{
    let mut f = Fixture::new()?;
    f.graphs.get_mut("first").unwrap().kind = Kind::Executor;
    for name in SEMANTIC_TREES {
        fs::create_dir_all(f.temp.path().join(name))?;
    }
    file(
        f.temp.path(),
        "protocol-bundles/consensus-first/definition.bin",
        "stale",
    )?;
    assert!(
        f.build()
            .unwrap_err()
            .to_string()
            .contains("reference differs")
    );
    let trace = fs::read_to_string(f.temp.path().join("trace"))?;
    let commands: Vec<_> = trace.lines().collect();
    assert_eq!(commands.len(), 2);
    assert!(commands[0].contains("--filter-platform"));
    assert!(!commands[1].contains("--filter-platform"));
    assert!(commands.iter().all(|line| line.starts_with("metadata")
        && line.contains("--locked")
        && line.contains("--offline")));
    Ok(())
}
#[test]
fn metadata_and_logging_preserve_arguments_working_directory_and_exit_status() -> Result<()> {
    let mut f = Fixture::new()?;
    let working_directory = f.temp.path().canonicalize()?;
    f.env.insert(
        "EXPECTED_CWD".into(),
        working_directory.display().to_string(),
    );
    metadata(
        &f.temp.path().join("manifest with spaces"),
        None,
        &f.env,
        true,
        &["one".into(), "two".into()],
        f.temp.path(),
    )?;
    let trace = fs::read_to_string(f.temp.path().join("trace"))?;
    assert!(trace.contains("--features one,two"));
    assert!(!trace.contains("--filter-platform"));
    assert!(trace.contains("--locked"));
    assert!(trace.contains("--offline"));
    let log = f.temp.path().join("failure.log");
    let args = vec![
        "/bin/sh".into(),
        "-c".into(),
        "printf '%s' \"$PWD\"; printf 'stderr' >&2; exit 7".into(),
    ];
    assert!(
        run_logged(&args, f.temp.path(), &f.env, &log)
            .unwrap_err()
            .to_string()
            .contains("7")
    );
    assert_eq!(
        fs::read_to_string(log)?,
        format!("{}stderr", working_directory.display())
    );
    Ok(())
}

#[test]
fn incompatible_panic_profile_rejects_before_invoking_cargo() -> Result<()> {
    let f = Fixture::new()?;
    let manifest = f
        .temp
        .path()
        .join("protocol-bundles/consensus-first/Cargo.toml");
    fs::write(
        &manifest,
        fs::read_to_string(&manifest)?.replace("panic='unwind'", "panic='abort'"),
    )?;
    assert!(
        f.build()
            .unwrap_err()
            .to_string()
            .contains("common unwind runtime")
    );
    assert!(!f.temp.path().join("trace").exists());
    Ok(())
}
