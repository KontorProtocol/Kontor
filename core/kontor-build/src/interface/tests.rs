use super::*;
use std::env;
use std::os::unix::fs::PermissionsExt;
use tempfile::tempdir;

#[test]
fn selection_requires_retained_identity_and_consensus_role() -> Result<()> {
    assert!(selection(&[json!({"graph":"first"})]).is_err());
    for identity in [json!(null), json!([]), json!("executor")] {
        assert!(
            selection(&[
                json!({"graph":"first","identity":identity}),
                json!({"graph":"second"})
            ])
            .is_err()
        );
    }
    assert!(selection(&[json!({"graph":"second","identity":{"kind":"consensus"}})]).is_err());
    assert!(selection(&[json!({"graph":"first","identity":{"kind":"consensus"}})])? == CONSENSUS);
    assert!(selection(&[json!({"graph":"first"}), json!({"graph":"second"})])? == PROBES);
    assert!(
        selection(&[
            json!({"graph":"first","identity":{"kind":"consensus"}}),
            json!({"graph":"second","identity":{"kind":"consensus"}})
        ])
        .is_err()
    );
    {
        let recipe = executor_graphs(Some("managed-node"))?
            .remove("first")
            .unwrap();
        let mut graphs = vec![
            json!({"graph":"first","identity":{"source_root":recipe.source_root,"source_snapshot":recipe.source_snapshot}}),
            json!({"graph":"observer"}),
        ];
        assert!(selection(&graphs)? == PROBES);
        graphs[0]["identity"]["source_snapshot"] = json!("substituted");
        assert!(selection(&graphs).is_err());
    }
    Ok(())
}
#[test]
fn diagnostics_reject_wrong_codes_success_and_crashes() -> Result<()> {
    let diagnostic = |code| json!({"level":"error","code":{"code":code}}).to_string();
    check_diagnostics(0, "", None)?;
    check_diagnostics(1, &diagnostic("E0308"), Some("E0308"))?;
    check_diagnostics(1, &diagnostic("E0603"), Some("E0603"))?;
    for (status, text) in [
        (0, String::new()),
        (-9, String::new()),
        (0, diagnostic("E0308")),
        (1, diagnostic("E0463")),
        (
            1,
            format!("{}\n{}", diagnostic("E0308"), diagnostic("E0463")),
        ),
    ] {
        assert!(check_diagnostics(status, &text, Some("E0308")).is_err());
    }
    assert!(check_diagnostics(0, "[]", None).is_err());
    Ok(())
}

#[test]
fn consensus_inputs_require_private_tokio_and_unchanged_staged_libraries() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path();
    let facade = root.join("libconsensus.rlib");
    let tokio = root.join("libtokio-fixture.rlib");
    fs::write(&facade, "facade")?;
    fs::write(&tokio, "tokio")?;
    let graphs = vec![json!({"graph":"first", "identity":{"kind":"consensus"},
        "facade":facade, "link_inputs":root,
        "artifacts":[{"path":facade,"sha256":sha256(&facade)?},{"path":tokio,"sha256":sha256(&tokio)?}]})];
    let (arguments, libraries) = inputs_for(&graphs, true, root)?;
    assert_eq!(
        libraries,
        json!({"first":sha256(&facade)?,"first_tokio":sha256(&tokio)?})
    );
    assert!(arguments.contains(&format!("dependency={}", root.display())));
    for library in [&facade, &tokio] {
        let original = fs::read(library)?;
        fs::write(library, "substituted")?;
        assert!(inputs_for(&graphs, true, root).is_err());
        fs::write(library, original)?;
    }
    let mut missing = graphs.clone();
    missing[0]["artifacts"].as_array_mut().unwrap().pop();
    assert!(inputs_for(&missing, true, root).is_err());
    let mut untyped = graphs;
    untyped[0].as_object_mut().unwrap().remove("identity");
    assert!(inputs_for(&untyped, false, root).is_err());
    Ok(())
}
#[test]
fn report_encoding_preserves_ascii_escaping_and_rejects_ambiguous_numbers() -> Result<()> {
    assert_eq!(
        encoded(&json!({"z":"é😀", "a":[1,false]}), false)?,
        r#"{"a":[1,false],"z":"\u00e9\ud83d\ude00"}"#
    );
    assert!(encoded(&json!({"float":1.0}), false).is_err());
    Ok(())
}
#[test]
fn capture_preserves_environment_cwd_status_and_times_out() -> Result<()> {
    let dir = tempdir()?;
    let env = Environment::from([("CHECK".into(), "explicit".into())]);
    let (code, out, err) = capture(
        dir.path(),
        &env,
        "/bin/sh",
        &[
            "-c".into(),
            "printf '%s' \"$CHECK\"; printf 'diagnostic' >&2; exit 7".into(),
        ],
        Duration::from_secs(2),
    )?;
    assert_eq!(
        (code, out.as_str(), err.as_str()),
        (7, "explicit", "diagnostic")
    );
    assert!(
        capture(
            dir.path(),
            &env,
            "/bin/sh",
            &["-c".into(), "exec /bin/sleep 10".into()],
            Duration::from_millis(20)
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn real_compiler_controls_and_report_tampering() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path();
    let env: Environment = env::vars().collect();
    let (code, version, _) = capture(
        root,
        &env,
        "rustc",
        &["-vV".into()],
        Duration::from_secs(10),
    )?;
    assert_eq!(code, 0);
    let target = version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .context("compiler host")?;
    let mut env = env;
    env.insert("RUSTC".into(), "rustc".into());
    let mut graphs = Vec::new();
    for label in ["first", "second"] {
        let mut artifacts = Vec::new();
        let mut facade = PathBuf::new();
        for (name, source) in [
            (
                "facade",
                "pub type Factory=u64; mod runtime {pub struct Runtime;}",
            ),
            ("wasmtime", "pub struct Engine;"),
            ("tokio", "pub mod runtime {pub struct Handle;}"),
        ] {
            let path = root.join(format!("{label}_{name}.rs"));
            fs::write(&path, source)?;
            let library = root.join(format!("lib{name}-{label}.rlib"));
            let args = vec![
                "--crate-type=rlib".into(),
                "--crate-name".into(),
                name.into(),
                format!("-Cmetadata={label}"),
                path.display().to_string(),
                "-o".into(),
                library.display().to_string(),
            ];
            let (code, _, err) = capture(root, &env, "rustc", &args, Duration::from_secs(15))?;
            ensure!(code == 0, "fixture compile: {err}");
            if name == "facade" {
                facade = library.clone();
            }
            artifacts.push(json!({"path":library.file_name().unwrap().to_str().unwrap(),"sha256":sha256(&library)?}));
        }
        graphs
            .push(json!({"graph":label,"facade":facade.file_name().unwrap().to_str().unwrap(),"link_inputs":".","artifacts":artifacts}));
    }
    let binding = verify(&graphs, target, &env, root, root)?;
    let evidence = root.join("type-boundary");
    verify_report(&evidence, &binding, &graphs, target)?;
    let log = evidence.join("wasmtime-engine.log");
    let original = fs::read(&log)?;
    fs::write(&log, "substituted")?;
    assert!(verify_report(&evidence, &binding, &graphs, target).is_err());
    fs::write(&log, original)?;
    let mut changed = graphs.clone();
    changed[0]["artifacts"][0]["sha256"] = json!("substituted");
    assert!(verify_report(&evidence, &binding, &changed, target).is_err());
    // Failed reruns must not retain a previous successful result binding.
    assert!(verify(&changed, target, &env, root, root).is_err());
    assert!(!evidence.join("result.json").exists());
    Ok(())
}
#[test]
fn adapter_results_require_every_named_test_and_success() {
    let output = ADAPTER_TESTS
        .iter()
        .map(|name| format!("test {name} ... ok\n"))
        .collect::<String>()
        + &format!(
            "test result: ok. {} passed; 0 failed; 0 ignored;",
            ADAPTER_TESTS.len()
        );
    assert!(adapter_tests_passed(0, &output));
    assert!(!adapter_tests_passed(1, &output));
    assert!(!adapter_tests_passed(
        0,
        &output.replace(ADAPTER_TESTS[0], "unrelated")
    ));
    assert!(!adapter_tests_passed(
        0,
        &output.replace("0 ignored", "1 ignored")
    ));
}

#[test]
fn adapter_runner_binds_sources_logs_and_named_test_results() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path();
    let facade = root.join("libconsensus.rlib");
    let tokio = root.join("libtokio-fixture.rlib");
    fs::write(&facade, "facade")?;
    fs::write(&tokio, "tokio")?;
    let graphs = vec![json!({"graph":"first", "identity":{"kind":"consensus"},
        "facade":facade, "link_inputs":root,
        "artifacts":[{"path":facade,"sha256":sha256(&facade)?},{"path":tokio,"sha256":sha256(&tokio)?}]})];
    let compiler = root.join("compiler.sh");
    let lines = ADAPTER_TESTS
        .iter()
        .map(|name| format!("test {name} ... ok\n"))
        .collect::<String>()
        + &format!(
            "test result: ok. {} passed; 0 failed; 0 ignored;\n",
            ADAPTER_TESTS.len()
        );
    fs::write(
        &compiler,
        format!(
            "#!/bin/sh\nwhile [ \"$1\" != '-o' ]; do shift; done\nshift\ncat > \"$1\" <<'SCRIPT'\n#!/bin/sh\ncat <<'RESULTS'\n{lines}RESULTS\nSCRIPT\nchmod +x \"$1\"\n"
        ),
    )?;
    fs::set_permissions(&compiler, fs::Permissions::from_mode(0o755))?;
    let mut env: Environment = env::vars().collect();
    env.insert("RUSTC".into(), compiler.display().to_string());
    let binding = verify_adapter(root, &graphs, "fixture", &env, root, root)?;
    let directory = root.join("node-adapter");
    verify_adapter_report(&directory, &binding, &graphs)?;
    let source = directory.join("adapter.rs");
    let original = fs::read_to_string(&source)?;
    fs::write(
        &source,
        original.replace("managed/types.rs", "other/types.rs"),
    )?;
    let mut changed = binding.clone();
    changed["source_sha256"] = json!(sha256(&source)?);
    assert!(verify_adapter_report(&directory, &changed, &graphs).is_err());
    fs::write(source, original)?;
    fs::write(
        directory.join("test.log"),
        format!(
            "test result: ok. {} passed; 0 failed; 0 ignored;",
            ADAPTER_TESTS.len()
        ),
    )?;
    changed = binding.clone();
    changed["test_log_sha256"] = json!(sha256(&directory.join("test.log"))?);
    assert!(verify_adapter_report(&directory, &changed, &graphs).is_err());
    fs::write(&compiler, "#!/bin/sh\necho 'compile failed' >&2\nexit 1\n")?;
    assert!(verify_adapter(root, &graphs, "fixture", &env, root, root).is_err());
    Ok(())
}
