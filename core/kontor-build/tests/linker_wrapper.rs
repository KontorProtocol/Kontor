#![cfg(unix)]

use std::fs;
use std::io::Write;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

use anyhow::Result;
use kontor_build::linker_record::{digest, executable, validate};
use serde_json::{Value, json};
use tempfile::{TempDir, tempdir};

struct Fixture {
    root: TempDir,
    spec: PathBuf,
    record: PathBuf,
    source: PathBuf,
    output: PathBuf,
}

impl Fixture {
    fn new() -> Result<Self> {
        let root = tempdir()?;
        let spec = root.path().join("spec.json");
        let record = root.path().join("record.json");
        fs::write(&spec, json!({"linker_record":record}).to_string())?;
        let source = root.path().join("main.c");
        fs::write(&source, "int main(void) { return 0; }\n")?;
        let output = root.path().join("program");
        Ok(Self {
            root,
            spec,
            record,
            source,
            output,
        })
    }

    fn command(&self, driver: &str) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kontor-node-linker"));
        command
            .env("KONTOR_NODE_LINK_SPEC", &self.spec)
            .env("KONTOR_REAL_LINKER", driver)
            .env("CCACHE_DISABLE", "1")
            .env_remove("COLLECT_LD_OVERRIDE");
        command
    }

    fn linked(&self, output: Output) -> Result<Value> {
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let record: Value = serde_json::from_slice(&fs::read(&self.record)?)?;
        validate(&record, &digest(&self.spec)?, &digest(&self.output)?, None)?;
        assert!(Command::new(&self.output).status()?.success());
        Ok(record)
    }
}

#[test]
fn real_driver_backend_record_and_cli_verifier_agree() -> Result<()> {
    let fixture = Fixture::new()?;
    let record = fixture.linked(
        fixture
            .command("cc")
            .arg(&fixture.source)
            .arg("-o")
            .arg(&fixture.output)
            .output()?,
    )?;
    assert_eq!(
        record["backend"]["sha256"],
        digest(Path::new(record["backend"]["path"].as_str().unwrap()))?
    );
    let request = json!({"record": record, "spec_hash": digest(&fixture.spec)?, "output_hash": digest(&fixture.output)?});
    let mut verifier = Command::new(env!("CARGO_BIN_EXE_kontor-build"))
        .arg("verify-linker-record")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    verifier
        .stdin
        .take()
        .unwrap()
        .write_all(request.to_string().as_bytes())?;
    let output = verifier.wait_with_output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn clang_direct_backend_and_failed_link() -> Result<()> {
    if executable("clang").is_err() {
        eprintln!("clang unavailable, direct-backend case not exercised");
        return Ok(());
    }
    let fixture = Fixture::new()?;
    let record = fixture.linked(
        fixture
            .command("clang")
            .arg(&fixture.source)
            .arg("-o")
            .arg(&fixture.output)
            .output()?,
    )?;
    assert!(record["selection"]["backend_query"].is_null());
    let failed = fixture
        .command("clang")
        .arg(fixture.root.path().join("missing.c"))
        .arg("-o")
        .arg(&fixture.output)
        .output()?;
    assert!(!failed.status.success());
    assert!(!fixture.record.exists());
    Ok(())
}

fn script(path: &Path, text: &str) -> Result<()> {
    fs::write(path, format!("#!/bin/sh\nset -eu\n{text}\n"))?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
    Ok(())
}

#[test]
#[cfg(target_os = "linux")]
fn gcc_response_files_preserve_b_search_and_fuse_ld() -> Result<()> {
    let fixture = Fixture::new()?;
    let baseline = fixture.linked(
        fixture
            .command("cc")
            .arg(&fixture.source)
            .arg("-o")
            .arg(&fixture.output)
            .output()?,
    )?;
    let directory = fixture.root.path().join("rust linker search");
    fs::create_dir(&directory)?;
    let linker = directory.join("ld.lld");
    let marker = fixture.root.path().join("invoked");
    script(
        &linker,
        "printf used > \"$MARKER\"\nexec \"$ACTUAL_LINKER\" \"$@\"",
    )?;
    let arguments = vec![
        "-B".into(),
        directory.to_str().unwrap().into(),
        "-fuse-ld=lld".into(),
        fixture.source.to_str().unwrap().into(),
        "-o".into(),
        fixture.output.to_str().unwrap().into(),
    ];
    let response = fixture.root.path().join("arguments");
    fs::write(
        &response,
        arguments
            .iter()
            .map(|arg: &String| serde_json::to_string(arg).unwrap())
            .collect::<Vec<_>>()
            .join(" "),
    )?;
    let outer = fixture.root.path().join("outer");
    fs::write(&outer, format!("@{}", response.display()))?;
    let record = fixture.linked(
        fixture
            .command("cc")
            .arg(format!("@{}", outer.display()))
            .env("MARKER", &marker)
            .env(
                "ACTUAL_LINKER",
                baseline["backend"]["invocation_path"].as_str().unwrap(),
            )
            .output()?,
    )?;
    assert_eq!(fs::read_to_string(marker)?, "used");
    assert_eq!(record["backend"]["path"], json!(linker.canonicalize()?));
    assert_eq!(record["backend"]["sha256"], digest(&linker)?);
    assert_eq!(record["expanded_arguments"], json!(arguments));
    Ok(())
}

#[test]
fn rejects_custom_driver_controls_before_execution() -> Result<()> {
    let fixture = Fixture::new()?;
    for option in ["-specs=custom", "--specs=custom", "-wrapper=custom"] {
        let failed = fixture
            .command("cc")
            .arg(option)
            .arg(&fixture.source)
            .arg("-o")
            .arg(&fixture.output)
            .output()?;
        assert!(!failed.status.success());
        assert!(String::from_utf8(failed.stderr)?.contains("custom compiler specs/wrappers"));
    }
    let failed = fixture
        .command("cc")
        .env("COLLECT_LD_OVERRIDE", "another")
        .output()?;
    assert!(!failed.status.success());
    assert!(String::from_utf8(failed.stderr)?.contains("COLLECT_LD_OVERRIDE"));
    assert!(!fixture.output.exists() && !fixture.record.exists());
    Ok(())
}

#[test]
fn tool_or_spec_changes_during_link_do_not_produce_success_records() -> Result<()> {
    let fixture = Fixture::new()?;
    let backend = fixture.root.path().join("ld");
    script(&backend, "exit 0")?;
    let driver = fixture.root.path().join("driver");
    for mutation in [
        "printf '\\n# changed\\n' >> \"$0\"",
        "printf '{}' > \"$KONTOR_NODE_LINK_SPEC\"",
    ] {
        fs::write(
            &fixture.spec,
            json!({"linker_record":fixture.record}).to_string(),
        )?;
        script(
            &driver,
            &format!(
                "if [ \"${{1:-}}\" = '-###' ]; then printf '\"%s\"\\n' \"$BACKEND\" >&2; exit 0; fi\nprintf output > \"$OUTPUT\"\n{mutation}"
            ),
        )?;
        let output = fixture
            .command(driver.to_str().unwrap())
            .args(["-o"])
            .arg(&fixture.output)
            .env("BACKEND", &backend)
            .env("OUTPUT", &fixture.output)
            .output()?;
        assert!(!output.status.success());
        assert!(String::from_utf8(output.stderr)?.contains("changed during"));
        assert!(!fixture.record.exists());
    }
    Ok(())
}

#[test]
fn real_rust_compiler_binds_completed_output_and_clears_failed_build_evidence() -> Result<()> {
    let fixture = Fixture::new()?;
    let compiler = executable("rustc")?["invocation_path"]
        .as_str()
        .unwrap()
        .to_owned();
    let linker = Path::new(env!("CARGO_BIN_EXE_kontor-node-linker"));
    let roots = fixture.root.path().join("roots.json");
    let spec = json!({"compiler":compiler,"graphs":[],"linker_wrapper":linker,"linker_wrapper_sha256":digest(linker)?,
        "root_objects": roots,"linker_record":fixture.record});
    fs::write(&fixture.spec, spec.to_string())?;
    let source = fixture.root.path().join("main.rs");
    fs::write(&source, "fn main() { println!(\"compiler output\"); }")?;
    let command = || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kontor-node-rustc"));
        command
            .arg(&compiler)
            .arg(&source)
            .args(["--crate-name", "kontor", "--crate-type", "bin", "--out-dir"])
            .arg(fixture.root.path())
            .args([
                "-Cextra-filename=-test",
                "-Cdebuginfo=2",
                "-Cstrip=debuginfo",
            ])
            .env("KONTOR_NODE_LINK_SPEC", &fixture.spec)
            .env("CCACHE_DISABLE", "1");
        command
    };
    let result = command().output()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let binary = fixture.root.path().join("kontor-test");
    assert_eq!(Command::new(&binary).output()?.stdout, b"compiler output\n");
    let link: Value = serde_json::from_slice(&fs::read(&fixture.record)?)?;
    let root: Value = serde_json::from_slice(&fs::read(&roots)?)?;
    assert_eq!(root["linker_record_sha256"], digest(&fixture.record)?);
    assert_eq!(
        root["compiler_output"],
        json!({"path":binary,"sha256":digest(&binary)?})
    );
    validate(
        &link,
        &digest(&fixture.spec)?,
        &digest(&binary)?,
        Some(&root["compiler_output"]),
    )?;
    #[cfg(target_os = "macos")]
    assert_ne!(link["output_sha256"], digest(&binary)?);
    fs::OpenOptions::new()
        .append(true)
        .open(&binary)?
        .write_all(b"changed after compiler")?;
    assert!(
        validate(
            &link,
            &digest(&fixture.spec)?,
            &digest(&binary)?,
            Some(&root["compiler_output"])
        )
        .is_err()
    );
    fs::write(&source, "invalid Rust source")?;
    assert!(!command().output()?.status.success());
    assert!(!roots.exists() && !fixture.record.exists());
    Ok(())
}

#[test]
fn linker_status_signals_and_inherited_descriptors_survive() -> Result<()> {
    let fixture = Fixture::new()?;
    let backend = fixture.root.path().join("ld");
    script(&backend, "exit 0")?;
    let driver = fixture.root.path().join("driver");
    let plan = "if [ \"${1:-}\" = '-###' ]; then printf '\"%s\"\\n' \"$BACKEND\" >&2; exit 0; fi";
    script(&driver, &format!("{plan}\ncat <&9\nexit 23"))?;
    let token = fixture.root.path().join("token");
    fs::write(&token, "+")?;
    let result = Command::new("sh")
        .args(["-c", "exec 9<\"$1\"; exec \"$2\" -o \"$3\"", "jobserver"])
        .arg(&token)
        .arg(env!("CARGO_BIN_EXE_kontor-node-linker"))
        .arg(&fixture.output)
        .env("KONTOR_NODE_LINK_SPEC", &fixture.spec)
        .env("KONTOR_REAL_LINKER", &driver)
        .env("BACKEND", &backend)
        .env("CARGO_MAKEFLAGS", "--jobserver-auth=9,10")
        .output()?;
    assert_eq!(result.status.code(), Some(23));
    assert_eq!(result.stdout, b"+");
    assert!(!fixture.record.exists());
    script(&driver, &format!("{plan}\nkill -TERM $$"))?;
    let signal = fixture
        .command(driver.to_str().unwrap())
        .arg("-o")
        .arg(&fixture.output)
        .env("BACKEND", &backend)
        .output()?;
    assert_eq!(signal.status.code(), Some(143));
    assert!(!fixture.record.exists());
    Ok(())
}

#[test]
fn changed_response_file_prevents_linking_with_a_stale_driver_plan() -> Result<()> {
    let fixture = Fixture::new()?;
    let backend = fixture.root.path().join("ld");
    script(&backend, "exit 0")?;
    let response = fixture.root.path().join("arguments");
    fs::write(&response, format!("-o {}", fixture.output.display()))?;
    let driver = fixture.root.path().join("driver");
    script(
        &driver,
        "if [ \"${1:-}\" = '-###' ]; then printf '\"%s\"\\n' \"$BACKEND\" >&2; printf '%s' '-o changed' > \"$RESPONSE\"; exit 0; fi\nprintf invoked > \"$MARKER\"",
    )?;
    let marker = fixture.root.path().join("invoked");
    let result = fixture
        .command(driver.to_str().unwrap())
        .arg(format!("@{}", response.display()))
        .env("BACKEND", &backend)
        .env("RESPONSE", &response)
        .env("MARKER", &marker)
        .output()?;
    assert!(!result.status.success());
    assert!(String::from_utf8(result.stderr)?.contains("response arguments changed"));
    assert!(!marker.exists() && !fixture.record.exists());
    Ok(())
}
