#![cfg(unix)]

use std::env;
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::{TempDir, tempdir};

fn digest(path: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(fs::read(path)?)))
}

struct Fixture {
    directory: TempDir,
    compiler: PathBuf,
    spec: PathBuf,
}

impl Fixture {
    fn new(script: &str) -> Result<Self> {
        let directory = tempdir()?;
        let compiler = directory.path().join("compiler");
        fs::write(&compiler, format!("#!/bin/sh\nset -eu\n{script}\n"))?;
        fs::set_permissions(&compiler, fs::Permissions::from_mode(0o755))?;
        let spec = directory.path().join("spec.json");
        fs::write(
            &spec,
            json!({"compiler": compiler, "graphs": []}).to_string(),
        )?;
        Ok(Self {
            directory,
            compiler,
            spec,
        })
    }

    fn command(&self) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_kontor-node-rustc"));
        command
            .arg(&self.compiler)
            .env("KONTOR_NODE_LINK_SPEC", &self.spec);
        command
    }
}

#[test]
fn preserves_probes_raw_arguments_and_clears_inherited_attestation() -> Result<()> {
    let fixture = Fixture::new(
        "test -z \"${KONTOR_NODE_ATTESTATION+x}\"; test -z \"${KONTOR_NODE_TARGET+x}\"; printf '%s\\0' \"$@\"",
    )?;
    let argument = OsString::from_vec(b"source-\xff.rs".to_vec());
    let output = fixture
        .command()
        .arg("-vV")
        .arg(argument)
        .env("KONTOR_NODE_ATTESTATION", "injected")
        .env("KONTOR_NODE_TARGET", "wrong")
        .output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(output.stdout, b"-vV\0source-\xff.rs\0");
    Ok(())
}

#[test]
fn compiler_status_signals_and_jobserver_descriptors_survive() -> Result<()> {
    let fixture = Fixture::new("cat <&9; exit 23")?;
    let token = fixture.directory.path().join("token");
    fs::write(&token, "+")?;
    let output = Command::new("sh")
        .args(["-c", "exec 9<\"$1\"; exec \"$2\" \"$3\"", "jobserver"])
        .arg(&token)
        .arg(env!("CARGO_BIN_EXE_kontor-node-rustc"))
        .arg(&fixture.compiler)
        .env("KONTOR_NODE_LINK_SPEC", &fixture.spec)
        .env("CARGO_MAKEFLAGS", "--jobserver-auth=9,10")
        .output()?;
    assert_eq!(output.status.code(), Some(23));
    assert_eq!(output.stdout, b"+");
    fs::write(&fixture.compiler, "#!/bin/sh\nkill -TERM $$\n")?;
    assert_eq!(fixture.command().output()?.status.code(), Some(143));
    Ok(())
}

#[test]
fn binds_completed_output_rejects_changed_spec_and_removes_stale_success() -> Result<()> {
    let fixture = Fixture::new(
        r#"
if [ "${FAIL:-0}" = 1 ]; then exit 42; fi
if [ "${NO_OBJECT:-0}" != 1 ]; then printf object > "$FAKE_OBJECT"; fi
printf linked > "$FAKE_OUTPUT"
printf '%s' "$FAKE_RECORD" > "$FAKE_LINK_RECORD"
if [ "${CHANGE_SPEC:-0}" = 1 ]; then printf '{}' > "$KONTOR_NODE_LINK_SPEC"; fi
"#,
    )?;
    let directory = fixture.directory.path();
    let output_path = directory.join("kontor-test");
    let object = directory.join("kontor-test.1.rcgu.o");
    let link_record = directory.join("link.json");
    let roots = directory.join("roots.json");
    let spec = json!({"compiler": fixture.compiler, "graphs": [], "linker_wrapper": fixture.compiler,
        "linker_wrapper_sha256": digest(&fixture.compiler)?, "linker_record": link_record, "root_objects": roots});
    fs::write(&fixture.spec, spec.to_string())?;
    let spec_hash = digest(&fixture.spec)?;
    let make_command = || {
        let mut command = fixture.command();
        command
            .args(["--crate-name", "kontor", "--out-dir"])
            .arg(directory)
            .args(["-Cextra-filename=-test"])
            .env("FAKE_OBJECT", &object)
            .env("FAKE_OUTPUT", &output_path)
            .env("FAKE_LINK_RECORD", &link_record)
            .env(
                "FAKE_RECORD",
                json!({"spec_sha256":spec_hash,"output": output_path}).to_string(),
            );
        command
    };
    let output = make_command().output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let record: Value = serde_json::from_slice(&fs::read(&roots)?)?;
    assert_eq!(
        record["compiler_output"],
        json!({"path":output_path,"sha256":digest(&output_path)?})
    );
    assert_eq!(record["linker_record_sha256"], digest(&link_record)?);
    assert_eq!(
        record["objects"],
        json!([{"path":object,"sha256":digest(&object)?}])
    );
    assert_eq!(
        make_command().env("FAIL", "1").output()?.status.code(),
        Some(42)
    );
    assert!(!roots.exists() && !link_record.exists() && !object.exists());
    let raw_linker = OsString::from_vec(b"-Clinker=/tmp/linker-\xff".to_vec());
    let raw = make_command().arg(raw_linker).output()?;
    assert!(!raw.status.success());
    assert!(String::from_utf8(raw.stderr)?.contains("UTF-8 compiler arguments"));
    assert!(!roots.exists() && !link_record.exists() && !object.exists());
    let missing = make_command().env("NO_OBJECT", "1").output()?;
    assert!(!missing.status.success());
    assert!(String::from_utf8(missing.stderr)?.contains("did not retain codegen objects"));
    let changed = make_command().env("CHANGE_SPEC", "1").output()?;
    assert!(!changed.status.success());
    assert!(String::from_utf8(changed.stderr)?.contains("identity disagree"));
    assert!(!roots.exists());
    Ok(())
}

#[test]
fn staged_node_wrapper_rejects_modified_binary() -> Result<()> {
    let directory = tempdir()?;
    let stage = || {
        Command::new(env!("CARGO_BIN_EXE_kontor-build"))
            .arg("stage-node-wrapper")
            .arg(directory.path())
            .output()
    };
    let output = stage()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let path = PathBuf::from(String::from_utf8(output.stdout)?.trim());
    assert_eq!(path.file_name().unwrap(), "kontor-node-rustc");
    assert_eq!(
        path.parent().unwrap().file_name().unwrap(),
        digest(&path)?.as_str()
    );
    // Unlink before replacing so the original hardlinked Cargo binary remains intact.
    fs::remove_file(&path)?;
    fs::write(&path, "changed")?;
    assert!(!stage()?.status.success());
    Ok(())
}
