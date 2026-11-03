#![cfg(unix)]

use std::env;
use std::ffi::OsString;
use std::fs;
use std::os::unix::ffi::OsStringExt;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use anyhow::Result;
use tempfile::{TempDir, tempdir};

const NAMESPACE: &str = "kontor_first_0123456789abcdef01234567";

fn stage(root: &Path) -> Result<Output> {
    Ok(Command::new(env!("CARGO_BIN_EXE_kontor-build"))
        .arg("stage-graph-wrapper")
        .arg(root)
        .output()?)
}

fn fixture(script: &str) -> Result<(TempDir, PathBuf, PathBuf)> {
    let directory = tempdir()?;
    let result = stage(directory.path())?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let wrapper = PathBuf::from(String::from_utf8(result.stdout)?.trim());
    let compiler = directory.path().join("rustc");
    fs::write(&compiler, format!("#!/bin/sh\n{script}\n"))?;
    fs::set_permissions(&compiler, fs::Permissions::from_mode(0o755))?;
    Ok((directory, wrapper, compiler))
}

fn invoke(wrapper: &Path, compiler: &Path) -> Command {
    let mut command = Command::new(wrapper);
    command
        .arg(compiler)
        .env("RUSTC_WRAPPER", wrapper)
        .env("KONTOR_PINNED_RUSTC", compiler)
        .env("KONTOR_NATIVE_NAMESPACE", NAMESPACE)
        .env_remove("RUSTC_WORKSPACE_WRAPPER");
    command
}

#[test]
fn adds_graph_metadata_without_changing_cargo_metadata_or_probe_arguments() -> Result<()> {
    let (_directory, wrapper, compiler) = fixture("printf '%s\\0' \"$@\"")?;
    for (args, appended) in [
        (
            vec![
                "--crate-name",
                "serde",
                "-Cmetadata=unit_identity",
                "lib.rs",
            ],
            true,
        ),
        (vec!["-vV"], false),
        (vec!["--version"], false),
        (vec!["--print", "sysroot"], false),
        (
            vec![
                "-",
                "--crate-name",
                "___",
                "--print=file-names",
                "--print=cfg",
            ],
            false,
        ),
    ] {
        let output = invoke(&wrapper, &compiler).args(&args).output()?;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let mut expected: Vec<u8> = args.iter().flat_map(|arg| arg.bytes().chain([0])).collect();
        if appended {
            expected.extend(format!("-Cmetadata={NAMESPACE}\0").bytes());
        }
        assert_eq!(output.stdout, expected);
    }
    let arg = OsString::from_vec(b"source-\xff.rs".to_vec());
    let output = invoke(&wrapper, &compiler).arg(&arg).output()?;
    assert!(output.status.success());
    assert_eq!(output.stdout, b"source-\xff.rs\0");
    Ok(())
}

#[test]
fn rejects_namespace_compiler_and_nested_wrapper_substitution() -> Result<()> {
    let (directory, wrapper, compiler) = fixture("exit 0")?;
    for namespace in [
        "",
        "kontor_first_ABCDEF0123456789abcdef01",
        "kontor_other_0123456789abcdef01234567",
        "kontor_first_0123456789abcdef012345678",
    ] {
        assert!(
            !invoke(&wrapper, &compiler)
                .env("KONTOR_NATIVE_NAMESPACE", namespace)
                .output()?
                .status
                .success()
        );
    }
    for variable in ["RUSTC_WRAPPER", "RUSTC_WORKSPACE_WRAPPER"] {
        assert!(
            !invoke(&wrapper, &compiler)
                .env(variable, "sccache")
                .output()?
                .status
                .success()
        );
    }
    let alternate = directory.path().join("other/rustc");
    fs::create_dir(alternate.parent().unwrap())?;
    fs::copy(&compiler, &alternate)?;
    let output = invoke(&wrapper, &compiler)
        .env("KONTOR_PINNED_RUSTC", alternate)
        .output()?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("exact pinned rustc"));
    Ok(())
}

#[test]
fn preserves_compiler_exit_status_and_inherited_jobserver_descriptors() -> Result<()> {
    let (directory, wrapper, compiler) = fixture("cat <&9; exit 23")?;
    let pipe = directory.path().join("jobserver");
    fs::write(&pipe, "inherited descriptor")?;
    let result = Command::new("sh")
        .args(["-c", "exec 9<\"$1\"; exec \"$2\" \"$3\" -vV", "sh"])
        .arg(pipe)
        .arg(&wrapper)
        .arg(&compiler)
        .env("RUSTC_WRAPPER", &wrapper)
        .env("KONTOR_PINNED_RUSTC", &compiler)
        .env("KONTOR_NATIVE_NAMESPACE", NAMESPACE)
        .env_remove("RUSTC_WORKSPACE_WRAPPER")
        .output()?;
    assert_eq!(result.status.code(), Some(23));
    assert_eq!(result.stdout, b"inherited descriptor");
    Ok(())
}

#[test]
fn staging_reuses_immutable_executable_and_rejects_replaced_content() -> Result<()> {
    let (directory, wrapper, _compiler) = fixture("exit 0")?;
    let inode = fs::metadata(&wrapper)?.ino();
    assert!(stage(directory.path())?.status.success());
    assert_eq!(fs::metadata(&wrapper)?.ino(), inode);
    // Replace the directory entry, not the shared executable inode.
    fs::remove_file(&wrapper)?;
    fs::write(wrapper, "substituted compiler wrapper")?;
    let output = stage(directory.path())?;
    assert!(!output.status.success());
    assert!(String::from_utf8_lossy(&output.stderr).contains("differs from the build tool"));
    Ok(())
}

#[test]
fn offline_cli_bootstrap_applies_to_both_cargo_commands() -> Result<()> {
    let directory = tempdir()?;
    let cargo = directory.path().join("cargo");
    fs::write(
        &cargo,
        "#!/bin/sh\nprintf '%s %s\\n' \"$CARGO_NET_OFFLINE\" \"$*\" >> \"$CALL_LOG\"\n",
    )?;
    fs::set_permissions(&cargo, fs::Permissions::from_mode(0o755))?;
    let mut paths = vec![directory.path().to_owned()];
    paths.extend(env::split_paths(&env::var_os("PATH").unwrap_or_default()));
    let log = directory.path().join("calls");
    let repository = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap();
    let result = Command::new(repository.join("tools/kontor"))
        .args(["protocol-bundles", "--offline"])
        .env("PATH", env::join_paths(paths)?)
        .env("CALL_LOG", &log)
        .env("CARGO_NET_OFFLINE", "false")
        .output()?;
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let calls = fs::read_to_string(log)?;
    assert_eq!(calls.lines().count(), 2);
    assert!(calls.lines().all(|line| line.starts_with("true ")));
    assert!(calls.contains("--bin kontor-graph-rustc"));
    assert!(calls.contains("--bin kontor-build -- protocol-bundles --offline"));
    Ok(())
}
