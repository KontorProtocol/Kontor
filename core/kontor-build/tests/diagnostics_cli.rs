#![cfg(unix)]

use std::fs;
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Result, bail};
use tempfile::tempdir;

fn bounded_output(mut child: Child) -> Result<Output> {
    let started = Instant::now();
    while child.try_wait()?.is_none() {
        if started.elapsed() > Duration::from_secs(5) {
            let _ = child.kill();
            let _ = child.wait();
            bail!("diagnostic wrapper waited on a surviving descendant");
        }
        thread::sleep(Duration::from_millis(20));
    }
    Ok(child.wait_with_output()?)
}

fn command(log: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_kontor-build"));
    command.args(["diagnostics", "run"]).arg(log);
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    command
}

#[test]
fn preserves_combined_output_exit_status_arguments_and_working_directory() -> Result<()> {
    let directory = tempdir()?;
    let log = directory.path().join("tests.log");
    let result = bounded_output(
        command(&log)
            .current_dir(directory.path())
            .args([
                "sh",
                "-c",
                "printf '%s\\n' \"$1\"; printf stderr >&2; pwd; exit 101",
                "sh",
                "argument with spaces",
            ])
            .spawn()?,
    )?;
    assert_eq!(result.status.code(), Some(101));
    assert_eq!(result.stdout, fs::read(log)?);
    let text = String::from_utf8(result.stdout)?;
    assert!(text.contains("argument with spaces"));
    assert!(text.contains("stderr"));
    assert!(text.contains(directory.path().canonicalize()?.to_str().unwrap()));
    Ok(())
}

#[test]
fn signal_exit_status_matches_shell_convention() -> Result<()> {
    let directory = tempdir()?;
    let result = bounded_output(
        command(&directory.path().join("tests.log"))
            .args(["sh", "-c", "kill -TERM $$"])
            .spawn()?,
    )?;
    assert_eq!(result.status.code(), Some(143));
    Ok(())
}

#[test]
fn exits_without_waiting_for_descendants_to_close_output() -> Result<()> {
    let directory = tempdir()?;
    let pid_file = directory.path().join("child.pid");
    let result = bounded_output(
        command(&directory.path().join("tests.log"))
            .args([
                "sh",
                "-c",
                "sleep 30 & echo $! > \"$1\"; echo parent-failed; exit 101",
                "sh",
            ])
            .arg(&pid_file)
            .spawn()?,
    );
    if pid_file.exists() {
        let pid = fs::read_to_string(pid_file)?;
        Command::new("kill").arg(pid.trim()).status()?;
    }
    let result = result?;
    assert_eq!(result.status.code(), Some(101));
    assert!(String::from_utf8_lossy(&result.stdout).contains("parent-failed"));
    Ok(())
}
