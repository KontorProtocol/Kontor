use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::ffi::OsString;
use std::fs::{self, File, FileTimes};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant, UNIX_EPOCH};

#[cfg(unix)]
use std::os::unix::process::ExitStatusExt;

use anyhow::{Context, Result, bail, ensure};
use clap::{Args, Subcommand};
use serde::{Deserialize, Serialize};
use serde_json::json;

#[cfg(test)]
mod tests;

type Roots = BTreeMap<String, PathBuf>;
type Inventory = BTreeMap<String, ReportMetadata>;

#[derive(Debug, Args)]
pub struct DiagnosticsArgs {
    #[command(subcommand)]
    action: Action,
}

#[derive(Debug, Subcommand)]
enum Action {
    /// Record existing reports before running tests.
    Prepare { output: PathBuf },
    /// Collect new reports and system diagnostics after a test failure.
    Collect { output: PathBuf },
    /// Stream a command's output to a file and preserve its exit status.
    Run {
        output: PathBuf,
        #[arg(required = true, trailing_var_arg = true, allow_hyphen_values = true)]
        command: Vec<OsString>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct ReportMetadata {
    mtime_ns: u64,
    size: u64,
}

#[derive(Default, Serialize, Deserialize)]
struct Snapshot {
    files: Inventory,
    errors: Vec<String>,
}

fn write_json(path: &Path, value: &impl Serialize) -> Result<()> {
    let mut file = File::create(path)?;
    serde_json::to_writer_pretty(&mut file, value)?;
    writeln!(file)?;
    Ok(())
}

fn snapshot(roots: &Roots) -> Snapshot {
    fn walk(root: &Path, directory: &Path, label: &str, result: &mut Snapshot) -> Result<()> {
        for entry in fs::read_dir(directory)? {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) => {
                    result.errors.push(error.to_string());
                    continue;
                }
            };
            let path = entry.path();
            let mut record = || -> Result<()> {
                let metadata = fs::symlink_metadata(&path)?;
                if metadata.is_dir() {
                    walk(root, &path, label, result)?;
                } else if metadata.is_file() {
                    let relative = path
                        .strip_prefix(root)?
                        .to_str()
                        .context("non-UTF8 report path")?;
                    result.files.insert(
                        format!("{label}/{relative}"),
                        ReportMetadata {
                            mtime_ns: metadata
                                .modified()?
                                .duration_since(UNIX_EPOCH)?
                                .as_nanos()
                                .try_into()?,
                            size: metadata.len(),
                        },
                    );
                }
                Ok(())
            };
            if let Err(error) = record() {
                result.errors.push(format!("{}: {error}", path.display()));
            }
        }
        Ok(())
    }
    let mut result = Snapshot::default();
    for (label, root) in roots {
        if let Err(error) = walk(root, root, label, &mut result) {
            result.errors.push(format!("{}: {error}", root.display()));
        }
    }
    result
}

fn prepare(output: &Path, roots: &Roots) -> Result<()> {
    fs::create_dir_all(output)?;
    write_json(&output.join("baseline.json"), &snapshot(roots))?;
    write_json(
        &output.join("run.json"),
        &json!({
            "started_at_unix_seconds": UNIX_EPOCH.elapsed()?.as_secs(),
            "commit": env::var("GITHUB_SHA").ok(),
            "run_id": env::var("GITHUB_RUN_ID").ok(),
            "attempt": env::var("GITHUB_RUN_ATTEMPT").ok(),
            "report_roots": roots,
        }),
    )
}

struct Reports {
    baseline: Inventory,
    copied: Inventory,
    errors: BTreeSet<String>,
}

impl Reports {
    fn new(output: &Path, roots: &Roots) -> Self {
        let baseline = || -> Result<Snapshot> {
            Ok(serde_json::from_slice(&fs::read(
                output.join("baseline.json"),
            )?)?)
        };
        let mut errors = BTreeSet::new();
        let baseline = match baseline() {
            Ok(value) => value.files,
            Err(error) => {
                // An absent or corrupt baseline must not upload historical runner reports.
                errors.insert(format!(
                    "Cannot read baseline; tracking reports from collection start: {error}"
                ));
                snapshot(roots).files
            }
        };
        Self {
            baseline,
            copied: Inventory::new(),
            errors,
        }
    }

    fn poll(&mut self, output: &Path, roots: &Roots) -> Snapshot {
        let current = snapshot(roots);
        self.errors.extend(current.errors.iter().cloned());
        for (key, metadata) in &current.files {
            if self.baseline.get(key) == Some(metadata) || self.copied.get(key) == Some(metadata) {
                continue;
            }
            let (label, relative) = key
                .split_once('/')
                .expect("snapshot labels include a slash");
            let source = roots[label].join(relative);
            let destination = output.join("reports").join(key);
            let copy = || -> Result<()> {
                fs::create_dir_all(destination.parent().context("report parent")?)?;
                let metadata = fs::metadata(&source)?;
                fs::copy(&source, &destination)?;
                File::open(&destination)?.set_times(
                    FileTimes::new()
                        .set_modified(metadata.modified()?)
                        .set_accessed(metadata.accessed()?),
                )?;
                Ok(())
            };
            match copy() {
                Ok(()) => {
                    self.copied.insert(key.clone(), metadata.clone());
                }
                Err(error) => {
                    self.errors
                        .insert(format!("Cannot copy {}: {error}", source.display()));
                }
            }
        }
        current
    }
}

fn collect_reports(
    output: &Path,
    roots: &Roots,
    wait: Duration,
    interval: Duration,
) -> Result<usize> {
    let mut reports = Reports::new(output, roots);
    let started = Instant::now();
    let current = loop {
        let current = reports.poll(output, roots);
        let remaining = wait.saturating_sub(started.elapsed());
        if remaining.is_zero() {
            break current;
        }
        // ReportCrash can finish several reports asynchronously, including growing files.
        thread::sleep(interval.min(remaining));
    };
    write_json(
        &output.join("reports.json"),
        &json!({
            "wait_seconds": wait.as_secs_f64(),
            "copied": reports.copied,
            "final_snapshot": current,
            "collection_errors": reports.errors,
        }),
    )?;
    Ok(reports.copied.len())
}

fn exit_code(status: ExitStatus) -> i32 {
    #[cfg(unix)]
    {
        status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(1))
    }
    #[cfg(not(unix))]
    {
        status.code().unwrap_or(1)
    }
}

fn capture_command(path: &Path, command: &[&str], timeout: Duration) -> Result<()> {
    let mut log = File::create(path)?;
    writeln!(log, "Command: {command:?}")?;
    log.flush()?;
    let capture = || -> Result<ExitStatus> {
        let mut child = Command::new(command[0])
            .args(&command[1..])
            .stdout(Stdio::from(log.try_clone()?))
            .stderr(Stdio::from(log.try_clone()?))
            .spawn()?;
        let started = Instant::now();
        loop {
            match child.try_wait() {
                Ok(Some(status)) => return Ok(status),
                Ok(None) if started.elapsed() < timeout => thread::sleep(Duration::from_millis(20)),
                result => {
                    let _ = child.kill();
                    let _ = child.wait();
                    result?;
                    bail!("command timed out after {} seconds", timeout.as_secs_f64());
                }
            }
        }
    };
    match capture() {
        Ok(status) => writeln!(log, "\nExit status: {}", exit_code(status))?,
        Err(error) => writeln!(log, "\nCollection error: {error}")?,
    }
    Ok(())
}

fn run_logged(output: &Path, command: &[OsString]) -> Result<i32> {
    ensure!(!command.is_empty(), "run requires a command");
    if let Some(parent) = output.parent().filter(|path| !path.as_os_str().is_empty()) {
        fs::create_dir_all(parent)?;
    }
    let log = File::create(output)?;
    let mut reader = File::open(output)?;
    // Regular files avoid waiting forever on pipes inherited by surviving descendants.
    let mut child = Command::new(&command[0])
        .args(&command[1..])
        .stdout(Stdio::from(log.try_clone()?))
        .stderr(Stdio::from(log))
        .spawn()?;
    let follow = || -> Result<i32> {
        let mut stdout = io::stdout().lock();
        let mut read = 0;
        let mut buffer = [0; 65536];
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            let count = reader.read(&mut buffer)?;
            if count == 0 {
                thread::sleep(Duration::from_millis(50));
            } else {
                stdout.write_all(&buffer[..count])?;
                stdout.flush()?;
                read += count as u64;
            }
        };
        // Capture only the length seen at parent exit, even if children keep appending.
        let remaining = reader.metadata()?.len().saturating_sub(read);
        io::copy(&mut reader.take(remaining), &mut stdout)?;
        stdout.flush()?;
        Ok(exit_code(status))
    };
    let result = follow();
    if result.is_err() {
        let _ = child.kill();
        let _ = child.wait();
    }
    result
}

fn collect(output: &Path, roots: &Roots) -> Result<()> {
    fs::create_dir_all(output)?;
    let count = collect_reports(
        output,
        roots,
        Duration::from_secs(30),
        Duration::from_secs(2),
    )?;
    let predicate = "process == \"ReportCrash\" OR process == \"diagnosticd\" OR process BEGINSWITH \"integration\" OR process BEGINSWITH \"kontor\" OR process == \"bitcoind\" OR eventMessage CONTAINS \"mach_msg\"";
    capture_command(
        &output.join("system.log"),
        &[
            "sudo",
            "-n",
            "/usr/bin/log",
            "show",
            "--last",
            "10m",
            "--style",
            "compact",
            "--info",
            "--debug",
            "--predicate",
            predicate,
        ],
        Duration::from_secs(30),
    )?;
    for (name, command) in [
        ("os.txt", vec!["sw_vers"]),
        ("kernel.txt", vec!["uname", "-a"]),
        (
            "crash-reporter-settings.txt",
            vec!["defaults", "read", "com.apple.CrashReporter"],
        ),
        (
            "core-settings.txt",
            vec!["sysctl", "kern.coredump", "kern.corefile"],
        ),
        ("processes.txt", vec!["ps", "-axo", "pid,ppid,stat,comm"]),
        (
            "disabled-system-services.txt",
            vec!["launchctl", "print-disabled", "system"],
        ),
        (
            "disabled-user-services.txt",
            vec!["sh", "-c", "exec launchctl print-disabled gui/$(id -u)"],
        ),
    ] {
        capture_command(&output.join(name), &command, Duration::from_secs(5))?;
    }
    let mut message = format!("Captured {count} new or changed macOS diagnostic report(s).");
    if count == 0 {
        message.push_str(
            " No crash report found; inspect reports.json and system.log for collection details.",
        );
        println!("::warning::{message}");
    }
    fs::write(output.join("summary.txt"), format!("{message}\n"))?;
    if let Some(path) = env::var_os("GITHUB_STEP_SUMMARY") {
        let mut file = File::options().create(true).append(true).open(path)?;
        writeln!(
            file,
            "### macOS crash diagnostics\n\n{message}\n\nTest output, report inventories, collection errors, and system diagnostics are in the macos-crash-reports artifact for this attempt.\n"
        )?;
    }
    println!("{message}");
    Ok(())
}

pub fn diagnostics(args: DiagnosticsArgs) -> Result<i32> {
    if let Action::Run { output, command } = args.action {
        return run_logged(&output, &command);
    }
    let roots = BTreeMap::from([
        (
            "user".to_owned(),
            PathBuf::from(env::var_os("HOME").context("HOME is not set")?)
                .join("Library/Logs/DiagnosticReports"),
        ),
        (
            "system".to_owned(),
            PathBuf::from("/Library/Logs/DiagnosticReports"),
        ),
    ]);
    match args.action {
        Action::Prepare { output } => prepare(&output, &roots)?,
        Action::Collect { output } => collect(&output, &roots)?,
        Action::Run { .. } => unreachable!(),
    }
    Ok(0)
}
