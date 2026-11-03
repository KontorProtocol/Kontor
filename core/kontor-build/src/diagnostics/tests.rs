use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

#[cfg(unix)]
use std::os::unix::fs::symlink;

use anyhow::Result;
use serde_json::Value;
use tempfile::{TempDir, tempdir};

use super::{Reports, Roots, capture_command, collect_reports, prepare};

fn fixture() -> Result<(TempDir, PathBuf, Roots)> {
    let directory = tempdir()?;
    let reports = directory.path().join("DiagnosticReports");
    let output = directory.path().join("output");
    fs::create_dir(&reports)?;
    Ok((
        directory,
        output,
        BTreeMap::from([("user".to_owned(), reports)]),
    ))
}

fn inventory(output: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&fs::read(
        output.join("reports.json"),
    )?)?)
}

#[test]
fn repeated_polls_collect_delayed_and_growing_reports_but_not_historical_reports() -> Result<()> {
    let (_directory, output, roots) = fixture()?;
    let root = &roots["user"];
    fs::write(root.join("historical.ips"), "old report")?;
    prepare(&output, &roots)?;
    let mut reports = Reports::new(&output, &roots);
    fs::create_dir(root.join("Retired"))?;
    let report = root.join("Retired/unexpected-process-name.ips");
    fs::write(&report, "partial")?;
    reports.poll(&output, &roots);
    assert_eq!(
        fs::read_to_string(output.join("reports/user/Retired/unexpected-process-name.ips"))?,
        "partial"
    );
    fs::write(&report, "complete crash report")?;
    fs::write(root.join("another-test.crash"), "second crash")?;
    reports.poll(&output, &roots);
    reports.poll(&output, &roots);
    assert_eq!(reports.copied.len(), 2);
    assert_eq!(
        fs::read_to_string(output.join("reports/user/Retired/unexpected-process-name.ips"))?,
        "complete crash report"
    );
    assert!(!output.join("reports/user/historical.ips").exists());
    assert_eq!(
        fs::metadata(report)?.modified()?,
        fs::metadata(output.join("reports/user/Retired/unexpected-process-name.ips"))?
            .modified()?
    );
    Ok(())
}

#[test]
#[cfg(unix)]
fn collects_changed_existing_reports_without_following_symlinks() -> Result<()> {
    let (directory, output, roots) = fixture()?;
    let root = &roots["user"];
    fs::write(root.join("existing.ips"), "old")?;
    prepare(&output, &roots)?;
    fs::write(root.join("existing.ips"), "updated report")?;
    let outside = directory.path().join("outside");
    fs::create_dir(&outside)?;
    fs::write(outside.join("secret"), "not a report")?;
    symlink(outside.join("secret"), root.join("linked-file"))?;
    symlink(outside, root.join("linked-directory"))?;
    assert_eq!(
        collect_reports(&output, &roots, Duration::ZERO, Duration::ZERO)?,
        1
    );
    assert_eq!(
        inventory(&output)?["copied"]
            .as_object()
            .unwrap()
            .keys()
            .collect::<Vec<_>>(),
        ["user/existing.ips"]
    );
    Ok(())
}

#[test]
fn missing_roots_and_copy_failures_are_reported_without_losing_other_reports() -> Result<()> {
    let (directory, output, mut roots) = fixture()?;
    roots.insert("system".to_owned(), directory.path().join("missing"));
    prepare(&output, &roots)?;
    fs::write(roots["user"].join("crash.ips"), "report")?;
    fs::create_dir_all(output.join("reports"))?;
    fs::write(output.join("reports/user"), "blocks destination directory")?;
    assert_eq!(
        collect_reports(&output, &roots, Duration::ZERO, Duration::ZERO)?,
        0
    );
    let errors = inventory(&output)?["collection_errors"].to_string();
    assert!(errors.contains("missing"));
    assert!(errors.contains("Cannot copy"));
    fs::remove_file(output.join("reports/user"))?;
    assert_eq!(
        collect_reports(&output, &roots, Duration::ZERO, Duration::ZERO)?,
        1
    );
    Ok(())
}

#[test]
fn no_reports_and_invalid_baselines_never_upload_historical_reports() -> Result<()> {
    let (_directory, output, roots) = fixture()?;
    prepare(&output, &roots)?;
    assert_eq!(
        collect_reports(&output, &roots, Duration::ZERO, Duration::ZERO)?,
        0
    );
    assert_eq!(
        inventory(&output)?["collection_errors"],
        serde_json::json!([])
    );
    fs::write(roots["user"].join("historical.ips"), "old report")?;
    for baseline in [
        None,
        Some("not JSON"),
        Some("{}"),
        Some(r#"{"files":null}"#),
    ] {
        if let Some(baseline) = baseline {
            fs::write(output.join("baseline.json"), baseline)?;
        } else {
            fs::remove_file(output.join("baseline.json"))?;
        }
        assert_eq!(
            collect_reports(&output, &roots, Duration::ZERO, Duration::ZERO)?,
            0
        );
        assert!(
            inventory(&output)?["collection_errors"]
                .to_string()
                .contains("Cannot read baseline")
        );
    }
    Ok(())
}

#[test]
fn command_failures_and_timeouts_preserve_partial_output() -> Result<()> {
    let directory = tempdir()?;
    let log = directory.path().join("command.log");
    capture_command(
        &log,
        &["sh", "-c", "printf diagnostic; exit 7"],
        Duration::from_secs(2),
    )?;
    let text = fs::read_to_string(&log)?;
    assert!(text.contains("diagnostic"));
    assert!(text.contains("Exit status: 7"));
    capture_command(
        &log,
        &[directory.path().join("missing-command").to_str().unwrap()],
        Duration::ZERO,
    )?;
    assert!(fs::read_to_string(&log)?.contains("Collection error:"));
    capture_command(
        &log,
        &["sh", "-c", "printf partial; exec sleep 5"],
        Duration::from_millis(100),
    )?;
    let text = fs::read_to_string(&log)?;
    assert!(text.contains("partial"));
    assert!(text.contains("Collection error: command timed out"));
    Ok(())
}
