use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path};

use anyhow::{Context, Result, ensure};
use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};

use super::probes::{number, string};
use super::resource_report::ThreadObservation;
use crate::container::sha256;

const CATEGORIES: [&str; 3] = ["tokio_worker", "blocking_pool", "block_on_caller"];
const GUARD_MARKER: &str = "KONTOR_RESOURCE_GUARD_CONTROL=";
const TERMINAL_MARKER: &str = "KONTOR_RESOURCE_GUARD_TERMINAL=";
const TARGET_MARKER: &str = "KONTOR_RESOURCE_GUARD_TARGET=";

#[derive(Deserialize)]
struct Runtime {
    flavor: String,
    worker_count: u64,
    #[serde(deserialize_with = "Option::deserialize")]
    worker_requested_bytes: Option<u64>,
    thread_observations: Vec<ThreadObservation>,
    blocking_pool_observed: bool,
    block_on_caller_observed: bool,
}

pub(super) fn thread_capacities(
    value: &Value,
    mode: &str,
    page: u64,
    os: &str,
    pid: u64,
) -> Result<Value> {
    ensure!(
        matches!(mode, "production" | "reduced")
            && matches!(os, "linux" | "macos")
            && page > 0
            && pid > 0,
        "invalid resource thread context"
    );
    let runtime: Runtime = serde_json::from_value(value.clone())
        .context("thread capacity record is incomplete or invalid")?;
    ensure!(
        runtime.flavor == "multi_thread",
        "{mode}: runtime is not multithreaded"
    );
    ensure!(runtime.worker_count >= 2, "{mode}: invalid worker count");
    if mode == "reduced" {
        ensure!(
            runtime.worker_requested_bytes == Some(1_015_808),
            "reduced workers did not request 992 KiB"
        );
    }
    let mut groups: BTreeMap<&str, Vec<Value>> = CATEGORIES
        .into_iter()
        .map(|key| (key, Vec::new()))
        .collect();
    let mut ids = BTreeSet::new();
    let mut tids = BTreeSet::new();
    for (index, thread) in runtime.thread_observations.iter().enumerate() {
        let category = thread.thread_category.as_str();
        ensure!(
            groups.contains_key(category),
            "{mode}: unknown thread category"
        );
        ensure!(
            !thread.thread_id.is_empty()
                && thread.process_id == pid
                && thread.os_thread_id > 0
                && thread.identity_api
                    == if os == "linux" {
                        "linux_gettid"
                    } else {
                        "macos_pthread_threadid_np"
                    }
                && thread.page_size_bytes == page,
            "{mode}: thread identity or page size is unverified"
        );
        ensure!(thread.mapped_bytes > 0, "{mode}: invalid mapped stack");
        ensure!(
            thread.usable_bytes > 0 && thread.usable_bytes <= thread.mapped_bytes,
            "{mode}: usable stack capacity is unverified"
        );
        ensure!(
            thread.mapped_end.checked_sub(thread.mapped_start) == Some(thread.mapped_bytes)
                && thread.usable_end.checked_sub(thread.usable_start) == Some(thread.usable_bytes)
                && thread.mapped_start <= thread.usable_start
                && thread.usable_end <= thread.mapped_end,
            "{mode}: actual usable worker range is unverified"
        );
        if os == "macos" && category == "tokio_worker" {
            // The writable arm64 pthread offset belongs to the measured capacity.
            ensure!(
                thread.mapped_start.is_multiple_of(page)
                    && thread.usable_start == thread.mapped_start
                    && thread.usable_end == thread.mapped_end,
                "{mode}: unexpected macOS pthread stack offset or layout"
            );
            if mode == "reduced" {
                let requested = thread
                    .requested_bytes
                    .context("missing reduced worker request")?;
                ensure!(
                    requested.is_multiple_of(page)
                        && thread.mapped_bytes.checked_sub(requested)
                            == Some(thread.mapped_end % page),
                    "{mode}: unexpected macOS pthread stack offset or layout"
                );
            }
        }
        ensure!(
            !thread.measurement_api.is_empty(),
            "{mode}: missing stack measurement API"
        );
        ensure!(
            !matches!(thread.guard_treatment.as_str(), "" | "unknown") && thread.guard_verified,
            "{mode}: unresolved thread guard treatment"
        );
        if thread.guard_bytes == 0 {
            ensure!(
                category != "tokio_worker"
                    && thread.guard_start == 0
                    && thread.guard_end == 0
                    && thread.guard_verification == "pthread_reports_none",
                "{mode}: worker guard is absent or guard range is inconsistent"
            );
        } else {
            let method = if os == "linux" {
                matches!(
                    thread.guard_verification.as_str(),
                    "linux_maps_prot_none" | "linux_proc_self_mem_eio"
                )
            } else {
                thread.guard_verification == "macos_mach_vm_region_prot_none"
            };
            ensure!(
                method
                    && thread
                        .guard_end
                        .checked_sub(thread.guard_start)
                        .is_some_and(|size| size >= thread.guard_bytes)
                    && thread.guard_start.is_multiple_of(page)
                    && thread.guard_end.is_multiple_of(page)
                    && ((thread.guard_start == thread.mapped_start
                        && thread.guard_end == thread.usable_start)
                        || thread.guard_end == thread.mapped_start),
                "{mode}: thread guard interval is unverified"
            );
        }
        ensure!(
            ids.insert(&thread.thread_id),
            "{mode}: duplicate thread capacity record"
        );
        ensure!(
            tids.insert(thread.os_thread_id),
            "{mode}: duplicate kernel thread identity"
        );
        if category == "tokio_worker" {
            ensure!(
                thread.requested_bytes == runtime.worker_requested_bytes,
                "{mode}: worker request differs from runtime settings"
            );
        }
        groups
            .get_mut(category)
            .context("missing thread category")?
            .push(value["thread_observations"][index].clone());
    }
    ensure!(
        groups["tokio_worker"].len() as u64 >= runtime.worker_count,
        "{mode}: not all workers measured"
    );
    ensure!(
        !groups["blocking_pool"].is_empty() && runtime.blocking_pool_observed,
        "{mode}: blocking pool not observed"
    );
    ensure!(
        !groups["block_on_caller"].is_empty() && runtime.block_on_caller_observed,
        "{mode}: block_on caller not observed"
    );
    Ok(json!(groups))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Control {
    process: Process,
    raw_log: RawLog,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RawLog {
    path: String,
    sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Process {
    pid: u64,
    command: Vec<String>,
    started_unix_ns: u64,
    ended_unix_ns: u64,
    exit_code: i32,
    signal: Value,
    timed_out: bool,
    complete: bool,
    test_harness_passed: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Terminal {
    pid: u64,
    binary_path: String,
    binary_sha256: String,
    embedded_source_sha: String,
    modes: Vec<String>,
    complete: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Child {
    mode: String,
    signal: i32,
    target: Target,
    child_binary: String,
    child_stdout: String,
    child_stderr: String,
}

#[derive(Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
struct Target {
    mode: String,
    process_id: u64,
    os_thread_id: u64,
    page_size_bytes: u64,
    guard_start: u64,
    guard_end: u64,
    guard_verification: String,
    address: u64,
}

fn raw_log(directory: &Path, entry: &RawLog) -> Result<String> {
    let relative = Path::new(&entry.path);
    ensure!(
        !relative.is_absolute()
            && !relative
                .components()
                .any(|part| part == Component::ParentDir),
        "raw log escapes evidence directory"
    );
    let path = directory.join(relative);
    ensure!(
        path.is_file() && path.canonicalize()?.starts_with(directory.canonicalize()?),
        "raw log is missing or resolves outside evidence directory"
    );
    ensure!(
        sha256(&path)? == entry.sha256,
        "raw log hash mismatch: {}",
        entry.path
    );
    Ok(fs::read_to_string(path)?)
}

pub(super) fn guard_control(report: &Value, manifest: &Value, directory: &Path) -> Result<()> {
    let os = string(&report["host"]["os"])?;
    ensure!(
        matches!(os, "linux" | "macos"),
        "unsupported guard control host"
    );
    let name_key = if os == "linux" {
        "test_name"
    } else {
        "macos_test_name"
    };
    let test_name = string(&manifest["guard_control_runner"][name_key])?;
    let control: Control = serde_json::from_value(report["guard_control"].clone())
        .context("guard control evidence is incomplete or invalid")?;
    let process = &control.process;
    ensure!(
        process.pid > 0
            && process.started_unix_ns > 0
            && process.ended_unix_ns > process.started_unix_ns
            && process.exit_code == 0
            && process.signal.is_null()
            && !process.timed_out
            && process.complete
            && process.test_harness_passed,
        "guard control process failed or transcript is incomplete"
    );
    let binary = string(&report["binary_path"])?;
    ensure!(
        process.command == [binary, "--exact", test_name, "--ignored", "--nocapture"],
        "guard control command differs from compiled test"
    );
    ensure!(
        string(&manifest["guard_control_runner"]["source_sha256"])?
            == string(&manifest["artifacts"]["resource_worker_diagnostic"]["sha256"])?,
        "guard control source differs from frozen worker"
    );
    let raw = raw_log(directory, &control.raw_log)?;
    let configurations = report["configurations"]
        .as_object()
        .context("missing guard configurations")?;
    for configuration in configurations.values() {
        ensure!(
            string(&configuration["process_log"]["path"])? != control.raw_log.path,
            "guard control reuses a workload process transcript"
        );
    }
    let lines: Vec<_> = raw.lines().collect();
    ensure!(
        lines
            .iter()
            .filter(|line| line.trim() == "running 1 test")
            .count()
            == 1,
        "guard control transcript lacks one selected test"
    );
    let harness: Vec<_> = lines
        .iter()
        .enumerate()
        .filter(|(_, line)| line.starts_with("test result:"))
        .collect();
    let pattern = Regex::new(
        r"^test result: ok\. 1 passed; 0 failed; 0 ignored; 0 measured; \d+ filtered out; finished in [0-9.]+s$",
    )?;
    ensure!(
        harness.len() == 1 && pattern.is_match(harness[0].1),
        "guard control test harness did not pass"
    );
    let markers: Vec<_> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, line)| line.split_once(GUARD_MARKER).map(|(_, raw)| (i, raw)))
        .collect();
    let terminals: Vec<_> = lines
        .iter()
        .enumerate()
        .filter_map(|(i, line)| line.split_once(TERMINAL_MARKER).map(|(_, raw)| (i, raw)))
        .collect();
    ensure!(
        markers.len() == 2 && terminals.len() == 1,
        "guard control transcript lacks exact two children and terminal"
    );
    ensure!(
        markers[1].0 < terminals[0].0 && terminals[0].0 < harness[0].0,
        "guard control terminal or harness result is out of order"
    );
    // Typed decoding also rejects duplicate or unknown fields in raw markers.
    let terminal: Terminal = serde_json::from_str(terminals[0].1)?;
    ensure!(
        terminal.pid == process.pid
            && terminal.binary_path == binary
            && terminal.binary_sha256 == string(&report["binary_sha256"])?
            && terminal.embedded_source_sha == string(&report["source_sha"])?
            && terminal.modes == ["reduced", "production"]
            && terminal.complete,
        "guard control terminal differs from source or binary closure"
    );
    let mut pids = BTreeSet::new();
    let mut tids = BTreeSet::new();
    for ((_, raw), mode) in markers.iter().zip(["reduced", "production"]) {
        let child: Child = serde_json::from_str(raw)?;
        ensure!(
            child.mode == mode,
            "guard control mode is missing or duplicated"
        );
        let target = &child.target;
        ensure!(
            target.mode == mode,
            "guard child target is incomplete or misattributed"
        );
        let page = number(
            &configurations.get(mode).context("missing guard mode")?["engine"]["page_size_bytes"],
        )?;
        let method = if os == "linux" {
            matches!(
                target.guard_verification.as_str(),
                "guard protected inside pthread stack range"
                    | "guard protected below pthread stack range"
                    | "inaccessible interval verified below pthread stack range by /proc/self/mem EIO"
            )
        } else {
            target.guard_verification == "macos_mach_vm_region_prot_none"
        };
        ensure!(
            target.process_id > 0
                && target.process_id != process.pid
                && pids.insert(target.process_id)
                && target.os_thread_id > 0
                && tids.insert(target.os_thread_id)
                && page > 0
                && target.page_size_bytes == page
                && target
                    .guard_end
                    .checked_sub(target.guard_start)
                    .is_some_and(|size| size >= page)
                && target.guard_start <= target.address
                && target.address < target.guard_end
                && method,
            "guard child PID, TID, or target is unverified"
        );
        ensure!(
            child.signal == 6 && child.child_binary == binary,
            "guard child signal or binary differs from compiled control"
        );
        let nested: Vec<_> = child
            .child_stdout
            .lines()
            .filter_map(|line| line.split_once(TARGET_MARKER).map(|(_, raw)| raw))
            .collect();
        ensure!(
            nested.len() == 1,
            "guard child raw output does not corroborate its fault"
        );
        let observed: Target = serde_json::from_str(nested[0])?;
        ensure!(
            observed == *target
                && child.child_stdout.matches("running 1 test").count() == 1
                && !child.child_stdout.contains("test result:")
                && child.child_stderr.contains(&format!(
                    "({}) has overflowed its stack",
                    target.os_thread_id
                ))
                && child
                    .child_stderr
                    .contains("fatal runtime error: stack overflow, aborting"),
            "guard child raw output does not corroborate its fault"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests;
