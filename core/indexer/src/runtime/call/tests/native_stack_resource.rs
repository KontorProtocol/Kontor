use std::collections::HashMap;
use std::env;
use std::sync::mpsc::channel;
use std::thread::ThreadId;
use std::time::Duration;

use anyhow::{Context, Result, bail, ensure};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use hex::encode;
use serde_json::{Value as JsonValue, from_str, json};
#[cfg(any(target_os = "linux", target_os = "macos"))]
use sha2::{Digest, Sha256};
use tokio::runtime::Builder;

#[cfg(target_os = "linux")]
use libc::{
    _SC_PAGESIZE, EIO, RLIMIT_CORE, SIGABRT, c_void, gettid, pthread_attr_destroy,
    pthread_attr_getguardsize, pthread_attr_getstack, pthread_attr_t, pthread_getattr_np,
    pthread_self, rlimit, setrlimit, sysconf,
};
#[cfg(target_os = "linux")]
use std::arch::asm;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::fs::read_to_string;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::io::Read;
#[cfg(target_os = "linux")]
use std::io::Write;
#[cfg(target_os = "linux")]
use std::mem::MaybeUninit;
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileExt;
#[cfg(target_os = "linux")]
use std::os::unix::process::ExitStatusExt;
#[cfg(any(target_os = "linux", target_os = "macos"))]
use std::path::Path;
#[cfg(target_os = "linux")]
use std::process::{self, Command, Stdio};
#[cfg(target_os = "linux")]
use std::ptr::null_mut;
#[cfg(target_os = "linux")]
use std::thread::sleep;
#[cfg(target_os = "linux")]
use std::time::Instant;
#[cfg(target_os = "linux")]
use tokio::runtime::Runtime as TokioRuntime;

#[cfg(any(target_os = "linux", target_os = "macos"))]
use crate::built_info;
use crate::runtime::Runtime;
use crate::runtime::resource_diagnostics::{self, ThreadEvent};

#[cfg(target_os = "macos")]
mod macos;

#[test]
#[ignore = "run explicitly to isolate a real paid call in a multithread worker"]
fn real_paid_large_frame_on_tokio_worker() -> Result<()> {
    let mode = env::var("KONTOR_RESOURCE_MODE").unwrap_or_else(|_| "reduced".to_string());
    ensure!(
        matches!(mode.as_str(), "production" | "reduced"),
        "unknown resource mode"
    );
    let reduced = mode == "reduced";
    #[cfg(target_os = "linux")]
    let (runtime, workers) = measured_tokio_runtime(reduced.then_some(1024 * 1024))?;
    #[cfg(target_os = "macos")]
    let (runtime, workers) = macos::measured_tokio_runtime(reduced.then_some(1024 * 1024))?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    let worker_ids = workers
        .iter()
        .map(|worker| worker.thread_id)
        .collect::<Vec<_>>();
    #[cfg(target_os = "linux")]
    let blocking = runtime
        .block_on(async { tokio::task::spawn_blocking(current_linux_stack_range).await })?
        .context("blocking pool stack capacity")?;
    #[cfg(target_os = "macos")]
    let blocking = runtime
        .block_on(async { tokio::task::spawn_blocking(macos::current_stack_range).await })?
        .context("blocking pool stack capacity")?;
    #[cfg(target_os = "linux")]
    let caller = current_linux_stack_range().context("block_on caller stack capacity")?;
    #[cfg(target_os = "macos")]
    let caller = macos::current_stack_range().context("block_on caller stack capacity")?;
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    ensure!(
        workers.iter().all(|worker| {
            worker.thread_id != blocking.thread_id
                && worker.thread_id != caller.thread_id
                && worker.os_thread_id != blocking.os_thread_id
                && worker.os_thread_id != caller.os_thread_id
        }) && blocking.thread_id != caller.thread_id
            && blocking.os_thread_id != caller.os_thread_id,
        "measured worker, blocking, and caller thread categories overlap"
    );
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    let (runtime, worker_ids) = {
        let (sender, receiver) = channel();
        let mut builder = Builder::new_multi_thread();
        builder.worker_threads(2).enable_all();
        if reduced {
            builder.thread_stack_size(1024 * 1024);
        }
        let runtime = builder
            .on_thread_start(move || {
                let _ = sender.send(std::thread::current().id());
            })
            .build()?;
        let first = receiver
            .recv_timeout(Duration::from_secs(5))
            .context("first Tokio worker did not start")?;
        let second = receiver
            .recv_timeout(Duration::from_secs(5))
            .context("second Tokio worker did not start")?;
        ensure!(first != second, "Tokio did not start distinct workers");
        (runtime, vec![first, second])
    };
    resource_diagnostics::start();
    let result = runtime.block_on(async {
        tokio::spawn(async move {
            let start = std::thread::current().id();
            super::native_stack::resource_smoke(reduced).await?;
            Ok::<_, anyhow::Error>((start, std::thread::current().id()))
        })
        .await
    });
    let events = resource_diagnostics::finish();
    let (start, end) = result??;
    ensure!(
        worker_ids.contains(&start) && worker_ids.contains(&end),
        "real paid call began or ended outside measured Tokio workers"
    );
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    for event in &events {
        if let Some(worker) = workers
            .iter()
            .find(|worker| worker.thread_id == event.thread_id)
        {
            ensure!(
                event.os_thread_id == worker.os_thread_id,
                "worker Rust/kernel thread identities disagree: {event:?}, {worker:?}"
            );
        } else {
            ensure!(
                workers
                    .iter()
                    .all(|worker| worker.os_thread_id != event.os_thread_id),
                "blocking event shares a measured worker kernel thread: {event:?}"
            );
        }
    }
    attest_resource_threads(&events, &worker_ids, &mode)?;
    #[cfg(target_os = "linux")]
    println!(
        "KONTOR_RESOURCE_RUNTIME={}",
        json!({
            "scope": "diagnostic_only",
            "mode": mode,
            "pid": std::process::id(),
            "flavor": "multi_thread",
            "worker_count": workers.len(),
            "worker_requested_bytes": reduced.then_some(1024 * 1024),
            "thread_observations": [
                linux_thread_observation(&workers[0], "tokio_worker", reduced.then_some(1024 * 1024)),
                linux_thread_observation(&workers[1], "tokio_worker", reduced.then_some(1024 * 1024)),
                linux_thread_observation(&blocking, "blocking_pool", None),
                linux_thread_observation(&caller, "block_on_caller", None),
            ],
            "blocking_pool_observed": true,
            "block_on_caller_observed": true,
        })
    );
    #[cfg(target_os = "macos")]
    println!(
        "KONTOR_RESOURCE_RUNTIME={}",
        json!({
            "scope": "diagnostic_only",
            "mode": mode,
            "pid": std::process::id(),
            "flavor": "multi_thread",
            "worker_count": workers.len(),
            "worker_requested_bytes": reduced.then_some(1024 * 1024),
            "thread_observations": [
                macos::thread_observation(&workers[0], "tokio_worker", reduced.then_some(1024 * 1024)),
                macos::thread_observation(&workers[1], "tokio_worker", reduced.then_some(1024 * 1024)),
                macos::thread_observation(&blocking, "blocking_pool", None),
                macos::thread_observation(&caller, "block_on_caller", None),
            ],
            "blocking_pool_observed": true,
            "block_on_caller_observed": true,
        })
    );
    Ok(())
}

fn attest_resource_threads(events: &[ThreadEvent], workers: &[ThreadId], mode: &str) -> Result<()> {
    let phase_names = [
        "fixture_preparation_entry",
        "publication_entry",
        "publication_exit",
        "fixture_preparation_exit",
        "sample_preparation_entry",
        "sample_preparation_exit",
        "operation_entry",
        "operation_exit",
        "postcall_observation_entry",
        "postcall_observation_exit",
        "teardown_entry",
        "teardown_exit",
    ];
    let mut previous_position = None;
    for name in phase_names {
        let matching = events
            .iter()
            .filter(|event| event.name == name)
            .collect::<Vec<_>>();
        ensure!(
            matching.len() == 1,
            "expected one {name} event: {matching:?}"
        );
        ensure!(
            workers.contains(&matching[0].thread_id),
            "{name} ran outside the Tokio worker pool: {matching:?}"
        );
        let position = events.iter().position(|event| event.name == name).unwrap();
        ensure!(
            previous_position.is_none_or(|previous| position > previous),
            "{name} is out of phase order"
        );
        previous_position = Some(position);
    }
    ensure!(
        events.iter().all(|event| {
            phase_names.contains(&event.name)
                || matches!(
                    event.name,
                    "compiler_entry"
                        | "compiler_exit"
                        | "blocking_decode_entry"
                        | "blocking_decode_exit"
                )
        }),
        "thread trace contains an unclassified event"
    );
    for (entry, exit, on_worker) in [
        ("compiler_entry", "compiler_exit", true),
        ("blocking_decode_entry", "blocking_decode_exit", false),
    ] {
        let entries = events
            .iter()
            .filter(|event| event.name == entry)
            .collect::<Vec<_>>();
        let exits = events
            .iter()
            .filter(|event| event.name == exit)
            .collect::<Vec<_>>();
        ensure!(
            !entries.is_empty() && entries.len() == exits.len(),
            "unpaired {entry}/{exit} events: entries={entries:?}, exits={exits:?}"
        );
        let mut in_flight = HashMap::new();
        for event in events {
            if event.name == entry {
                ensure!(
                    in_flight.insert(event.thread_id, event).is_none(),
                    "overlapping {entry} events on one thread: {event:?}"
                );
            } else if event.name == exit {
                let start = in_flight.remove(&event.thread_id);
                ensure!(
                    start.is_some(),
                    "{exit} has no matching entry on this thread: {event:?}"
                );
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                ensure!(
                    start.unwrap().os_thread_id == event.os_thread_id,
                    "{entry}/{exit} changed kernel thread identity: {event:?}"
                );
            } else {
                continue;
            }
            ensure!(
                workers.contains(&event.thread_id) == on_worker
                    && event.thread_id != std::thread::current().id(),
                "{entry}/{exit} ran in the wrong thread category: {event:?}"
            );
        }
        ensure!(in_flight.is_empty(), "unclosed {entry} events");
    }
    println!(
        "KONTOR_RESOURCE_THREAD_TRACE={}",
        json!({
            "scope": "diagnostic_only",
            "mode": mode,
            "compiler_internal_threads": "unobserved",
            "events": events.iter().map(|event| {
                #[cfg(any(target_os = "linux", target_os = "macos"))]
                let os_thread_id = Some(event.os_thread_id);
                #[cfg(not(any(target_os = "linux", target_os = "macos")))]
                let os_thread_id = None::<i32>;
                json!({
                    "name": event.name,
                    "rust_thread_id": format!("{:?}", event.thread_id),
                    "category": if workers.contains(&event.thread_id) {
                        "tokio_worker"
                    } else {
                        "blocking_pool"
                    },
                    "os_thread_id": os_thread_id,
                })
            }).collect::<Vec<_>>(),
        })
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "run through the bounded resource child driver"]
fn chain_worker_case() -> Result<()> {
    let mode = env::var("KONTOR_RESOURCE_MODE")?;
    ensure!(
        matches!(mode.as_str(), "reduced" | "production"),
        "unknown resource mode"
    );
    let stores: u32 = env::var("KONTOR_CHAIN_STORES")?.parse()?;
    ensure!(
        matches!(stores, 33 | 63 | 64 | 65),
        "unsupported resource chain count"
    );
    let chain_mode = env::var("KONTOR_CHAIN_MODE")?;
    ensure!(
        matches!(chain_mode.as_str(), "paid" | "view" | "core"),
        "unknown resource chain call mode"
    );
    let trap_control = match env::var("KONTOR_CHAIN_TRAP_CONTROL").as_deref() {
        Ok("1") => true,
        Ok("0") => false,
        _ => bail!("invalid resource chain control selection"),
    };
    ensure!(
        !trap_control || stores == 64,
        "trap control requires 64 Stores"
    );
    let reduced = mode == "reduced";
    let (runtime, workers) = measured_tokio_runtime(reduced.then_some(1024 * 1024))?;
    let blocking = runtime
        .block_on(async { tokio::task::spawn_blocking(current_linux_stack_range).await })?
        .context("blocking pool stack capacity")?;
    let caller = current_linux_stack_range().context("block_on caller stack capacity")?;
    let worker_ids = workers
        .iter()
        .map(|worker| worker.thread_id)
        .collect::<Vec<_>>();
    ensure!(
        workers.iter().all(|worker| {
            worker.thread_id != blocking.thread_id
                && worker.thread_id != caller.thread_id
                && worker.os_thread_id != blocking.os_thread_id
                && worker.os_thread_id != caller.os_thread_id
        }) && blocking.thread_id != caller.thread_id
            && blocking.os_thread_id != caller.os_thread_id,
        "chain worker, blocking, and caller thread categories overlap"
    );
    resource_diagnostics::start_chain();
    let task_chain_mode = chain_mode.clone();
    let result = runtime.block_on(async {
        tokio::spawn(async move {
            let start = std::thread::current().id();
            if trap_control {
                super::sequential_chains::resource_chain_trap_control(
                    task_chain_mode,
                    stores - 1,
                    reduced,
                )
                .await?;
            } else {
                super::sequential_chains::resource_chain_probe(
                    task_chain_mode,
                    stores - 1,
                    reduced,
                )
                .await?;
            }
            Ok::<_, anyhow::Error>((start, std::thread::current().id()))
        })
        .await
    });
    let events = resource_diagnostics::finish();
    let (start, end) = result??;
    ensure!(
        worker_ids.contains(&start) && worker_ids.contains(&end),
        "chain case began or ended outside measured Tokio workers"
    );
    for event in &events {
        if let Some(worker) = workers
            .iter()
            .find(|worker| worker.thread_id == event.thread_id)
        {
            ensure!(
                event.os_thread_id == worker.os_thread_id,
                "chain worker Rust/kernel thread identity differs: {event:?}"
            );
        } else {
            ensure!(
                event.name.starts_with("blocking_decode_")
                    && workers
                        .iter()
                        .all(|worker| worker.os_thread_id != event.os_thread_id),
                "chain event escaped worker or blocking category: {event:?}"
            );
        }
    }
    ensure!(
        events
            .iter()
            .any(|event| event.name == "canonical_input_entry")
            && (stores == 65
                || events
                    .iter()
                    .any(|event| event.name == "canonical_output_entry")),
        "chain case did not observe required input or result conversion"
    );
    println!(
        "KONTOR_CHAIN_WORKER_RUNTIME={}",
        json!({
            "scope": "paired_chain_worker",
            "mode": mode,
            "stores": stores,
            "chain_mode": chain_mode,
            "trap_control": trap_control,
            "pid": std::process::id(),
            "flavor": "multi_thread",
            "worker_count": workers.len(),
            "worker_requested_bytes": reduced.then_some(1024 * 1024),
            "thread_observations": [
                linux_thread_observation(&workers[0], "tokio_worker", reduced.then_some(1024 * 1024)),
                linux_thread_observation(&workers[1], "tokio_worker", reduced.then_some(1024 * 1024)),
                linux_thread_observation(&blocking, "blocking_pool", None),
                linux_thread_observation(&caller, "block_on_caller", None),
            ],
            "blocking_pool_observed": true,
            "block_on_caller_observed": true,
        })
    );
    println!(
        "KONTOR_CHAIN_WORKER_TRACE={}",
        json!({
            "scope": "paired_chain_worker",
            "mode": mode,
            "stores": stores,
            "chain_mode": chain_mode,
            "trap_control": trap_control,
            "events": events.iter().map(|event| json!({
                "name": event.name,
                "thread_id": format!("{:?}", event.thread_id),
                "os_thread_id": event.os_thread_id,
                "category": if worker_ids.contains(&event.thread_id) {
                    "tokio_worker"
                } else {
                    "blocking_pool"
                },
            })).collect::<Vec<_>>(),
        })
    );
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "run through the bounded Pulley resource child driver"]
fn pulley_boundary_worker_case() -> Result<()> {
    let configuration = env::var("KONTOR_RESOURCE_MODE")?;
    ensure!(
        matches!(configuration.as_str(), "reduced" | "production"),
        "unknown resource configuration"
    );
    let case_id = env::var("KONTOR_BOUNDARY_CASE")?;
    let process_role = env::var("KONTOR_BOUNDARY_ROLE")?;
    let probe = env::var("KONTOR_RESOURCE_TEARDOWN_PROBE")?;
    ensure!(
        (process_role == "probe_off_control" && probe == "off")
            || (process_role != "probe_off_control" && probe == "on"),
        "boundary process role and teardown probe differ"
    );
    let frozen_depths = match (
        env::var("KONTOR_BOUNDARY_LAST_SUCCESS"),
        env::var("KONTOR_BOUNDARY_FIRST_FAILURE"),
    ) {
        (Ok(last), Ok(first)) => Some((last.parse::<u32>()?, first.parse::<u32>()?)),
        (Err(env::VarError::NotPresent), Err(env::VarError::NotPresent)) => None,
        _ => bail!("boundary depth environment is incomplete"),
    };
    let reduced = configuration == "reduced";
    #[cfg(target_os = "linux")]
    let (runtime, workers) = measured_tokio_runtime(reduced.then_some(1024 * 1024))?;
    #[cfg(target_os = "macos")]
    let (runtime, workers) = macos::measured_tokio_runtime(reduced.then_some(1024 * 1024))?;
    #[cfg(target_os = "linux")]
    let blocking = runtime
        .block_on(async { tokio::task::spawn_blocking(current_linux_stack_range).await })?
        .context("blocking pool stack capacity")?;
    #[cfg(target_os = "macos")]
    let blocking = runtime
        .block_on(async { tokio::task::spawn_blocking(macos::current_stack_range).await })?
        .context("blocking pool stack capacity")?;
    #[cfg(target_os = "linux")]
    let caller = current_linux_stack_range().context("block_on caller stack capacity")?;
    #[cfg(target_os = "macos")]
    let caller = macos::current_stack_range().context("block_on caller stack capacity")?;
    let worker_ids = workers
        .iter()
        .map(|worker| worker.thread_id)
        .collect::<Vec<_>>();
    ensure!(
        workers.iter().all(|worker| {
            worker.thread_id != blocking.thread_id
                && worker.thread_id != caller.thread_id
                && worker.os_thread_id != blocking.os_thread_id
                && worker.os_thread_id != caller.os_thread_id
        }) && blocking.thread_id != caller.thread_id
            && blocking.os_thread_id != caller.os_thread_id,
        "boundary worker, blocking, and caller thread categories overlap"
    );
    resource_diagnostics::start_chain();
    let task_case_id = case_id.clone();
    let task_configuration = configuration.clone();
    let task_role = process_role.clone();
    let result = runtime.block_on(async {
        tokio::spawn(async move {
            let start = std::thread::current().id();
            let summary = super::native_stack::resource_boundary(
                &task_case_id,
                &task_configuration,
                &task_role,
                frozen_depths,
            )
            .await?;
            Ok::<_, anyhow::Error>((summary, start, std::thread::current().id()))
        })
        .await
    });
    let events = resource_diagnostics::finish();
    let (summary, start, end) = result??;
    ensure!(
        worker_ids.contains(&start) && worker_ids.contains(&end),
        "boundary case began or ended outside measured Tokio workers"
    );
    for event in &events {
        if let Some(worker) = workers
            .iter()
            .find(|worker| worker.thread_id == event.thread_id)
        {
            ensure!(
                event.os_thread_id == worker.os_thread_id,
                "boundary worker Rust/kernel thread identity differs: {event:?}"
            );
        } else {
            ensure!(
                event.name.starts_with("blocking_decode_")
                    && workers
                        .iter()
                        .all(|worker| worker.os_thread_id != event.os_thread_id),
                "boundary event escaped worker or blocking category: {event:?}"
            );
        }
    }
    #[cfg(target_os = "linux")]
    let thread_observations = [
        linux_thread_observation(&workers[0], "tokio_worker", reduced.then_some(1024 * 1024)),
        linux_thread_observation(&workers[1], "tokio_worker", reduced.then_some(1024 * 1024)),
        linux_thread_observation(&blocking, "blocking_pool", None),
        linux_thread_observation(&caller, "block_on_caller", None),
    ];
    #[cfg(target_os = "macos")]
    let thread_observations = [
        macos::thread_observation(&workers[0], "tokio_worker", reduced.then_some(1024 * 1024)),
        macos::thread_observation(&workers[1], "tokio_worker", reduced.then_some(1024 * 1024)),
        macos::thread_observation(&blocking, "blocking_pool", None),
        macos::thread_observation(&caller, "block_on_caller", None),
    ];
    println!(
        "BOUNDARY_WORKER_RUNTIME={}",
        json!({
            "scope": "paired_pulley_boundary_worker",
            "configuration": configuration,
            "case_id": case_id,
            "process_role": process_role,
            "pid": std::process::id(),
            "flavor": "multi_thread",
            "worker_count": workers.len(),
            "worker_requested_bytes": reduced.then_some(1024 * 1024),
            "thread_observations": thread_observations,
            "blocking_pool_observed": true,
            "block_on_caller_observed": true,
            "embedded_source_sha": built_info::GIT_COMMIT_HASH,
            "binary_sha256": sha256_file(&env::current_exe()?)?,
        })
    );
    println!(
        "BOUNDARY_WORKER_TRACE={}",
        json!({
            "scope": "paired_pulley_boundary_worker",
            "configuration": configuration,
            "case_id": case_id,
            "process_role": process_role,
            "events": events.iter().map(|event| json!({
                "name": event.name,
                "thread_id": format!("{:?}", event.thread_id),
                "os_thread_id": event.os_thread_id,
                "category": if worker_ids.contains(&event.thread_id) {
                    "tokio_worker"
                } else {
                    "blocking_pool"
                },
            })).collect::<Vec<_>>(),
        })
    );
    println!("BOUNDARY_PROBE_SUMMARY:{summary}");
    println!(
        "BOUNDARY_PROBE_TERMINAL:{}",
        json!({
            "case_id": case_id,
            "process_role": process_role,
            "configuration": configuration,
            "pid": std::process::id(),
            "attempt_count": summary["attempt_count"],
            "complete": true,
        })
    );
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
#[test]
#[ignore = "run through the bounded finite stack resource child driver"]
fn finite_stack_worker_case() -> Result<()> {
    let configuration = env::var("KONTOR_RESOURCE_MODE")?;
    ensure!(
        matches!(configuration.as_str(), "reduced" | "production"),
        "unknown resource configuration"
    );
    let case_id = env::var("KONTOR_FINITE_STACK_CASE")?;
    ensure!(
        matches!(
            case_id.as_str(),
            "large_frame_paid"
                | "max_gas_paid"
                | "pending_host_io"
                | "canonical_lift_lower"
                | "canonical_realloc"
                | "canonical_post_return"
                | "generated_initialization"
                | "explicit_resource_drop"
                | "failed_instantiation_cleanup"
                | "foreign_wave_parse_print"
                | "canonical_type_value_recursion"
        ),
        "unknown finite stack case"
    );
    let process_role = env::var("KONTOR_FINITE_STACK_ROLE")?;
    let probe = env::var("KONTOR_RESOURCE_TEARDOWN_PROBE")?;
    ensure!(
        (process_role == "target_observed" && probe == "on")
            || (process_role == "probe_off_control" && probe == "off"),
        "finite stack role and teardown probe differ"
    );
    let reduced = configuration == "reduced";
    #[cfg(target_os = "linux")]
    let (runtime, workers) = measured_tokio_runtime(reduced.then_some(1024 * 1024))?;
    #[cfg(target_os = "macos")]
    let (runtime, workers) = macos::measured_tokio_runtime(reduced.then_some(1024 * 1024))?;
    #[cfg(target_os = "linux")]
    let blocking = runtime
        .block_on(async { tokio::task::spawn_blocking(current_linux_stack_range).await })?
        .context("blocking pool stack capacity")?;
    #[cfg(target_os = "macos")]
    let blocking = runtime
        .block_on(async { tokio::task::spawn_blocking(macos::current_stack_range).await })?
        .context("blocking pool stack capacity")?;
    #[cfg(target_os = "linux")]
    let caller = current_linux_stack_range().context("block_on caller stack capacity")?;
    #[cfg(target_os = "macos")]
    let caller = macos::current_stack_range().context("block_on caller stack capacity")?;
    let worker_ids = workers
        .iter()
        .map(|worker| worker.thread_id)
        .collect::<Vec<_>>();
    ensure!(
        workers
            .iter()
            .all(|worker| worker.thread_id != blocking.thread_id
                && worker.thread_id != caller.thread_id
                && worker.os_thread_id != blocking.os_thread_id
                && worker.os_thread_id != caller.os_thread_id)
            && blocking.thread_id != caller.thread_id
            && blocking.os_thread_id != caller.os_thread_id,
        "finite stack worker, blocking, and caller thread categories overlap"
    );
    resource_diagnostics::start_chain();
    let task_case_id = case_id.clone();
    let task_configuration = configuration.clone();
    let task_role = process_role.clone();
    let result = runtime.block_on(async {
        tokio::spawn(async move {
            let start = std::thread::current().id();
            let summary = if task_case_id == "pending_host_io" {
                super::native_stack::resource_pending_host_io(&task_configuration, &task_role)
                    .await?
            } else if task_case_id == "generated_initialization" {
                super::native_stack::resource_generated_initialization(
                    &task_configuration,
                    &task_role,
                )
                .await?
            } else if matches!(
                task_case_id.as_str(),
                "explicit_resource_drop" | "failed_instantiation_cleanup"
            ) {
                super::native_stack::resource_lifecycle(
                    &task_case_id,
                    &task_configuration,
                    &task_role,
                )
                .await?
            } else if task_case_id == "foreign_wave_parse_print" {
                super::native_stack::resource_foreign_wave(&task_configuration, &task_role).await?
            } else if task_case_id == "canonical_type_value_recursion" {
                super::native_stack::resource_type_value(&task_configuration, &task_role).await?
            } else if task_case_id.starts_with("canonical_") {
                super::native_stack::resource_canonical(
                    &task_case_id,
                    &task_configuration,
                    &task_role,
                )
                .await?
            } else {
                super::native_stack::resource_finite_paid(
                    &task_case_id,
                    &task_configuration,
                    &task_role,
                )
                .await?
            };
            Ok::<_, anyhow::Error>((summary, start, std::thread::current().id()))
        })
        .await
    });
    let events = resource_diagnostics::finish();
    let (summary, start, end) = result??;
    ensure!(
        worker_ids.contains(&start) && worker_ids.contains(&end),
        "finite stack call began or ended outside measured Tokio workers"
    );
    for event in &events {
        if let Some(worker) = workers
            .iter()
            .find(|worker| worker.thread_id == event.thread_id)
        {
            ensure!(
                event.os_thread_id == worker.os_thread_id,
                "finite stack worker Rust/kernel thread identity differs: {event:?}"
            );
        } else {
            ensure!(
                event.name.starts_with("blocking_decode_")
                    && workers
                        .iter()
                        .all(|worker| worker.os_thread_id != event.os_thread_id),
                "finite stack event escaped worker or blocking category: {event:?}"
            );
        }
    }
    #[cfg(target_os = "linux")]
    let thread_observations = [
        linux_thread_observation(&workers[0], "tokio_worker", reduced.then_some(1024 * 1024)),
        linux_thread_observation(&workers[1], "tokio_worker", reduced.then_some(1024 * 1024)),
        linux_thread_observation(&blocking, "blocking_pool", None),
        linux_thread_observation(&caller, "block_on_caller", None),
    ];
    #[cfg(target_os = "macos")]
    let thread_observations = [
        macos::thread_observation(&workers[0], "tokio_worker", reduced.then_some(1024 * 1024)),
        macos::thread_observation(&workers[1], "tokio_worker", reduced.then_some(1024 * 1024)),
        macos::thread_observation(&blocking, "blocking_pool", None),
        macos::thread_observation(&caller, "block_on_caller", None),
    ];
    println!(
        "FINITE_STACK_RUNTIME={}",
        json!({
            "scope": "paired_finite_stack_worker",
            "configuration": configuration,
            "case_id": case_id,
            "process_role": process_role,
            "pid": std::process::id(),
            "flavor": "multi_thread",
            "worker_count": workers.len(),
            "worker_requested_bytes": reduced.then_some(1024 * 1024),
            "thread_observations": thread_observations,
            "blocking_pool_observed": true,
            "block_on_caller_observed": true,
            "embedded_source_sha": built_info::GIT_COMMIT_HASH,
            "binary_sha256": sha256_file(&env::current_exe()?)?,
        })
    );
    println!(
        "FINITE_STACK_TRACE={}",
        json!({
            "scope": "paired_finite_stack_worker",
            "configuration": configuration,
            "case_id": case_id,
            "process_role": process_role,
            "events": events.iter().map(|event| json!({
                "name": event.name,
                "thread_id": format!("{:?}", event.thread_id),
                "os_thread_id": event.os_thread_id,
                "category": if worker_ids.contains(&event.thread_id) {
                    "tokio_worker"
                } else {
                    "blocking_pool"
                },
            })).collect::<Vec<_>>(),
        })
    );
    println!(
        "FINITE_STACK_TERMINAL={}",
        json!({
            "case_id": case_id,
            "process_role": process_role,
            "configuration": configuration,
            "pid": std::process::id(),
            "sample_count": summary["sample_count"],
            "complete": true,
        })
    );
    Ok(())
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "run explicitly to verify macOS worker guards in isolated child processes"]
fn macos_worker_guard_fault_control() -> Result<()> {
    macos::guard_fault_control()
}

#[cfg(target_os = "macos")]
#[test]
#[ignore = "run only as a faulting child of macos_worker_guard_fault_control"]
fn macos_worker_guard_fault_child() -> Result<()> {
    macos::guard_fault_child()
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "run explicitly to verify worker guards in isolated child processes"]
fn linux_worker_guard_fault_control() -> Result<()> {
    let binary = env::current_exe()?;
    for mode in ["reduced", "production"] {
        let mut child = Command::new(&binary)
            .args([
                "--exact",
                "runtime::call::tests::native_stack_resource::linux_worker_guard_fault_child",
                "--ignored",
                "--nocapture",
            ])
            .env("KONTOR_RESOURCE_GUARD_FAULT_CHILD", "1")
            .env("KONTOR_RESOURCE_MODE", mode)
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        let process_id = child.id();
        let started = Instant::now();
        while child.try_wait()?.is_none() {
            if started.elapsed() >= Duration::from_secs(30) {
                if let Err(error) = child.kill()
                    && child.try_wait()?.is_none()
                {
                    return Err(error.into());
                }
                let output = child.wait_with_output()?;
                bail!(
                    "{mode} guard child timed out: stdout={}, stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output()?;
        let stderr = String::from_utf8_lossy(&output.stderr);
        let signal = output.status.signal();
        ensure!(
            signal == Some(SIGABRT)
                && stderr.contains("has overflowed its stack")
                && stderr.contains("fatal runtime error: stack overflow"),
            "{mode} guard child did not report a guard fault: status={:?}, stderr={}",
            output.status,
            stderr
        );
        let stdout = String::from_utf8(output.stdout)?;
        let targets = stdout
            .lines()
            .filter_map(|line| {
                line.split_once("KONTOR_RESOURCE_GUARD_TARGET=")
                    .map(|(_, value)| value)
            })
            .collect::<Vec<_>>();
        ensure!(
            targets.len() == 1,
            "{mode} child did not report exactly one guard target"
        );
        let target: JsonValue = from_str(targets[0])?;
        let guard_start = target["guard_start"]
            .as_u64()
            .context("missing guard start")?;
        let guard_end = target["guard_end"].as_u64().context("missing guard end")?;
        let address = target["address"]
            .as_u64()
            .context("missing fault address")?;
        let page_size = target["page_size_bytes"]
            .as_u64()
            .context("missing page size")?;
        let os_thread_id = target["os_thread_id"]
            .as_i64()
            .context("missing kernel thread ID")?;
        ensure!(
            target["mode"].as_str() == Some(mode)
                && target["process_id"].as_u64() == Some(u64::from(process_id))
                && os_thread_id > 0
                && page_size.is_power_of_two()
                && guard_end
                    .checked_sub(guard_start)
                    .is_some_and(|bytes| bytes >= page_size)
                && guard_start <= address
                && address < guard_end
                && matches!(
                    target["guard_verification"].as_str(),
                    Some("guard protected inside pthread stack range")
                        | Some("guard protected below pthread stack range")
                        | Some(
                            "inaccessible interval verified below pthread stack range by /proc/self/mem EIO"
                        )
                ),
            "{mode} child reported an invalid guard target: {target}"
        );
        ensure!(
            stderr.contains(&format!("({os_thread_id}) has overflowed its stack")),
            "{mode} stack-overflow abort was reported for a different thread"
        );
        println!(
            "KONTOR_RESOURCE_GUARD_CONTROL={}",
            json!({
                "mode": mode,
                "signal": signal,
                "target": target,
                "child_binary": binary,
                "child_stdout": stdout,
                "child_stderr": String::from_utf8_lossy(&output.stderr),
            })
        );
    }
    println!(
        "KONTOR_RESOURCE_GUARD_TERMINAL={}",
        json!({
            "pid": process::id(),
            "binary_path": binary,
            "binary_sha256": sha256_file(&binary)?,
            "embedded_source_sha": built_info::GIT_COMMIT_HASH
                .context("guard control binary has no embedded source revision")?,
            "modes": ["reduced", "production"],
            "complete": true,
        })
    );
    Ok(())
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
fn sha256_file(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut digest = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        digest.update(&buffer[..count]);
    }
    Ok(encode(digest.finalize()))
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "run only as a faulting child of linux_worker_guard_fault_control"]
fn linux_worker_guard_fault_child() -> Result<()> {
    ensure!(
        env::var("KONTOR_RESOURCE_GUARD_FAULT_CHILD").as_deref() == Ok("1"),
        "guard fault child requires its isolated parent"
    );
    let mode = env::var("KONTOR_RESOURCE_MODE")?;
    ensure!(
        matches!(mode.as_str(), "reduced" | "production"),
        "unknown guard mode"
    );
    let limit = rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    ensure!(
        unsafe { setrlimit(RLIMIT_CORE, &limit) } == 0,
        "could not disable core dump"
    );
    let (runtime, _) = measured_tokio_runtime((mode == "reduced").then_some(1024 * 1024))?;
    runtime.block_on(async move {
        tokio::spawn(async move {
            let stack = current_linux_stack_range()?;
            ensure!(stack.guard_bytes > 0, "worker has no reported guard");
            let address = stack.guard_start + stack.page_size_bytes / 2;
            ensure!(
                address < stack.guard_end,
                "guard target is outside protected interval"
            );
            println!(
                "KONTOR_RESOURCE_GUARD_TARGET={}",
                json!({
                    "mode": mode,
                    "process_id": stack.process_id,
                    "os_thread_id": stack.os_thread_id,
                    "page_size_bytes": stack.page_size_bytes,
                    "guard_start": stack.guard_start,
                    "guard_end": stack.guard_end,
                    "guard_verification": stack.guard_treatment,
                    "address": address,
                })
            );
            std::io::stdout().flush()?;
            // A machine store probes the guard without creating a Rust reference
            // to an inaccessible address in this deliberately faulting child.
            unsafe {
                #[cfg(target_arch = "x86_64")]
                asm!("mov byte ptr [{address}], 0", address = in(reg) address, options(nostack));
                #[cfg(target_arch = "aarch64")]
                asm!("strb wzr, [{address}]", address = in(reg) address, options(nostack));
            }
            Ok::<(), anyhow::Error>(())
        })
        .await
    })??;
    bail!("worker guard access did not fault")
}

#[cfg(target_os = "linux")]
#[derive(Debug)]
struct LinuxStackRange {
    thread_id: ThreadId,
    process_id: u32,
    os_thread_id: i32,
    page_size_bytes: usize,
    mapped_start: usize,
    mapped_end: usize,
    usable_start: usize,
    usable_end: usize,
    guard_start: usize,
    guard_end: usize,
    guard_bytes: usize,
    guard_treatment: &'static str,
}

#[cfg(target_os = "linux")]
fn linux_thread_observation(
    stack: &LinuxStackRange,
    category: &str,
    requested_bytes: Option<usize>,
) -> JsonValue {
    let guard_verification = match stack.guard_treatment {
        "guard protected inside pthread stack range"
        | "guard protected below pthread stack range" => "linux_maps_prot_none",
        "inaccessible interval verified below pthread stack range by /proc/self/mem EIO" => {
            "linux_proc_self_mem_eio"
        }
        "pthread reports no guard" => "pthread_reports_none",
        _ => unreachable!("current_linux_stack_range returned unknown guard treatment"),
    };
    json!({
        "thread_category": category,
        "thread_id": format!("{:?}", stack.thread_id),
        "process_id": stack.process_id,
        "os_thread_id": stack.os_thread_id,
        "identity_api": "linux_gettid",
        "page_size_bytes": stack.page_size_bytes,
        "requested_bytes": requested_bytes,
        "mapped_bytes": stack.mapped_end - stack.mapped_start,
        "guard_bytes": stack.guard_bytes,
        "guard_start": stack.guard_start,
        "guard_end": stack.guard_end,
        "guard_verification": guard_verification,
        "usable_bytes": stack.usable_end - stack.usable_start,
        "mapped_start": stack.mapped_start,
        "mapped_end": stack.mapped_end,
        "usable_start": stack.usable_start,
        "usable_end": stack.usable_end,
        "measurement_api": "pthread_getattr_np,pthread_attr_getstack,pthread_attr_getguardsize,/proc/self/maps,/proc/self/mem",
        "guard_treatment": stack.guard_treatment,
        "guard_verified": true,
    })
}

#[cfg(target_os = "linux")]
fn current_linux_stack_range() -> Result<LinuxStackRange> {
    let mut raw = MaybeUninit::<pthread_attr_t>::uninit();
    // pthread_getattr_np initializes the opaque attribute object; destroy it
    // after both getters, including when a getter fails.
    let status = unsafe { pthread_getattr_np(pthread_self(), raw.as_mut_ptr()) };
    ensure!(status == 0, "pthread_getattr_np failed: {status}");
    let mut attr = unsafe { raw.assume_init() };
    let mut stack_ptr = null_mut::<c_void>();
    let mut stack_size = 0;
    let mut guard_size = 0;
    let stack_status = unsafe { pthread_attr_getstack(&attr, &mut stack_ptr, &mut stack_size) };
    let guard_status = unsafe { pthread_attr_getguardsize(&attr, &mut guard_size) };
    let destroy_status = unsafe { pthread_attr_destroy(&mut attr) };
    ensure!(
        stack_status == 0,
        "pthread_attr_getstack failed: {stack_status}"
    );
    ensure!(
        guard_status == 0,
        "pthread_attr_getguardsize failed: {guard_status}"
    );
    ensure!(
        destroy_status == 0,
        "pthread_attr_destroy failed: {destroy_status}"
    );
    let mapped_start = stack_ptr as usize;
    let mapped_end = mapped_start
        .checked_add(stack_size)
        .context("stack range overflow")?;
    ensure!(
        mapped_start > 0 && mapped_end > mapped_start,
        "invalid pthread stack range"
    );
    let page_size = unsafe { sysconf(_SC_PAGESIZE) };
    ensure!(page_size > 0, "host page size is unavailable");
    let page_size = usize::try_from(page_size)?;
    let os_thread_id = unsafe { gettid() };
    ensure!(os_thread_id > 0, "kernel thread ID is unavailable");

    let marker = 0u8;
    let marker_address = std::hint::black_box(&marker as *const u8 as usize);
    let maps = read_to_string("/proc/self/maps")?;
    let mut ranges = Vec::new();
    for line in maps.lines() {
        let mut fields = line.split_whitespace();
        let addresses = fields.next().context("missing maps addresses")?;
        let permissions = fields.next().context("missing maps permissions")?;
        let (start, end) = addresses.split_once('-').context("malformed maps range")?;
        ranges.push((
            usize::from_str_radix(start, 16)?,
            usize::from_str_radix(end, 16)?,
            permissions,
        ));
    }
    let writable = ranges
        .iter()
        .find(|(start, end, permissions)| {
            *start <= marker_address && marker_address < *end && permissions.starts_with("rw")
        })
        .context("thread stack pointer is not in a writable mapping")?;
    let usable_start = writable.0.max(mapped_start);
    let usable_end = writable.1.min(mapped_end);
    ensure!(
        usable_start <= marker_address && marker_address < usable_end,
        "pthread stack and live writable mapping disagree"
    );
    let internal_guard = ranges.iter().any(|(start, end, permissions)| {
        *start == mapped_start && *end == usable_start && permissions.starts_with("---")
    });
    let external_guard = ranges.iter().any(|(start, end, permissions)| {
        *end == mapped_start
            && mapped_start - *start >= guard_size
            && permissions.starts_with("---")
    });
    let (guard_start, guard_end, guard_treatment) = if guard_size == 0 {
        (0, 0, "pthread reports no guard")
    } else if internal_guard && usable_start - mapped_start >= guard_size {
        (
            mapped_start,
            usable_start,
            "guard protected inside pthread stack range",
        )
    } else if external_guard {
        let start = ranges
            .iter()
            .find(|(start, end, permissions)| {
                *end == mapped_start
                    && mapped_start - *start >= guard_size
                    && permissions.starts_with("---")
            })
            .context("external guard mapping disappeared")?
            .0;
        (
            start,
            mapped_start,
            "guard protected below pthread stack range",
        )
    } else {
        // glibc 2.42 may install lightweight guards inside an rw VMA. Those
        // pages are absent from maps but /proc/self/mem returns EIO on them.
        ensure!(
            guard_size.is_multiple_of(page_size),
            "pthread guard is not page aligned"
        );
        let guard_start = mapped_start
            .checked_sub(guard_size)
            .context("guard underflow")?;
        let mem = File::open("/proc/self/mem")?;
        let mut byte = [0u8; 1];
        let usable_read = mem.read_at(&mut byte, mapped_start as u64);
        let guard_protected = (guard_start..mapped_start)
            .step_by(page_size)
            .all(|address| {
                mem.read_at(&mut byte, address as u64)
                    .is_err_and(|error| error.raw_os_error() == Some(EIO))
            });
        ensure!(
            matches!(usable_read, Ok(1)) && guard_protected,
            "pthread guard is not verified by maps or /proc/self/mem: pthread={mapped_start:#x}..{mapped_end:#x}, guard={guard_size}, writable={writable:?}"
        );
        (
            guard_start,
            mapped_start,
            "inaccessible interval verified below pthread stack range by /proc/self/mem EIO",
        )
    };
    ensure!(
        guard_bytes_match(guard_start, guard_end, guard_size, page_size),
        "guard range is inconsistent with the pthread guard size"
    );
    Ok(LinuxStackRange {
        thread_id: std::thread::current().id(),
        process_id: std::process::id(),
        os_thread_id,
        page_size_bytes: page_size,
        mapped_start,
        mapped_end,
        usable_start,
        usable_end,
        guard_start,
        guard_end,
        guard_bytes: guard_size,
        guard_treatment,
    })
}

#[cfg(target_os = "linux")]
fn guard_bytes_match(start: usize, end: usize, size: usize, page_size: usize) -> bool {
    start <= end
        && end - start >= size
        && start.is_multiple_of(page_size)
        && end.is_multiple_of(page_size)
}

#[test]
fn reduced_resource_engine_keeps_the_logical_stack() -> Result<()> {
    let production = Runtime::new_engine()?;
    let reduced = Runtime::new_resource_diagnostic_engine()?;
    assert_eq!(production.get_target(), reduced.get_target());
    assert_eq!(production.get_max_wasm_stack(), 512 * 1024);
    assert_eq!(
        reduced.get_max_wasm_stack(),
        production.get_max_wasm_stack()
    );
    assert_eq!(production.get_async_stack_size(), 2 * 1024 * 1024);
    assert_eq!(reduced.get_async_stack_size(), 1024 * 1024);
    Ok(())
}

#[cfg(target_os = "linux")]
fn measured_tokio_runtime(
    worker_stack_size: Option<usize>,
) -> Result<(TokioRuntime, [LinuxStackRange; 2])> {
    let (sender, receiver) = channel();
    let mut builder = Builder::new_multi_thread();
    builder.worker_threads(2).enable_all();
    if let Some(size) = worker_stack_size {
        builder.thread_stack_size(size);
    }
    let runtime = builder
        .on_thread_start(move || {
            let _ = sender.send(current_linux_stack_range());
        })
        .build()?;
    let first = receiver
        .recv_timeout(Duration::from_secs(5))
        .context("first Tokio worker did not start")?
        .context("first Tokio worker stack capacity")?;
    let second = receiver
        .recv_timeout(Duration::from_secs(5))
        .context("second Tokio worker did not start")?
        .context("second Tokio worker stack capacity")?;
    ensure!(
        first.thread_id != second.thread_id && first.os_thread_id != second.os_thread_id,
        "Tokio did not start distinct workers"
    );
    Ok((runtime, [first, second]))
}

#[cfg(target_os = "linux")]
#[test]
fn reduced_tokio_workers_have_measured_usable_ranges() -> Result<()> {
    let (runtime, reduced) = measured_tokio_runtime(Some(1024 * 1024))?;
    let [first, second] = &reduced;
    for stack in [&first, &second] {
        ensure!(
            stack.process_id == std::process::id()
                && stack.mapped_start <= stack.usable_start
                && stack.usable_start < stack.usable_end
                && stack.usable_end <= stack.mapped_end
                && stack.page_size_bytes > 0
                && stack.guard_end - stack.guard_start >= stack.guard_bytes
                && stack.guard_bytes > 0
                && stack.guard_treatment != "pthread reports no guard",
            "reduced worker guard/range is not verified: {stack:?}"
        );
    }
    let blocking = runtime
        .block_on(async { tokio::task::spawn_blocking(current_linux_stack_range).await })?
        .context("blocking pool stack capacity")?;
    let caller = current_linux_stack_range().context("block_on caller stack capacity")?;
    ensure!(
        blocking.process_id == std::process::id()
            && caller.process_id == std::process::id()
            && blocking.thread_id != first.thread_id
            && blocking.thread_id != second.thread_id
            && caller.thread_id != first.thread_id
            && caller.thread_id != second.thread_id
            && blocking.os_thread_id != first.os_thread_id
            && blocking.os_thread_id != second.os_thread_id
            && caller.os_thread_id != first.os_thread_id
            && caller.os_thread_id != second.os_thread_id,
        "blocking/caller and Tokio worker categories overlap"
    );
    let (_production_runtime, production) = measured_tokio_runtime(None)?;
    ensure!(
        production
            .iter()
            .all(|stack| stack.process_id == std::process::id()),
        "production worker process identity differs from the current process"
    );
    let production_min = production
        .iter()
        .map(|stack| stack.usable_end - stack.usable_start)
        .min()
        .context("production workers missing")?;
    let reduced_max = reduced
        .iter()
        .map(|stack| stack.usable_end - stack.usable_start)
        .max()
        .context("reduced workers missing")?;
    ensure!(
        production_min >= reduced_max.saturating_mul(2),
        "actual worker usable-capacity ratio is below two: production_min={production_min}, reduced_max={reduced_max}"
    );
    Ok(())
}
