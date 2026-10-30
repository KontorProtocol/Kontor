use std::arch::asm;
use std::env;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::process::{self, Command, Stdio};
use std::sync::mpsc::channel;
use std::thread::{self, ThreadId};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail, ensure};
use libc::{
    _SC_PAGESIZE, RLIMIT_CORE, SIGABRT, pthread_get_stackaddr_np, pthread_get_stacksize_np,
    pthread_self, pthread_threadid_np, rlimit, setrlimit, sysconf,
};
use mach2::kern_return::KERN_SUCCESS;
use mach2::mach_port::mach_port_deallocate;
use mach2::port::MACH_PORT_NULL;
use mach2::traps::mach_task_self;
use mach2::vm::mach_vm_region;
use mach2::vm_prot::{VM_PROT_NONE, VM_PROT_READ, VM_PROT_WRITE};
use mach2::vm_region::{VM_REGION_BASIC_INFO_64, vm_region_basic_info_64, vm_region_info_t};
use serde_json::{Value as JsonValue, from_str, json};
use tokio::runtime::{Builder, Runtime as TokioRuntime};

use crate::built_info;

use super::sha256_file;

#[derive(Debug)]
pub(super) struct MacStackRange {
    pub(super) thread_id: ThreadId,
    pub(super) process_id: u32,
    pub(super) os_thread_id: i64,
    pub(super) page_size_bytes: usize,
    pub(super) mapped_start: usize,
    pub(super) mapped_end: usize,
    pub(super) usable_start: usize,
    pub(super) usable_end: usize,
    pub(super) guard_start: usize,
    pub(super) guard_end: usize,
    pub(super) guard_bytes: usize,
}

fn region_at(address: usize) -> Result<(usize, usize, i32)> {
    let task = unsafe { mach_task_self() };
    let mut start = u64::try_from(address)?;
    let mut size = 0_u64;
    let mut info = unsafe { std::mem::zeroed::<vm_region_basic_info_64>() };
    let mut count = vm_region_basic_info_64::count();
    let mut object_name = MACH_PORT_NULL;
    let status = unsafe {
        mach_vm_region(
            task,
            &mut start,
            &mut size,
            VM_REGION_BASIC_INFO_64,
            (&mut info as *mut vm_region_basic_info_64).cast::<i32>() as vm_region_info_t,
            &mut count,
            &mut object_name,
        )
    };
    if object_name != MACH_PORT_NULL {
        ensure!(
            unsafe { mach_port_deallocate(task, object_name) } == KERN_SUCCESS,
            "could not release Mach VM region object port"
        );
    }
    ensure!(status == KERN_SUCCESS, "mach_vm_region failed: {status}");
    let start = usize::try_from(start)?;
    let size = usize::try_from(size)?;
    let end = start.checked_add(size).context("Mach VM region overflow")?;
    ensure!(
        start <= address && address < end && count == vm_region_basic_info_64::count(),
        "Mach VM region does not cover requested stack page"
    );
    Ok((start, end, info.protection))
}

pub(super) fn current_stack_range() -> Result<MacStackRange> {
    let page_size = unsafe { sysconf(_SC_PAGESIZE) };
    ensure!(page_size > 0, "macOS page size is unavailable");
    let page_size = usize::try_from(page_size)?;
    ensure!(page_size.is_power_of_two(), "macOS page size is invalid");
    let pthread = unsafe { pthread_self() };
    let high = unsafe { pthread_get_stackaddr_np(pthread) } as usize;
    let stack_size = unsafe { pthread_get_stacksize_np(pthread) };
    let stack_pointer: usize;
    unsafe {
        #[cfg(target_arch = "aarch64")]
        asm!("mov {stack_pointer}, sp", stack_pointer = out(reg) stack_pointer, options(nomem, nostack, preserves_flags));
        #[cfg(target_arch = "x86_64")]
        asm!("mov {stack_pointer}, rsp", stack_pointer = out(reg) stack_pointer, options(nomem, nostack, preserves_flags));
    }
    let mut os_thread_id = 0_u64;
    let thread_status = unsafe { pthread_threadid_np(pthread, &mut os_thread_id) };
    ensure!(
        thread_status == 0 && os_thread_id > 0,
        "pthread thread ID is unavailable: status={thread_status}, pthread={pthread:p}, high={high:#x}, size={stack_size:#x}, page_size={page_size:#x}, sp={stack_pointer:#x}, os_thread_id={os_thread_id}"
    );
    let os_thread_id = i64::try_from(os_thread_id).context("pthread thread ID overflow")?;
    ensure!(
        high > 0 && stack_size >= page_size,
        "pthread stack range is invalid: low=unknown, high={high:#x}, size={stack_size:#x}, page_size={page_size:#x}, sp={stack_pointer:#x}, os_thread_id={os_thread_id}"
    );
    let low = high
        .checked_sub(stack_size)
        .with_context(|| format!("pthread stack underflow: high={high:#x}, size={stack_size:#x}, page_size={page_size:#x}, sp={stack_pointer:#x}, os_thread_id={os_thread_id}"))?;
    // Darwin can place pthread_t inside the top stack page, so high need not be page aligned.
    ensure!(
        low % page_size == 0,
        "pthread stack lower bound is not page aligned: low={low:#x}, high={high:#x}, size={stack_size:#x}, page_size={page_size:#x}, sp={stack_pointer:#x}, os_thread_id={os_thread_id}"
    );
    ensure!(
        low <= stack_pointer && stack_pointer < high,
        "current stack pointer is outside pthread stack range: low={low:#x}, high={high:#x}, size={stack_size:#x}, page_size={page_size:#x}, sp={stack_pointer:#x}, os_thread_id={os_thread_id}"
    );
    let (writable_start, writable_end, protection) = region_at(low).with_context(|| {
        format!("pthread stack Mach region lookup failed: low={low:#x}, high={high:#x}, size={stack_size:#x}, page_size={page_size:#x}, sp={stack_pointer:#x}, os_thread_id={os_thread_id}")
    })?;
    ensure!(
        writable_start <= low
            && writable_end >= high
            && protection & (VM_PROT_READ | VM_PROT_WRITE) == VM_PROT_READ | VM_PROT_WRITE,
        "pthread stack is not one contiguous writable Mach VM region: low={low:#x}, high={high:#x}, size={stack_size:#x}, page_size={page_size:#x}, sp={stack_pointer:#x}, os_thread_id={os_thread_id}, region_start={writable_start:#x}, region_end={writable_end:#x}, protection={protection:#x}"
    );
    let guard_start = low
        .checked_sub(page_size)
        .with_context(|| format!("pthread guard underflow: low={low:#x}, high={high:#x}, page_size={page_size:#x}, sp={stack_pointer:#x}, os_thread_id={os_thread_id}"))?;
    let (guard_region_start, guard_region_end, guard_protection) = region_at(guard_start)
        .with_context(|| format!("pthread guard Mach region lookup failed: guard_start={guard_start:#x}, low={low:#x}, high={high:#x}, page_size={page_size:#x}, sp={stack_pointer:#x}, os_thread_id={os_thread_id}"))?;
    ensure!(
        guard_region_start <= guard_start
            && guard_region_end >= low
            && guard_protection == VM_PROT_NONE,
        "pthread guard page is not a protected Mach VM region: guard_start={guard_start:#x}, low={low:#x}, high={high:#x}, page_size={page_size:#x}, sp={stack_pointer:#x}, os_thread_id={os_thread_id}, region_start={guard_region_start:#x}, region_end={guard_region_end:#x}, protection={guard_protection:#x}"
    );
    Ok(MacStackRange {
        thread_id: thread::current().id(),
        process_id: process::id(),
        os_thread_id,
        page_size_bytes: page_size,
        mapped_start: low,
        mapped_end: high,
        usable_start: low,
        usable_end: high,
        guard_start,
        guard_end: low,
        guard_bytes: page_size,
    })
}

pub(super) fn thread_observation(
    stack: &MacStackRange,
    category: &str,
    requested_bytes: Option<usize>,
) -> JsonValue {
    json!({
        "thread_category": category,
        "thread_id": format!("{:?}", stack.thread_id),
        "process_id": stack.process_id,
        "os_thread_id": stack.os_thread_id,
        "identity_api": "macos_pthread_threadid_np",
        "page_size_bytes": stack.page_size_bytes,
        "requested_bytes": requested_bytes,
        "mapped_bytes": stack.mapped_end - stack.mapped_start,
        "guard_bytes": stack.guard_bytes,
        "guard_start": stack.guard_start,
        "guard_end": stack.guard_end,
        "guard_verification": "macos_mach_vm_region_prot_none",
        "usable_bytes": stack.usable_end - stack.usable_start,
        "mapped_start": stack.mapped_start,
        "mapped_end": stack.mapped_end,
        "usable_start": stack.usable_start,
        "usable_end": stack.usable_end,
        "measurement_api": "pthread_get_stackaddr_np,pthread_get_stacksize_np,pthread_threadid_np,mach_vm_region",
        "guard_treatment": "guard protected below pthread stack range",
        "guard_verified": true,
    })
}

pub(super) fn blocking_thread_observation() -> JsonValue {
    let stack = current_stack_range().expect("blocking decode stack capacity");
    thread_observation(&stack, "blocking_pool", None)
}

pub(super) fn measured_tokio_runtime(
    worker_stack_size: Option<usize>,
) -> Result<(TokioRuntime, [MacStackRange; 2])> {
    let (sender, receiver) = channel();
    let mut builder = Builder::new_multi_thread();
    builder.worker_threads(2).enable_all();
    if let Some(size) = worker_stack_size {
        builder.thread_stack_size(size);
    }
    let runtime = builder
        .on_thread_start(move || {
            let _ = sender.send(current_stack_range());
        })
        .build()?;
    let first = receiver
        .recv_timeout(Duration::from_secs(5))
        .context("first macOS Tokio worker did not start")??;
    let second = receiver
        .recv_timeout(Duration::from_secs(5))
        .context("second macOS Tokio worker did not start")??;
    ensure!(
        first.thread_id != second.thread_id && first.os_thread_id != second.os_thread_id,
        "macOS Tokio workers have duplicate identities"
    );
    Ok((runtime, [first, second]))
}

pub(super) fn guard_fault_control() -> Result<()> {
    let binary = env::current_exe()?;
    for mode in ["reduced", "production"] {
        let mut child = Command::new(&binary)
            .args([
                "--exact",
                "runtime::call::tests::native_stack_resource::macos_worker_guard_fault_child",
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
                    "{mode} macOS guard child timed out: stdout={}, stderr={}",
                    String::from_utf8_lossy(&output.stdout),
                    String::from_utf8_lossy(&output.stderr)
                );
            }
            thread::sleep(Duration::from_millis(10));
        }
        let output = child.wait_with_output()?;
        let signal = output.status.signal();
        let stdout = String::from_utf8_lossy(&output.stdout);
        let stderr = String::from_utf8_lossy(&output.stderr);
        ensure!(
            signal == Some(SIGABRT),
            "{mode} macOS guard child did not abort after the guard fault: status={:?}, signal={signal:?}, stdout={stdout}, stderr={stderr}",
            output.status
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
            "{mode} macOS child lacks one guard target"
        );
        let target: JsonValue = from_str(targets[0])?;
        let start = target["guard_start"]
            .as_u64()
            .context("missing guard start")?;
        let end = target["guard_end"].as_u64().context("missing guard end")?;
        let address = target["address"]
            .as_u64()
            .context("missing guard address")?;
        let page = target["page_size_bytes"]
            .as_u64()
            .context("missing page size")?;
        ensure!(
            target["mode"].as_str() == Some(mode)
                && target["process_id"].as_u64() == Some(u64::from(process_id))
                && target["os_thread_id"].as_i64().is_some_and(|id| id > 0)
                && target["guard_verification"].as_str() == Some("macos_mach_vm_region_prot_none")
                && page.is_power_of_two()
                && end.checked_sub(start).is_some_and(|bytes| bytes >= page)
                && start <= address
                && address < end,
            "{mode} macOS guard target is invalid: {target}"
        );
        let os_thread_id = target["os_thread_id"]
            .as_i64()
            .context("missing OS thread ID")?;
        ensure!(
            stderr.contains(&format!("({os_thread_id}) has overflowed its stack"))
                && stderr.contains("fatal runtime error: stack overflow, aborting"),
            "{mode} macOS guard child lacks Rust overflow diagnostics for worker {os_thread_id}: stderr={stderr}"
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
                .context("macOS guard binary has no embedded source revision")?,
            "modes": ["reduced", "production"],
            "complete": true,
        })
    );
    Ok(())
}

pub(super) fn guard_fault_child() -> Result<()> {
    ensure!(
        env::var("KONTOR_RESOURCE_GUARD_FAULT_CHILD").as_deref() == Ok("1"),
        "macOS guard child requires isolated parent"
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
            let stack = current_stack_range()?;
            let address = stack.guard_start + stack.page_size_bytes / 2;
            ensure!(
                address < stack.guard_end,
                "guard address lies outside protected page"
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
                    "guard_verification": "macos_mach_vm_region_prot_none",
                    "address": address,
                })
            );
            std::io::stdout().flush()?;
            unsafe {
                #[cfg(target_arch = "aarch64")]
                asm!("strb wzr, [{address}]", address = in(reg) address, options(nostack));
                #[cfg(target_arch = "x86_64")]
                asm!("mov byte ptr [{address}], 0", address = in(reg) address, options(nostack));
            }
            Ok::<(), anyhow::Error>(())
        })
        .await
    })??;
    bail!("macOS worker guard access did not fault")
}
