use anyhow::Result;

#[cfg(target_os = "linux")]
use std::fs::{File, read_to_string};
#[cfg(target_os = "linux")]
use std::mem::MaybeUninit;
#[cfg(target_os = "linux")]
use std::os::unix::fs::FileExt;
#[cfg(target_os = "linux")]
use std::ptr::null_mut;
#[cfg(target_os = "linux")]
use std::sync::mpsc::channel;
#[cfg(target_os = "linux")]
use std::thread::ThreadId;
#[cfg(target_os = "linux")]
use std::time::Duration;

#[cfg(target_os = "linux")]
use anyhow::{Context, ensure};
#[cfg(target_os = "linux")]
use libc::{
    _SC_PAGESIZE, EIO, c_void, gettid, pthread_attr_destroy, pthread_attr_getguardsize,
    pthread_attr_getstack, pthread_attr_t, pthread_getattr_np, pthread_self, sysconf,
};
#[cfg(target_os = "linux")]
use tokio::runtime::{Builder, Runtime as TokioRuntime};

use crate::runtime::Runtime;

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
            guard_size % page_size == 0,
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
            "lightweight guard verified below pthread stack range",
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
    start <= end && end - start >= size && start % page_size == 0 && end % page_size == 0
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
