use std::process;
use std::thread;

#[cfg(target_os = "linux")]
use anyhow::{Context, bail};
use anyhow::{Result, ensure};
use serde_json::{Value as JsonValue, json};

#[cfg(target_os = "linux")]
use libc::{_SC_PAGESIZE, _SC_PHYS_PAGES, sysconf};
#[cfg(target_os = "linux")]
use std::fs::read_to_string;
#[cfg(target_os = "linux")]
use std::path::{Component, Path};

#[cfg(target_os = "macos")]
use libc::sysctlbyname;
#[cfg(target_os = "macos")]
use mach2::kern_return::KERN_SUCCESS;
#[cfg(target_os = "macos")]
use mach2::task::task_info;
#[cfg(target_os = "macos")]
use mach2::task_info::{TASK_VM_INFO, task_info_t, task_vm_info};
#[cfg(target_os = "macos")]
use mach2::traps::mach_task_self;
#[cfg(target_os = "macos")]
use std::ffi::CString;
#[cfg(target_os = "macos")]
use std::mem::{offset_of, size_of};
#[cfg(target_os = "macos")]
use std::ptr::null_mut;

fn cpu_count() -> Result<usize> {
    Ok(thread::available_parallelism()?.get())
}

#[cfg(target_os = "linux")]
fn kib_field(text: &str, name: &str) -> Result<u64> {
    let values = text
        .lines()
        .filter_map(|line| line.strip_prefix(name))
        .collect::<Vec<_>>();
    ensure!(
        values.len() == 1,
        "Linux memory field {name} is missing or duplicated"
    );
    let parts = values[0].split_whitespace().collect::<Vec<_>>();
    ensure!(
        parts.len() == 2 && parts[1] == "kB",
        "Linux memory field {name} changed units"
    );
    parts[0]
        .parse::<u64>()?
        .checked_mul(1024)
        .context("Linux memory field overflow")
}

#[cfg(target_os = "linux")]
fn cgroup_memory() -> Result<(u64, String, String, String)> {
    let membership = read_to_string("/proc/self/cgroup")?;
    for line in membership.lines() {
        let fields = line.splitn(3, ':').collect::<Vec<_>>();
        ensure!(fields.len() == 3, "Linux cgroup membership is malformed");
        let v2 = fields[0] == "0" && fields[1].is_empty();
        let v1_memory = fields[1].split(',').any(|name| name == "memory");
        if !v2 && !v1_memory {
            continue;
        }
        let relative = Path::new(fields[2].trim_start_matches('/'));
        ensure!(
            !relative
                .components()
                .any(|part| matches!(part, Component::ParentDir)),
            "Linux cgroup membership escapes its mount"
        );
        let directory = if v2 {
            Path::new("/sys/fs/cgroup").join(relative)
        } else {
            Path::new("/sys/fs/cgroup/memory").join(relative)
        };
        let current = directory.join(if v2 {
            "memory.current"
        } else {
            "memory.usage_in_bytes"
        });
        let limit = directory.join(if v2 {
            "memory.max"
        } else {
            "memory.limit_in_bytes"
        });
        if let Ok(value) = read_to_string(&current) {
            let bytes = value.trim().parse::<u64>()?;
            let limit_value = read_to_string(&limit)?.trim().to_owned();
            ensure!(bytes > 0, "Linux cgroup memory charge is zero");
            return Ok((
                bytes,
                current.display().to_string(),
                limit.display().to_string(),
                limit_value,
            ));
        }
    }
    bail!("Linux cgroup memory charge is unavailable")
}

#[cfg(target_os = "linux")]
pub(crate) fn snapshot() -> Result<JsonValue> {
    let status = read_to_string("/proc/self/status")?;
    let rollup = read_to_string("/proc/self/smaps_rollup")?;
    let meminfo = read_to_string("/proc/meminfo")?;
    let page = unsafe { sysconf(_SC_PAGESIZE) };
    let pages = unsafe { sysconf(_SC_PHYS_PAGES) };
    ensure!(
        page > 0 && pages > 0,
        "Linux physical memory page count is invalid"
    );
    let physical = u64::try_from(page)?
        .checked_mul(u64::try_from(pages)?)
        .context("Linux physical memory overflow")?;
    ensure!(
        physical == kib_field(&meminfo, "MemTotal:")?,
        "Linux physical memory sources disagree"
    );
    let private = kib_field(&rollup, "Private_Clean:")?
        .checked_add(kib_field(&rollup, "Private_Dirty:")?)
        .context("Linux private memory overflow")?;
    let (charged, charge_source, limit_source, memory_limit) = cgroup_memory()?;
    Ok(json!({
        "os": "linux", "pid": process::id(), "cpu_count": cpu_count()?,
        "physical_memory_bytes": physical,
        "enforcement": {"memory_field": memory_limit,
                        "memory_source": limit_source},
        "mapped_reservation": {"bytes": kib_field(&status, "VmSize:")?,
                               "source": "/proc/self/status:VmSize"},
        "resident": {"bytes": kib_field(&status, "VmRSS:")?,
                     "source": "/proc/self/status:VmRSS"},
        "private": {"bytes": private,
                    "source": "/proc/self/smaps_rollup:Private_Clean+Private_Dirty"},
        "accounted_scope": {"bytes": charged, "source": charge_source,
                            "scope": "cgroup_total_including_other_processes_and_cache"},
    }))
}

#[cfg(target_os = "macos")]
fn physical_memory() -> Result<u64> {
    let name = CString::new("hw.memsize")?;
    let mut bytes = 0_u64;
    let mut length = size_of::<u64>();
    let status = unsafe {
        sysctlbyname(
            name.as_ptr(),
            (&mut bytes as *mut u64).cast(),
            &mut length,
            null_mut(),
            0,
        )
    };
    ensure!(
        status == 0 && length == size_of::<u64>() && bytes > 0,
        "macOS physical memory sysctl failed"
    );
    Ok(bytes)
}

#[cfg(target_os = "macos")]
pub(crate) fn snapshot() -> Result<JsonValue> {
    let mut info = task_vm_info::default();
    let mut count = u32::try_from(size_of::<task_vm_info>() / size_of::<i32>())?;
    let status = unsafe {
        task_info(
            mach_task_self(),
            TASK_VM_INFO,
            (&mut info as *mut task_vm_info).cast::<i32>() as task_info_t,
            &mut count,
        )
    };
    ensure!(
        status == KERN_SUCCESS
            && usize::try_from(count)? * size_of::<i32>()
                >= offset_of!(task_vm_info, phys_footprint) + size_of::<u64>(),
        "macOS task VM info lacks physical footprint"
    );
    let mapped = info.virtual_size;
    let resident = info.resident_size;
    let private = info.internal;
    let footprint = info.phys_footprint;
    Ok(json!({
        "os": "macos", "pid": process::id(), "cpu_count": cpu_count()?,
        "physical_memory_bytes": physical_memory()?,
        "enforcement": {"memory_field": "none", "memory_source": "none"},
        "mapped_reservation": {"bytes": mapped,
                               "source": "task_vm_info.virtual_size"},
        "resident": {"bytes": resident,
                     "source": "task_vm_info.resident_size"},
        "private": {"bytes": private, "source": "task_vm_info.internal"},
        "accounted_scope": {"bytes": footprint,
                            "source": "task_vm_info.phys_footprint",
                            "scope": "process_task_phys_footprint"},
    }))
}
