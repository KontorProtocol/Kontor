use anyhow::{Context, Result, ensure};
use libc::{CLOCK_MONOTONIC, clock_gettime, timespec};

pub(super) fn monotonic_ns() -> Result<u64> {
    let mut stamp = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };
    // Both processes use the host's CLOCK_MONOTONIC, so scheduling delay in
    // the measured service cannot move the offered-arrival epoch forward.
    // SAFETY: stamp is a valid, writable timespec for the duration of the call.
    ensure!(unsafe { clock_gettime(CLOCK_MONOTONIC, &mut stamp) } == 0);
    ensure!((0..1_000_000_000).contains(&stamp.tv_nsec));
    u64::try_from(stamp.tv_sec)?
        .checked_mul(1_000_000_000)
        .and_then(|seconds| seconds.checked_add(stamp.tv_nsec as u64))
        .context("monotonic clock overflow")
}
