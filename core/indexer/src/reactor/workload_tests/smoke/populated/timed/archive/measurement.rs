use std::collections::BTreeMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use anyhow::{Context, Result, ensure};
use serde::Serialize;
use serde_json::json;

#[derive(Serialize)]
struct Sample {
    memory_current_bytes: u64,
    swap_current_bytes: u64,
    process_rss_bytes: u64,
    memory_events: BTreeMap<String, u64>,
    memory_stat: BTreeMap<String, u64>,
    cpu_stat: BTreeMap<String, u64>,
    memory_pressure: String,
}

fn membership() -> Result<PathBuf> {
    let contents = fs::read_to_string("/proc/self/cgroup")?;
    let entries = contents
        .lines()
        .filter_map(|line| line.strip_prefix("0::"))
        .collect::<Vec<_>>();
    ensure!(
        entries.len() == 1,
        "trial measurement requires unified cgroup v2"
    );
    Ok(Path::new("/sys/fs/cgroup").join(entries[0].trim_start_matches('/')))
}

fn number(path: &Path) -> Result<u64> {
    Ok(fs::read_to_string(path)?.trim().parse()?)
}

fn counters(path: &Path) -> Result<BTreeMap<String, u64>> {
    fs::read_to_string(path)?
        .lines()
        .map(|line| {
            let mut fields = line.split_whitespace();
            let key = fields.next().context("missing counter name")?;
            let value = fields.next().context("missing counter value")?.parse()?;
            ensure!(fields.next().is_none(), "invalid cgroup counter");
            Ok((key.to_owned(), value))
        })
        .collect()
}

fn sample(directory: &Path) -> Result<Sample> {
    let status = fs::read_to_string("/proc/self/status")?;
    let rss = status
        .lines()
        .find_map(|line| line.strip_prefix("VmRSS:"))
        .context("process RSS unavailable")?;
    let fields = rss.split_whitespace().collect::<Vec<_>>();
    ensure!(
        fields.len() == 2 && fields[1] == "kB",
        "unexpected RSS units"
    );
    Ok(Sample {
        memory_current_bytes: number(&directory.join("memory.current"))?,
        swap_current_bytes: number(&directory.join("memory.swap.current"))?,
        process_rss_bytes: fields[0]
            .parse::<u64>()?
            .checked_mul(1024)
            .context("RSS overflow")?,
        memory_events: counters(&directory.join("memory.events"))?,
        memory_stat: counters(&directory.join("memory.stat"))?,
        cpu_stat: counters(&directory.join("cpu.stat"))?,
        memory_pressure: fs::read_to_string(directory.join("memory.pressure"))?,
    })
}

fn limits(directory: &Path) -> Result<BTreeMap<String, String>> {
    ["cpu.max", "memory.max", "memory.swap.max"]
        .into_iter()
        .map(|name| {
            Ok((
                name.to_owned(),
                fs::read_to_string(directory.join(name))?.trim().to_owned(),
            ))
        })
        .collect()
}

pub(super) struct TrialMemory {
    directory: PathBuf,
    peak: File,
    before: Sample,
    limits: BTreeMap<String, String>,
    started: Instant,
}

impl TrialMemory {
    pub(super) fn start() -> Result<Option<Self>> {
        let Some(enabled) = std::env::var_os("KONTOR_WORKLOAD_TRIAL_MEMORY") else {
            return Ok(None);
        };
        ensure!(enabled == "1", "invalid trial memory setting");
        let directory = membership()?;
        let limits = limits(&directory)?;
        let before = sample(&directory)?;
        let mut peak = OpenOptions::new()
            .read(true)
            .write(true)
            .open(directory.join("memory.peak"))
            .context("trial peak accounting requires writable memory.peak")?;
        // Linux resets the peak only for this open file description. Reopening
        // at the end would silently report the service's lifetime peak instead.
        peak.write_all(b"reset")?;
        peak.seek(SeekFrom::Start(0))?;
        let mut reset = String::new();
        peak.read_to_string(&mut reset)?;
        let _: u64 = reset.trim().parse().context("invalid reset peak")?;
        Ok(Some(Self {
            directory,
            peak,
            before,
            limits,
            started: Instant::now(),
        }))
    }

    pub(super) fn finish(mut self, restore: &str, paced_api: bool) -> Result<()> {
        ensure!(membership()? == self.directory, "trial changed cgroup");
        ensure!(
            limits(&self.directory)? == self.limits,
            "trial resource limits changed"
        );
        let after = sample(&self.directory)?;
        self.peak.seek(SeekFrom::Start(0))?;
        let mut peak = String::new();
        self.peak.read_to_string(&mut peak)?;
        let peak: u64 = peak.trim().parse()?;
        eprintln!(
            "workload_trial_memory={}",
            json!({
                "schema_version": 1, "restore": restore, "paced_api": paced_api,
                "pid": std::process::id(), "cgroup": self.directory,
                "limits": self.limits, "elapsed_ns": self.started.elapsed().as_nanos(),
                "before": self.before, "after": after, "peak_bytes": peak,
                "scope": "replay with competing views, in-process scheduling and semantic oracles; setup and external Bitcoin excluded",
                "peak_reset": "same_open_file_description"
            })
        );
        Ok(())
    }
}
