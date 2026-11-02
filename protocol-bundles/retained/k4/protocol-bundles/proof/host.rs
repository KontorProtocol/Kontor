use std::any::Any;
use std::fs;
#[cfg(target_os = "linux")]
use std::io;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::thread;
use std::time::{Duration, Instant};

use kontor_proof_first as first;
use kontor_proof_second as second;

type Owner = Box<dyn Any + Send>;
type Callback = Box<dyn Fn(Vec<u8>) -> Result<Vec<u8>, String> + Send + Sync>;
type Start = fn(String, PathBuf, u64, Callback) -> Result<Owner, String>;
type Stop = fn(&mut (dyn Any + Send), Duration) -> Result<bool, String>;
type Decide = fn(&mut (dyn Any + Send)) -> Result<u64, String>;

static INTERRUPTS: AtomicUsize = AtomicUsize::new(0);
static TERMINATIONS: AtomicUsize = AtomicUsize::new(0);

unsafe extern "C" {
    fn signal(number: i32, handler: extern "C" fn(i32)) -> usize;
    fn kill(pid: i32, number: i32) -> i32;
}

extern "C" fn handle_signal(number: i32) {
    match number {
        2 => {
            INTERRUPTS.fetch_add(1, Ordering::Relaxed);
        }
        15 => {
            TERMINATIONS.fetch_add(1, Ordering::Relaxed);
        }
        _ => {}
    }
}

fn host_events() {
    for (number, counter) in [(2, &INTERRUPTS), (15, &TERMINATIONS)] {
        let before = counter.load(Ordering::Relaxed);
        assert_eq!(
            unsafe { kill(process::id().try_into().unwrap(), number) },
            0
        );
        let deadline = Instant::now() + Duration::from_secs(5);
        while counter.load(Ordering::Relaxed) == before {
            assert!(Instant::now() < deadline, "node control signal lost");
            thread::sleep(Duration::from_millis(1));
        }
        assert_eq!(counter.load(Ordering::Relaxed), before + 1);
    }
    let status = Command::new("/bin/sh")
        .args(["-c", "exit 23"])
        .status()
        .unwrap();
    assert_eq!(status.code(), Some(23), "node-owned child status was lost");
}

#[cfg(target_os = "linux")]
fn descriptors() -> usize {
    fs::read_dir("/proc/self/fd").unwrap().count()
}

#[cfg(target_os = "macos")]
fn descriptors() -> usize {
    let output = Command::new("lsof")
        .args(["-nP", "-a", "-p", &process::id().to_string(), "-Ff"])
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .filter(|line| {
            line.starts_with('f') && line.as_bytes().get(1).is_some_and(u8::is_ascii_digit)
        })
        .count()
}

#[cfg(target_os = "linux")]
fn task_snapshot() -> Vec<(PathBuf, io::Result<String>)> {
    fs::read_dir("/proc/self/task")
        .unwrap()
        .map(|entry| {
            let path = entry.unwrap().path();
            let stat = fs::read_to_string(path.join("stat"));
            (path, stat)
        })
        .collect()
}

#[cfg(target_os = "linux")]
fn count_after_exits(
    tasks: Vec<(PathBuf, io::Result<String>)>,
    mut read_stat: impl FnMut(&Path) -> io::Result<String>,
) -> usize {
    let mut live = 0;
    let mut exiting = Vec::new();
    for (path, stat) in &tasks {
        match stat {
            Ok(stat) => {
                // comm may contain spaces and ')'. Field 9 is flags;
                // field 3 starts after the last closing parenthesis.
                let fields: Vec<_> = stat
                    .rsplit_once(')')
                    .unwrap()
                    .1
                    .split_whitespace()
                    .collect();
                let flags: u64 = fields[6].parse().unwrap();
                if flags & 0x4 != 0 {
                    exiting.push(path);
                } else {
                    live += 1;
                }
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => panic!("reading task state: {error}"),
        }
    }
    if !exiting.is_empty() {
        eprintln!("exiting task snapshot: {tasks:?}");
    }
    let started = Instant::now();
    let mut polls = 0;
    // Linux clears the join futex before clearing mm or removing the /proc task.
    // PF_EXITING is irreversible, even while vsize still describes the shared mm.
    // Preserve every initial live observation while waiting only for identified
    // exiting entries, so another live worker cannot disappear into this wait.
    while !exiting.is_empty() {
        exiting.retain(|path| match read_stat(path) {
            Ok(_) => true,
            Err(error) if error.kind() == io::ErrorKind::NotFound => false,
            Err(error) => panic!("reading exiting task state: {error}"),
        });
        polls += 1;
        assert!(
            exiting.is_empty() || started.elapsed() < Duration::from_secs(1),
            "joined tasks remained in /proc: {exiting:?}; snapshot: {:?}",
            task_snapshot()
        );
        if !exiting.is_empty() {
            thread::yield_now();
        }
    }
    if polls > 0 {
        eprintln!(
            "joined task visibility: {polls} re-polls in {:?}",
            started.elapsed()
        );
    }
    live
}

#[cfg(target_os = "linux")]
fn workers() -> usize {
    count_after_exits(task_snapshot(), |path| {
        fs::read_to_string(path.join("stat"))
    })
}

#[cfg(target_os = "macos")]
fn workers() -> usize {
    let output = Command::new("ps")
        .args(["-M", "-p", &process::id().to_string()])
        .output()
        .unwrap();
    assert!(output.status.success());
    String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .skip(1)
        .count()
}

fn stop_and_drop(mut owner: Owner, stop: Stop) {
    // The opaque owner can move between host control threads, and its Drop must
    // remain in the graph that created it even after its explicit join completed.
    thread::spawn(move || {
        assert!(stop(owner.as_mut(), Duration::from_secs(10)).unwrap());
        drop(owner);
    })
    .join()
    .unwrap();
}

fn resources(stage: &str) -> (usize, usize) {
    let snapshot = (workers(), descriptors());
    println!(
        "resources {stage}: workers={}, descriptors={}",
        snapshot.0, snapshot.1
    );
    snapshot
}

fn warm_crypto() {
    let cold = resources("cold");
    let limit = thread::available_parallelism().unwrap().get();
    let left = first::exercise_crypto().unwrap();
    let first = resources("first crypto");
    assert_eq!(first.1, cold.1, "crypto created persistent descriptors");
    assert!(
        (1..=limit).contains(&(first.0 - cold.0)),
        "unexpected first blst pool size"
    );
    assert_eq!(first::exercise_crypto().unwrap(), left);
    assert_eq!(resources("first crypto repeated"), first);
    assert_eq!(second::exercise_crypto().unwrap(), left);
    let second = resources("second crypto");
    assert_eq!(second.1, first.1, "crypto created persistent descriptors");
    assert_eq!(
        second.0 - first.0,
        first.0 - cold.0,
        "blst graphs should have separate equal-sized pools"
    );
    assert_eq!(second::exercise_crypto().unwrap(), left);
    assert_eq!(resources("second crypto repeated"), second);
}

fn callback(calls: Arc<AtomicUsize>) -> Callback {
    Box::new(move |input| {
        assert_eq!(input.len(), 8);
        calls.fetch_add(1, Ordering::Relaxed);
        Ok(42_u64.to_le_bytes().to_vec())
    })
}

fn warm_engine(
    root: &Path,
    name: &str,
    address: &str,
    calls: &Arc<AtomicUsize>,
    start: Start,
    decide: Decide,
    stop: Stop,
) {
    let before = resources(&format!("before {name} engine"));
    let mut owner = start(
        address.to_owned(),
        root.join(format!("{name}-warm.wal")),
        1,
        callback(calls.clone()),
    )
    .unwrap();
    assert_eq!(decide(owner.as_mut()).unwrap(), 1);
    stop_and_drop(owner, stop);
    let after = resources(&format!("after {name} engine stopped"));
    assert_eq!(after.1, before.1 + 2, "expected one Tokio Unix pair");
    assert_eq!(after.0, before.0 + 1, "expected one futures-timer helper");
}

fn cycle(root: &Path, index: u64, calls: &Arc<AtomicUsize>, addresses: &[String; 2]) {
    let start: [Start; 2] = [first::start, second::start];
    let first_host = first::callback(callback(calls.clone()));
    let second_host = second::callback(callback(calls.clone()));
    let mut left = start[0](
        addresses[0].clone(),
        root.join(format!("first-{index}.wal")),
        index + 1,
        first_host,
    )
    .unwrap();
    let mut right = start[1](
        addresses[1].clone(),
        root.join(format!("second-{index}.wal")),
        index + 1,
        second_host,
    )
    .unwrap();
    assert!(
        second::stop(left.as_mut(), Duration::ZERO).is_err(),
        "cross-graph Any identity unexpectedly matched"
    );
    assert!(
        first::stop(right.as_mut(), Duration::ZERO).is_err(),
        "cross-graph Any identity unexpectedly matched"
    );
    host_events();
    assert_eq!(first::decide(left.as_mut()).unwrap(), index + 1);
    assert_eq!(second::decide(right.as_mut()).unwrap(), index + 1);
    stop_and_drop(left, first::stop);
    stop_and_drop(right, second::stop);
}

fn main() {
    let root = PathBuf::from(std::env::args_os().nth(1).expect("proof WAL directory"));
    fs::create_dir(&root).unwrap();
    assert_ne!(unsafe { signal(2, handle_signal) }, usize::MAX);
    assert_ne!(unsafe { signal(15, handle_signal) }, usize::MAX);
    warm_crypto();
    assert_eq!(first::exercise_vm().unwrap().0, 1026);
    let first_vm = resources("first VM");
    assert_eq!(first::exercise_vm().unwrap().0, 1026);
    assert_eq!(resources("first VM repeated"), first_vm);
    assert_eq!(second::exercise_vm().unwrap().0, 1028);
    let second_vm = resources("second VM");
    assert_eq!(second::exercise_vm().unwrap().0, 1028);
    assert_eq!(resources("second VM repeated"), second_vm);
    assert_eq!(first::shape().unwrap(), ["a", "z"]);
    assert_eq!(second::shape().unwrap(), ["z", "a"]);
    for callback in [first::callback, second::callback] {
        let failing = callback(Box::new(|_| panic!("host callback failure control")));
        assert_eq!(failing(vec![0; 8]).unwrap_err(), "bundle call panicked");
    }
    let reservations = [
        TcpListener::bind("127.0.0.1:0").unwrap(),
        TcpListener::bind("127.0.0.1:0").unwrap(),
    ];
    let addresses = reservations.each_ref().map(|listener| {
        format!(
            "/ip4/127.0.0.1/tcp/{}",
            listener.local_addr().unwrap().port()
        )
    });
    drop(reservations);
    let cold = descriptors();
    let calls = Arc::new(AtomicUsize::new(0));
    warm_engine(
        &root,
        "first",
        &addresses[0],
        &calls,
        first::start,
        first::decide,
        first::stop,
    );
    warm_engine(
        &root,
        "second",
        &addresses[1],
        &calls,
        second::start,
        second::decide,
        second::stop,
    );
    cycle(&root, 0, &calls, &addresses);
    let warm = descriptors();
    let warm_workers = workers();
    resources("both engines stopped");
    assert_eq!(warm, cold + 4, "expected one Tokio Unix pair per graph");
    for index in 1..20 {
        cycle(&root, index, &calls, &addresses);
        assert_eq!(descriptors(), warm, "engine replacement leaked descriptors");
        assert_eq!(workers(), warm_workers, "engine replacement leaked workers");
    }
    assert_eq!(calls.load(Ordering::Relaxed), 42);
    thread::scope(|scope| {
        scope.spawn(|| {
            for _ in 0..20 {
                assert_eq!(first::exercise().unwrap().0, 1026);
            }
        });
        scope.spawn(|| {
            for _ in 0..20 {
                assert_eq!(second::exercise().unwrap().0, 1028);
            }
        });
    });
    assert_eq!(
        resources("concurrent VM and crypto repeated"),
        (warm_workers, warm)
    );
    fs::remove_dir_all(root).unwrap();
    println!(
        "two real VM/crypto/consensus graphs, 42 decisions, callbacks and panic containment, isolated Any owners, host signals/child statuses, and 20 replacement cycles passed; cold descriptors={cold}, warm={warm}"
    );
}
