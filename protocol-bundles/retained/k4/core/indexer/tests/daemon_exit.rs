use std::fs::{File, read_to_string, write};
use std::net::TcpListener;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// The process-level complement to the cluster suite's SIGTERM→exit-0
/// assertion: a node whose API cannot START must exit non-zero, promptly, with
/// the real cause on stderr. Before the supervisor rework a bind failure
/// logged a misleading "HTTP server panicked on join", never cancelled, and
/// left the node running headless — no API, no probes, exit 0 whenever it was
/// eventually stopped.
///
/// Needs no bitcoind: the API binds before anything talks to Bitcoin, so the
/// pre-bound port makes the failure deterministic and immediate.
#[test]
fn a_fatal_startup_error_exits_nonzero_with_the_cause() {
    // Hold the port for the duration so the node's bind loses the race. The
    // SAME wildcard address the node binds, not 127.0.0.1: on macOS,
    // SO_REUSEADDR lets a wildcard bind coexist with a specific-address one,
    // so a loopback pre-bind does not conflict there and the node starts
    // happily. Two identical wildcard binds conflict on every platform.
    let taken = TcpListener::bind("0.0.0.0:0").expect("pre-bind a port");
    let port = taken.local_addr().expect("local addr").port();
    let data_dir = tempfile::tempdir().expect("tempdir");
    // Genesis parsing can race the API failure; keep this valid so only the
    // port conflict can cause startup to fail.
    let genesis_path = data_dir.path().join("genesis.json");
    write(&genesis_path, r#"{"sigma_min":"1","validators":[]}"#).expect("write genesis");
    // Files preserve both streams without letting a full pipe stall shutdown.
    let stdout_path = data_dir.path().join("stdout.log");
    let stderr_path = data_dir.path().join("stderr.log");

    let mut child = Command::new(env!("CARGO_BIN_EXE_kontor"))
        .args([
            "run",
            "--api-port",
            &port.to_string(),
            "--data-dir",
            data_dir.path().to_str().expect("utf-8 tempdir"),
            "--network",
            "regtest",
            "--starting-block-height",
            "102",
            "--bitcoin-rpc-url",
            "http://127.0.0.1:1",
            "--bitcoin-rpc-user",
            "x",
            "--bitcoin-rpc-password",
            "x",
            "--zmq-address",
            "tcp://127.0.0.1:1",
            "--genesis-file",
            genesis_path.to_str().expect("utf-8 tempdir"),
        ])
        .stdout(Stdio::from(
            File::create(&stdout_path).expect("create stdout log"),
        ))
        .stderr(Stdio::from(
            File::create(&stderr_path).expect("create stderr log"),
        ))
        .spawn()
        .expect("spawn kontor");

    // Bounded wait, well under the daemon's 25s shutdown budget plus margin:
    // the bind failure fires during startup, so a slow exit here IS a failure.
    let deadline = Instant::now() + Duration::from_secs(60);
    let timed_out = loop {
        if child.try_wait().expect("try_wait").is_some() {
            break false;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            break true;
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    let status = child.wait().expect("wait for kontor");
    let stdout = read_to_string(stdout_path).expect("read stdout");
    let stderr = read_to_string(stderr_path).expect("read stderr");
    let diagnostics = format!("status: {status}\nstdout:\n{stdout}\nstderr:\n{stderr}");

    assert!(!timed_out, "node did not exit within 60s: {diagnostics}");
    assert!(
        !status.success(),
        "a node that could not start reported success: {diagnostics}"
    );
    assert!(
        stderr.contains("HTTP server failed"),
        "the real cause must reach stderr: {diagnostics}"
    );
    drop(taken);
}
