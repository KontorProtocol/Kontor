use std::io::Read;
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
    // Hold the port for the duration so the node's bind loses the race.
    let taken = TcpListener::bind("127.0.0.1:0").expect("pre-bind a port");
    let port = taken.local_addr().expect("local addr").port();
    let data_dir = tempfile::tempdir().expect("tempdir");
    // Clap requires it; the bind failure fires before it is ever read, so an
    // empty validator set is enough.
    let genesis_path = data_dir.path().join("genesis.json");
    std::fs::write(&genesis_path, r#"{"validators":[]}"#).expect("write genesis");

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
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn kontor");

    // Bounded wait, well under the daemon's 25s shutdown budget plus margin:
    // the bind failure fires during startup, so a slow exit here IS a failure.
    let deadline = Instant::now() + Duration::from_secs(60);
    let status = loop {
        if let Some(status) = child.try_wait().expect("try_wait") {
            break status;
        }
        if Instant::now() > deadline {
            let _ = child.kill();
            panic!("node did not exit within 60s of a fatal startup error");
        }
        std::thread::sleep(Duration::from_millis(100));
    };

    let mut stderr = String::new();
    child
        .stderr
        .take()
        .expect("piped stderr")
        .read_to_string(&mut stderr)
        .expect("read stderr");

    assert!(
        !status.success(),
        "a node that could not start reported success (stderr: {stderr})"
    );
    assert!(
        stderr.contains("HTTP server failed"),
        "the real cause must reach stderr, got: {stderr}"
    );
    drop(taken);
}
