use super::*;
use clap::Parser;
use tempfile::tempdir;

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    args: ProtocolBundlesArgs,
}
fn arguments(args: &[&str]) -> ProtocolBundlesArgs {
    Cli::try_parse_from(std::iter::once("bundle").chain(args.iter().copied()))
        .unwrap()
        .args
}
#[test]
fn modes_preserve_defaults_and_reject_invalid_combinations() -> Result<()> {
    assert_eq!(mode(&arguments(&[]))?, (Mode::Proof, None));
    assert_eq!(
        mode(&arguments(&["--build-consensus"]))?,
        (Mode::Consensus, None)
    );
    assert_eq!(
        mode(&arguments(&["--build-node"]))?,
        (Mode::Node, Some("production-node".into()))
    );
    assert_eq!(
        mode(&arguments(&["--build-executors"]))?,
        (Mode::Executors, Some("production-node".into()))
    );
    for set in ["legacy-qualification", "production-node"] {
        assert_eq!(
            mode(&arguments(&["--build-node", "--link-set", set]))?,
            (Mode::Node, Some(set.into()))
        );
    }
    assert_eq!(
        mode(&arguments(&["--build-node", "--node-qualification"]))?,
        (Mode::Node, Some("managed-node".into()))
    );
    assert!(mode(&arguments(&["--build-node", "--link-set", "managed-node"])).is_err());
    assert!(
        mode(&arguments(&[
            "--build-node",
            "--node-qualification",
            "--link-set",
            "production-node"
        ]))
        .is_err()
    );
    for args in [
        vec!["--build-executors", "--build-node"],
        vec!["--build-consensus", "--build-node"],
        vec!["--build-consensus", "--build-executors"],
        vec!["--node-qualification"],
        vec!["--install-node", "out"],
        vec!["--jobs", "0"],
        vec!["--jobs", "3"],
        vec!["--profile", "custom"],
        vec!["--link-set", "unknown"],
        vec!["--build-node", "--link-set", "k4-node"],
    ] {
        assert!(Cli::try_parse_from(std::iter::once("bundle").chain(args)).is_err());
    }
    assert!(mode(&arguments(&["--link-set", "managed-node"])).is_err());
    assert!(
        mode(&arguments(&[
            "--build-consensus",
            "--link-set",
            "managed-node"
        ]))
        .is_err()
    );
    let args = arguments(&[
        "--build-node",
        "--node-qualification",
        "--install-node",
        "a b",
        "--offline",
        "-j",
        "1",
    ]);
    assert!(args.offline && args.node_qualification);
    assert_eq!(args.install_node, Some(PathBuf::from("a b")));
    assert_eq!(args.jobs, 1);
    Ok(())
}
#[test]
fn environment_preserves_offline_policy_and_removes_compiler_overrides() {
    let removed = [
        "RUSTFLAGS",
        "CARGO_ENCODED_RUSTFLAGS",
        "RUSTC",
        "RUSTC_WORKSPACE_WRAPPER",
        "CARGO_BUILD_RUSTC",
        "CARGO_BUILD_RUSTC_WRAPPER",
        "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
        "CARGO_PROFILE_RELEASE_PANIC",
        "CARGO_PROFILE_DEV_OPT_LEVEL",
        "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS",
    ];
    let mut input: Environment = removed
        .iter()
        .map(|key| (key.to_string(), "override".into()))
        .collect();
    input.extend([
        ("CARGO_NET_OFFLINE".into(), "true".into()),
        ("PATH".into(), "tools".into()),
        ("RUSTUP_TOOLCHAIN".into(), "wrong".into()),
        ("RUSTC_WRAPPER".into(), "ccache".into()),
        (
            "CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER".into(),
            "clang".into(),
        ),
    ]);
    let env = sanitized_environment(input.clone(), 1, false);
    for key in removed {
        assert!(!env.contains_key(key), "{key}");
    }
    assert_eq!(env["RUSTUP_TOOLCHAIN"], TOOLCHAIN);
    assert_eq!(env["RUSTC_WRAPPER"], "");
    assert_eq!(env["CCACHE_DISABLE"], "1");
    assert_eq!(env["CARGO_BUILD_JOBS"], "1");
    assert_eq!(env["CARGO_NET_OFFLINE"], "true");
    assert_eq!(env["PATH"], "tools");
    assert_eq!(env["CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER"], "clang");
    input.insert("CARGO_NET_OFFLINE".into(), "false".into());
    assert_eq!(
        sanitized_environment(input.clone(), 2, true)["CARGO_NET_OFFLINE"],
        "true"
    );
    assert_eq!(
        sanitized_environment(input, 2, false)["CARGO_NET_OFFLINE"],
        "false"
    );
}
#[test]
fn targets_require_supported_native_execution() -> Result<()> {
    for host in [
        "x86_64-unknown-linux-gnu",
        "aarch64-unknown-linux-gnu",
        "aarch64-apple-darwin",
    ] {
        let compiler = format!("rustc 1.99.1\nhost: {host}\nrelease: 1.99.1\n");
        assert_eq!(native_target(&compiler, None)?, host);
        assert_eq!(native_target(&compiler, Some(host))?, host);
        assert!(native_target(&compiler, Some("wasm32-unknown-unknown")).is_err());
    }
    assert!(
        native_target(
            "host: x86_64-unknown-linux-gnu",
            Some("aarch64-unknown-linux-gnu")
        )
        .is_err()
    );
    assert!(native_target("host: x86_64-apple-darwin", None).is_err());
    assert!(native_target("no host", None).is_err());
    Ok(())
}
#[test]
fn output_lock_precedes_invalidation_and_covers_all_configurations() -> Result<()> {
    let temp = tempdir()?;
    let base = temp.path().join("new output");
    let proof = output_directory(&base, "target", "dev", Mode::Proof, None);
    assert_eq!(proof, base.join("target/dev"));
    let consensus = output_directory(&base, "target", "dev", Mode::Consensus, None);
    assert_eq!(consensus, proof.join("consensus"));
    let node = output_directory(&base, "target", "release", Mode::Node, Some("managed-node"));
    assert_eq!(node, base.join("target/release/executors/managed-node"));
    assert_eq!(
        node,
        output_directory(
            &base,
            "target",
            "release",
            Mode::Executors,
            Some("managed-node")
        )
    );
    let lock = begin_output(&base, &node, true)?;
    for name in [
        "node-build.json",
        "executor-build.json",
        "consensus-build.json",
        "qualification.json",
        "build-inputs.json",
    ] {
        fs::write(node.join(name), "existing")?;
    }
    assert!(begin_output(&base, &node, true).is_err());
    assert!(begin_output(&base, &consensus, true).is_err());
    assert_eq!(
        fs::read_to_string(node.join("node-build.json"))?,
        "existing"
    );
    // Other tests spawn children concurrently. A fork can briefly inherit this
    // descriptor before exec closes it, so release the lock before dropping it.
    lock.unlock()?;
    drop(lock);
    let lock = begin_output(&base, &node, true)?;
    for name in [
        "node-build.json",
        "executor-build.json",
        "consensus-build.json",
        "qualification.json",
    ] {
        assert!(!node.join(name).exists());
    }
    assert!(node.join("build-inputs.json").is_file());
    lock.unlock()?;
    drop(lock);
    fs::create_dir_all(&proof)?;
    fs::write(proof.join("qualification.json"), "stale")?;
    fs::write(proof.join("build-inputs.json"), "diagnostics")?;
    let _lock = begin_output(&base, &proof, false)?;
    assert!(!proof.join("qualification.json").exists());
    assert!(proof.join("build-inputs.json").is_file());
    Ok(())
}
