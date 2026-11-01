use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

fn git_output(manifest: &Path, args: &[&str]) -> Option<String> {
    let output = Command::new("git")
        .current_dir(manifest)
        .args(args)
        .output()
        .ok()?;
    output.status.success().then_some(())?;
    Some(String::from_utf8(output.stdout).ok()?.trim().to_owned())
}

fn track_git_head() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let Some(head) = git_output(&manifest, &["rev-parse", "--git-path", "HEAD"]) else {
        return;
    };
    println!("cargo:rerun-if-changed={head}");
    if let Some(reference) = git_output(&manifest, &["symbolic-ref", "--quiet", "HEAD"]) {
        for name in [reference.as_str(), "packed-refs"] {
            if let Some(path) = git_output(&manifest, &["rev-parse", "--git-path", name]) {
                let mut path = manifest.join(path);
                if name == "packed-refs" && !path.exists() {
                    continue;
                }
                // Packed refs can become loose without changing packed-refs.
                // Watching the nearest existing parent also sees that creation.
                while !path.exists() && path.pop() {}
                println!("cargo:rerun-if-changed={}", path.display());
            }
        }
    }
}

fn build_protos() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let source = if env::var("CARGO_PKG_NAME").as_deref() == Ok("kontor-node") {
        manifest.join("../../core/indexer")
    } else {
        manifest
    };
    let protos = &[
        "proto/consensus/v1/consensus.proto",
        "proto/consensus/v1/sync.proto",
        "proto/consensus/v1/liveness.proto",
    ];

    let protos = protos.map(|proto| source.join(proto));
    for proto in &protos {
        println!("cargo:rerun-if-changed={}", proto.display());
    }

    let fds = protox::compile(&protos, [source.join("proto")]).expect("protobuf compilation");

    let mut config = prost_build::Config::new();
    config.enable_type_names();
    config.bytes(["."]);

    config.compile_fds(fds).expect("prost codegen");
}

fn main() {
    println!("cargo:rustc-check-cfg=cfg(kontor_observer)");
    println!("cargo:rustc-check-cfg=cfg(kontor_retained)");
    println!("cargo:rustc-check-cfg=cfg(kontor_linked)");
    println!("cargo:rustc-check-cfg=cfg(kontor_node)");
    if env::var("CARGO_PKG_NAME").as_deref() == Ok("kontor-node") {
        println!("cargo:rustc-cfg=kontor_node");
        println!("cargo:rustc-cfg=kontor_linked");
    }
    // Explicit protobuf inputs disable Cargo's default package scan. Track Git
    // separately, including linked worktrees, so commits refresh built metadata.
    track_git_head();
    built::write_built_file().expect("Failed to acquire build-time information");
    build_protos();
    // Test contracts are committed, container-built artifacts
    // (test-contracts/binaries/, see tools/kontor build), so neither
    // production nor test builds compile wasm — no wasm32 toolchain/wasm-opt.
}
