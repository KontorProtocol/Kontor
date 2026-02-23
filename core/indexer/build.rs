use glob::glob;
use std::process::Command;

fn build(contract_dir: &std::path::Path) {
    let target_dir = contract_dir.join("target");

    // Define patterns to monitor (all files in contracts, recursively)
    let pattern = contract_dir.join("**").join("*");

    // Tell Cargo to rerun the script only if relevant files change
    let pattern_str = pattern.to_str().expect("Invalid path");
    for path in glob(pattern_str)
        .expect("Failed to read glob pattern")
        .flatten()
    {
        // Skip directories and the target folder
        if path.is_file() && !path.starts_with(&target_dir) {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

    // Debugging output
    println!("Debug: Starting build script for contracts");

    // Verify build.sh exists
    let build_script = contract_dir.join("build.sh");
    if !build_script.exists() {
        panic!("build.sh not found in {}", contract_dir.display());
    }

    // Execute the build script
    let status = Command::new(&build_script)
        .current_dir(contract_dir)
        .status()
        .expect("Failed to execute build script");

    if !status.success() {
        panic!("Failed to build contract to WASM");
    }
}

fn build_protos() {
    let protos = &[
        "src/consensus/proto/consensus.proto",
        "src/consensus/proto/sync.proto",
        "src/consensus/proto/liveness.proto",
    ];

    for proto in protos {
        println!("cargo:rerun-if-changed={proto}");
    }

    let fds = protox::compile(protos, ["src/consensus/proto"]).expect("protobuf compilation");

    let mut config = prost_build::Config::new();
    config.enable_type_names();
    config.bytes(["."]);

    config.compile_fds(fds).expect("prost codegen");
}

fn main() {
    built::write_built_file().expect("Failed to acquire build-time information");

    build_protos();

    // Get the path to the contracts directory
    let mut cd = std::env::current_dir().unwrap();
    cd.pop();
    cd.pop();
    build(&cd.join("test-contracts"));
}
