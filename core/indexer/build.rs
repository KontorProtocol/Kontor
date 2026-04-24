fn build_protos() {
    let protos = &[
        "proto/consensus/v1/consensus.proto",
        "proto/consensus/v1/sync.proto",
        "proto/consensus/v1/liveness.proto",
    ];

    for proto in protos {
        println!("cargo:rerun-if-changed={proto}");
    }

    let fds = protox::compile(protos, ["proto"]).expect("protobuf compilation");

    let mut config = prost_build::Config::new();
    config.enable_type_names();
    config.bytes(["."]);

    config.compile_fds(fds).expect("prost codegen");
}

fn main() {
    built::write_built_file().expect("Failed to acquire build-time information");
    build_protos();
    // Test-contracts compilation moved to testlib's build.rs (dev-only
    // crate), so production builds of indexer don't carry the wasm32
    // toolchain or wasm-opt dependency.
}
