use std::env;
use std::path::PathBuf;

fn main() {
    let manifest = PathBuf::from(env::var_os("CARGO_MANIFEST_DIR").expect("manifest directory"));
    let source = manifest.join("../../core/indexer/proto");
    let files = ["consensus", "sync", "liveness"]
        .map(|name| source.join(format!("consensus/v1/{name}.proto")));
    for file in &files {
        println!("cargo:rerun-if-changed={}", file.display());
    }
    let descriptors = protox::compile(&files, [&source]).expect("protobuf compilation");
    let mut config = prost_build::Config::new();
    config.enable_type_names();
    config.bytes(["."]);
    config.compile_fds(descriptors).expect("prost codegen");
}
