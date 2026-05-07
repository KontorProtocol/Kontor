use glob::glob;
use std::process::Command;

// Compile test-contracts to WASM. Lives in testlib (a dev-only crate)
// rather than indexer's build.rs so production builds of indexer —
// which never pull in testlib — don't need the wasm32 toolchain or
// the Binaryen/wasm-opt tooling. Tests that touch test-contracts
// depend on testlib, which triggers this build.
fn main() {
    let mut cd = std::env::current_dir().unwrap();
    cd.pop(); // pop /testlib
    cd.pop(); // pop /core
    let contract_dir = cd.join("test-contracts");
    let target_dir = contract_dir.join("target");

    // Rerun only when test-contract sources change (exclude build
    // outputs so the target dir doesn't retrigger us on every build).
    let pattern = contract_dir.join("**").join("*");
    let pattern_str = pattern.to_str().expect("valid path");
    for path in glob(pattern_str).expect("glob pattern").flatten() {
        if path.is_file() && !path.starts_with(&target_dir) {
            println!("cargo:rerun-if-changed={}", path.display());
        }
    }

    let build_script = contract_dir.join("build.sh");
    if !build_script.exists() {
        panic!("build.sh not found in {}", contract_dir.display());
    }
    let status = Command::new(&build_script)
        .current_dir(&contract_dir)
        .status()
        .expect("execute test-contracts/build.sh");
    if !status.success() {
        panic!("test-contracts build failed");
    }
}
