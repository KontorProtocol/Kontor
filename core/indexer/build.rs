use std::process::Command;

fn main() {
    let mut cd = std::env::current_dir().unwrap();
    cd.pop();
    cd.pop();
    let contract_dir = cd.join("contracts");

    println!("cargo:rerun-if-changed={}", contract_dir.display());

    println!("Debug: Starting build script");
    let status = Command::new("./build.sh")
        .current_dir(contract_dir)
        .status()
        .expect("Failed to execute build script");

    if !status.success() {
        panic!("Failed to build contract to WASM");
    }
}
