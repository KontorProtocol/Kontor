//! `kontor build` — the full contract builder. Compiles a contract workspace to
//! wasm and produces the on-chain `.wasm.br` artifacts, REPRODUCIBLY:
//!   cargo build --release (wasm32, pinned rustc via the workspace's
//!   rust-toolchain.toml) -> brotli.
//! Both rustc→wasm32 and the pure-Rust `brotli = "=8.0.3"` crate (the same one the
//! indexer decompresses with) are platform-deterministic, so the output is
//! byte-identical across machines and CPU arches. (We deliberately do NOT run
//! `wasm-opt`: binaryen's output isn't reproducible across toolchains/arches —
//! a documented LLVM iteration-order issue — and it's the one thing that broke
//! cross-platform reproducibility.)

use std::ffi::OsString;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use clap::Args;

// Matches the old `brotli -Zf` CLI: -Z = quality 11; default window 22.
const BROTLI_QUALITY: u32 = 11;
const BROTLI_LGWIN: u32 = 22;
const BROTLI_BUF: usize = 4096;

#[derive(Args)]
pub struct BuildArgs {
    /// Contract workspace to build. Its `.cargo/config.toml` selects the wasm32
    /// target and `rust-toolchain.toml` pins rustc. Defaults to the current dir.
    #[arg(default_value = ".")]
    dir: PathBuf,
    /// Also copy the resulting `.wasm.br` artifacts into this directory
    /// (e.g. native-contracts/binaries).
    #[arg(long)]
    out_dir: Option<PathBuf>,
}

pub fn run(args: BuildArgs) -> Result<()> {
    // 1. Compile to wasm. cargo picks up `dir`'s .cargo/config.toml (wasm32 target)
    //    and rust-toolchain.toml (pinned rustc) from the working directory.
    //
    //    Path-dependencies (e.g. stdlib) embed their ABSOLUTE source path in
    //    panic-location strings, so the wasm differs per build host
    //    (/home/<user>/… vs /home/runner/…). Remap the repo root (the contract
    //    workspace's parent) to a stable virtual prefix so the output is
    //    byte-reproducible across machines — each host remaps its own root to the
    //    same relative form. Setting RUSTFLAGS REPLACES the .cargo/config.toml
    //    `[target.wasm32].rustflags`, so re-include `-simd128` here.
    let repo_root = std::fs::canonicalize(&args.dir)
        .with_context(|| format!("canonicalizing {}", args.dir.display()))?
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| args.dir.clone());
    let mut rustflags = std::env::var("RUSTFLAGS").unwrap_or_default();
    for flag in [
        "-Ctarget-feature=-simd128".to_string(),
        format!("--remap-path-prefix={}=", repo_root.display()),
    ] {
        if !rustflags.is_empty() {
            rustflags.push(' ');
        }
        rustflags.push_str(&flag);
    }

    let status = Command::new("cargo")
        .current_dir(&args.dir)
        .env("RUSTFLAGS", rustflags)
        .args(["build", "--release"])
        .status()
        .context("running cargo build")?;
    if !status.success() {
        bail!("cargo build failed in {}", args.dir.display());
    }

    // 2. brotli-compress every built module -> <name>.wasm.br (decompressed by the
    //    indexer's brotli=8.0.3).
    let release = args.dir.join("target/wasm32-unknown-unknown/release");
    let mut built = 0;
    for entry in
        std::fs::read_dir(&release).with_context(|| format!("reading {}", release.display()))?
    {
        let wasm = entry?.path();
        if !is_contract_wasm(&wasm) {
            continue;
        }
        let mut br: OsString = wasm.clone().into_os_string();
        br.push(".br"); // token.wasm -> token.wasm.br
        let br = PathBuf::from(br);
        compress(&wasm, &br).with_context(|| format!("compressing {}", wasm.display()))?;
        if let Some(out_dir) = &args.out_dir {
            let dest = out_dir.join(br.file_name().expect("br has a file name"));
            std::fs::copy(&br, &dest).with_context(|| format!("copying to {}", dest.display()))?;
        }
        println!("built {}", br.display());
        built += 1;
    }
    if built == 0 {
        bail!("no contract wasm found in {}", release.display());
    }
    Ok(())
}

/// A primary contract module: `*.wasm` (`.wasm.br` artifacts have extension `br`,
/// so they're excluded).
fn is_contract_wasm(p: &Path) -> bool {
    p.extension().is_some_and(|e| e == "wasm")
}

fn compress(input: &Path, out_br: &Path) -> Result<()> {
    let wasm = std::fs::read(input).with_context(|| format!("reading {}", input.display()))?;
    let mut compressed = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(
            &mut compressed,
            BROTLI_BUF,
            BROTLI_QUALITY,
            BROTLI_LGWIN,
        );
        writer.write_all(&wasm)?;
    }
    std::fs::write(out_br, &compressed).with_context(|| format!("writing {}", out_br.display()))?;
    Ok(())
}
