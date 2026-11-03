use anyhow::{Context, Result, ensure};
use std::env;
use std::fs::{self, File};
use std::io;
use std::path::{Path, PathBuf};

use super::container::sha256;

pub const GRAPH_WRAPPER_NAME: &str = "kontor-graph-rustc";

pub fn stage_graph_wrapper(output: &Path) -> Result<PathBuf> {
    stage_wrapper(output, GRAPH_WRAPPER_NAME)
}

pub fn stage_node_wrapper(output: &Path) -> Result<PathBuf> {
    stage_wrapper(output, "kontor-node-rustc")
}

pub fn stage_linker_wrapper(output: &Path) -> Result<PathBuf> {
    stage_wrapper(output, "kontor-node-linker")
}

fn stage_wrapper(output: &Path, name: &str) -> Result<PathBuf> {
    let executable = env::current_exe()?.canonicalize()?;
    let source = executable
        .parent()
        .context("build tool directory")?
        .join(name);
    ensure!(
        source.is_file(),
        "compiler wrapper is missing; use tools/kontor to bootstrap it"
    );
    let hash = sha256(&source)?;
    let directory = output.join("compiler-wrapper").join(&hash);
    fs::create_dir_all(&directory)?;
    let wrapper = directory.join(name);
    if !wrapper.try_exists()? {
        // Hard links preserve this wrapper inode across later Cargo rebuilds.
        // A copy is needed when the output lives on another filesystem.
        if let Err(error) = fs::hard_link(&source, &wrapper)
            && error.kind() != io::ErrorKind::AlreadyExists
        {
            let mut target = File::options()
                .write(true)
                .create_new(true)
                .open(&wrapper)?;
            io::copy(&mut File::open(&source)?, &mut target)?;
            target.set_permissions(fs::metadata(&source)?.permissions())?;
        }
    }
    ensure!(
        sha256(&wrapper)? == hash,
        "staged compiler wrapper differs from the build tool"
    );
    wrapper.canonicalize().context("staged compiler wrapper")
}
