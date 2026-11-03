// Keep this executable std-only so unrelated CLI changes do not invalidate graph caches.
use std::env;
use std::error::Error;
use std::ffi::{OsStr, OsString};
use std::path::{Path, PathBuf};
use std::process::Command;

#[cfg(unix)]
use std::os::unix::process::CommandExt;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn require(condition: bool, message: &str) -> Result<()> {
    if condition {
        Ok(())
    } else {
        Err(message.into())
    }
}

fn main() -> Result<()> {
    let namespace = env::var("KONTOR_NATIVE_NAMESPACE").unwrap_or_default();
    let valid = ["first", "second", "observer"].iter().any(|graph| {
        namespace
            .strip_prefix(&format!("kontor_{graph}_"))
            .is_some_and(|suffix| {
                suffix.len() == 24
                    && suffix
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            })
    });
    require(
        valid,
        "missing or invalid protocol graph compiler namespace",
    )?;
    let this = env::current_exe()?.canonicalize()?;
    let configured = env::var_os("RUSTC_WRAPPER")
        .map(PathBuf::from)
        .and_then(|path| path.canonicalize().ok());
    require(
        configured.as_ref() == Some(&this)
            && env::var_os("RUSTC_WORKSPACE_WRAPPER").is_none_or(|value| value.is_empty()),
        "protocol builds forbid an additional compiler wrapper",
    )?;
    let mut arguments: Vec<OsString> = env::args_os().skip(1).collect();
    require(
        !arguments.is_empty(),
        "protocol wrapper requires a compiler",
    )?;
    let compiler = arguments.remove(0);
    let expected = env::var_os("KONTOR_PINNED_RUSTC")
        .map(PathBuf::from)
        .and_then(|path| path.canonicalize().ok());
    require(
        expected.is_some() && Path::new(&compiler).canonicalize().ok() == expected,
        "protocol wrapper requires the exact pinned rustc, not another compiler or wrapper",
    )?;
    let probe = arguments.iter().any(|arg| {
        ["-vV", "--version", "--print", "-"]
            .iter()
            .any(|value| arg == OsStr::new(value))
            || arg.as_encoded_bytes().starts_with(b"--print=")
    });
    if !probe && arguments.iter().any(|value| value == "--crate-name") {
        // Preserve Cargo's per-unit metadata and add the graph namespace to host and target units.
        arguments.push(format!("-Cmetadata={namespace}").into());
    }
    let mut command = Command::new(compiler);
    command.args(arguments);
    #[cfg(unix)]
    {
        Err(command.exec().into())
    }
    #[cfg(not(unix))]
    {
        Err("protocol graph compilation requires a supported Unix host".into())
    }
}
