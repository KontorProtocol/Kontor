use std::collections::{BTreeMap, BTreeSet};
use std::ffi::CStr;
use std::fs;
use std::mem::MaybeUninit;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};
use libc::{uname, utsname};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::container::sha256;

pub type Environment = BTreeMap<String, String>;
const TOOLCHAIN: &str = "1.99.1";

pub(crate) fn output(
    cwd: &Path,
    program: &Path,
    args: &[&str],
    env: Option<&Environment>,
) -> Result<String> {
    let program = if program.components().count() > 1 {
        cwd.join(program)
    } else {
        program.to_owned()
    };
    let mut command = Command::new(&program);
    command.current_dir(cwd).args(args).stdin(Stdio::null());
    if let Some(env) = env {
        command.env_clear().envs(env);
    }
    let result = command
        .output()
        .with_context(|| format!("run {}", program.display()))?;
    ensure!(
        result.status.success(),
        "toolchain command failed: {}: {}",
        program.display(),
        String::from_utf8_lossy(&result.stderr)
    );
    Ok(String::from_utf8(result.stdout)?
        .replace("\r\n", "\n")
        .replace('\r', "\n"))
}

pub fn symbol_reader(cwd: &Path) -> Result<PathBuf> {
    let compiler = output(
        cwd,
        Path::new("rustup"),
        &["which", "--toolchain", TOOLCHAIN, "rustc"],
        None,
    )?;
    let compiler = cwd.join(compiler.trim());
    let version = output(cwd, &compiler, &["-Vv"], None)?;
    let host = version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .context("missing compiler host")?;
    let path = compiler
        .parent()
        .and_then(Path::parent)
        .context("compiler sysroot")?
        .join("lib/rustlib")
        .join(host)
        .join("bin/llvm-nm");
    ensure!(
        path.is_file(),
        "missing pinned llvm-nm; run rustup component add --toolchain {TOOLCHAIN} llvm-tools-preview"
    );
    Ok(path)
}

fn platform() -> Result<Vec<String>> {
    let mut value = MaybeUninit::<utsname>::uninit();
    // uname initializes every field on success, including NUL termination.
    let value = unsafe {
        ensure!(
            uname(value.as_mut_ptr()) == 0,
            "cannot read platform identity"
        );
        value.assume_init()
    };
    [
        &value.sysname[..],
        &value.nodename[..],
        &value.release[..],
        &value.version[..],
        &value.machine[..],
    ]
    .iter()
    .map(|field| {
        // These are the initialized, NUL-terminated uname fields above.
        Ok(unsafe { CStr::from_ptr(field.as_ptr()) }
            .to_str()?
            .to_owned())
    })
    .collect()
}

fn collect(cwd: &Path, env: &Environment, target: &str, reader: &Path) -> Result<Value> {
    let rustc = env.get("RUSTC").context("missing pinned RUSTC")?;
    let sysroot = output(cwd, Path::new(rustc), &["--print", "sysroot"], Some(env))?;
    let sysroot = cwd.join(sysroot.trim());
    let mut common = BTreeMap::new();
    for entry in fs::read_dir(sysroot.join("lib/rustlib").join(target).join("lib"))? {
        let path = entry?.path();
        if path
            .extension()
            .is_some_and(|extension| extension == "rlib" || extension == "rmeta")
        {
            common.insert(
                path.file_name()
                    .context("sysroot library filename")?
                    .to_str()
                    .context("sysroot library filename must be UTF8")?
                    .to_owned(),
                sha256(&path)?,
            );
        }
    }
    ensure!(!common.is_empty(), "missing common sysroot libraries");
    let mut compiler_libraries = BTreeMap::new();
    for entry in fs::read_dir(sysroot.join("lib"))? {
        let path = entry?.path();
        let name = path
            .file_name()
            .context("compiler library filename")?
            .to_str()
            .context("compiler library filename must be UTF8")?;
        if path.is_file()
            && (name.contains(".so")
                || path
                    .extension()
                    .is_some_and(|extension| extension == "dylib"))
        {
            compiler_libraries.insert(path.strip_prefix(&sysroot)?.to_owned(), sha256(&path)?);
        }
    }
    let build_environment: Environment = env
        .iter()
        .filter(|(key, _)| {
            [
                "CC",
                "CXX",
                "AR",
                "RANLIB",
                "CFLAGS",
                "CXXFLAGS",
                "LDFLAGS",
                "MACOSX_DEPLOYMENT_TARGET",
                "SDKROOT",
                "RUSTC",
                "RUSTUP_TOOLCHAIN",
            ]
            .contains(&key.as_str())
                || [
                    "CARGO_PROFILE_",
                    "CARGO_TARGET_",
                    "CC_",
                    "CXX_",
                    "CFLAGS_",
                    "CXXFLAGS_",
                    "AR_",
                ]
                .iter()
                .any(|prefix| key.starts_with(prefix))
        })
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    Ok(json!({
        "compiler": output(cwd, Path::new(rustc), &["-Vv"], Some(env))?,
        "symbol_reader": {"path": reader, "sha256": sha256(reader)?, "version": output(cwd, reader, &["--version"], None)?},
        "rustc_sha256": sha256(&sysroot.join("bin/rustc"))?, "common_sysroot": common,
        "compiler_libraries": compiler_libraries, "build_environment": build_environment,
        "cc": output(cwd, Path::new(env.get("CC").map(String::as_str).unwrap_or("cc")), &["--version"], Some(env))?,
        "platform": platform()?,
    }))
}

pub fn tools(cwd: &Path, env: &Environment, target: &str) -> Result<Value> {
    collect(cwd, env, target, &symbol_reader(cwd)?)
}

#[derive(Deserialize)]
pub struct Graph {
    compiler_proc_macros: Vec<CompilerMacro>,
}

#[derive(Deserialize)]
struct CompilerMacro {
    path: PathBuf,
    staged: PathBuf,
}

fn reject_compiler_libraries(text: &str, graphs: &[Graph], darwin: bool) -> Result<()> {
    let mut names = BTreeSet::new();
    for graph in graphs {
        for item in &graph.compiler_proc_macros {
            for path in [&item.path, &item.staged] {
                names.insert(
                    path.file_name()
                        .context("proc-macro filename")?
                        .to_str()
                        .context("proc-macro filename must be UTF8")?,
                );
            }
        }
    }
    for line in text.lines() {
        if !darwin && !line.contains("NEEDED") {
            continue;
        }
        ensure!(
            !names.iter().any(|name| line.contains(name)),
            "compiler proc-macro library became a node runtime dependency"
        );
    }
    Ok(())
}

pub fn runtime_libraries(
    cwd: &Path,
    executable: &Path,
    env: &Environment,
    graphs: &[Graph],
) -> Result<String> {
    let darwin = cfg!(target_os = "macos");
    let (program, option) = if darwin {
        ("otool", "-L")
    } else {
        ("readelf", "-d")
    };
    let text = output(
        cwd,
        Path::new(program),
        &[
            option,
            executable
                .to_str()
                .context("executable path must be UTF8")?,
        ],
        Some(env),
    )?;
    reject_compiler_libraries(&text, graphs, darwin)?;
    Ok(text)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    fn script(path: &Path, body: &str) -> Result<()> {
        fs::create_dir_all(path.parent().unwrap())?;
        fs::write(path, format!("#!/bin/sh\n{body}\n"))?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o755))?;
        Ok(())
    }

    #[test]
    fn inventory_binds_compiler_and_sysroot_without_exposing_unrelated_environment() -> Result<()> {
        let dir = tempdir()?;
        let root = dir.path().canonicalize()?;
        let rustc = root.join("bin/rustc");
        script(
            &rustc,
            "if [ \"$1\" = --print ]; then printf '%s\\n' \"$FAKE_SYSROOT\"; else printf 'compiler\\r\\n'; fi",
        )?;
        fs::create_dir_all(root.join("lib/rustlib/target/lib"))?;
        let library = root.join("lib/rustlib/target/lib/common.rlib");
        fs::write(&library, "library")?;
        fs::write(
            root.join("lib/rustlib/target/lib/ignored.txt"),
            "not a library",
        )?;
        fs::write(root.join("lib/driver.so.1"), "compiler library")?;
        let reader = root.join("llvm-nm");
        script(&reader, "printf 'reader\\r\\n'")?;
        let cc = root.join("cc");
        script(&cc, "printf '%s\\n' \"$CFLAGS\"")?;
        let env = Environment::from([
            ("RUSTC".into(), rustc.to_str().unwrap().into()),
            ("CC".into(), "./cc".into()),
            ("FAKE_SYSROOT".into(), root.to_str().unwrap().into()),
            ("CFLAGS".into(), "flags".into()),
            ("CARGO_TARGET_TEST_RUSTFLAGS".into(), "target flags".into()),
            ("SECRET".into(), "private".into()),
        ]);
        let original = collect(&root, &env, "target", &reader)?;
        assert_eq!(original["compiler"], "compiler\n");
        assert_eq!(original["cc"], "flags\n");
        assert_eq!(original["symbol_reader"]["version"], "reader\n");
        assert_eq!(original["common_sysroot"].as_object().unwrap().len(), 1);
        assert_eq!(original["compiler_libraries"].as_object().unwrap().len(), 1);
        assert!(original["build_environment"].get("SECRET").is_none());
        assert!(
            original["build_environment"]
                .get("CARGO_TARGET_TEST_RUSTFLAGS")
                .is_some()
        );
        fs::write(&library, "changed library")?;
        assert_ne!(collect(&root, &env, "target", &reader)?, original);
        fs::remove_file(library)?;
        assert!(
            collect(&root, &env, "target", &reader)
                .unwrap_err()
                .to_string()
                .contains("missing common sysroot")
        );
        Ok(())
    }

    #[test]
    fn runtime_scan_checks_both_original_and_staged_names_on_each_platform() -> Result<()> {
        let graphs: Vec<Graph> = serde_json::from_value(
            json!([{"compiler_proc_macros": [{"path": "/compiler/macro.so", "staged": "/staged/renamed.so"}]}]),
        )?;
        reject_compiler_libraries("(NEEDED) libc.so", &graphs, false)?;
        reject_compiler_libraries("(RPATH) /compiler/macro.so", &graphs, false)?;
        for name in ["macro.so", "renamed.so"] {
            assert!(
                reject_compiler_libraries(&format!("(NEEDED) {name}"), &graphs, false).is_err()
            );
            assert!(
                reject_compiler_libraries(
                    &format!("\t{name} (compatibility version 1.0.0)"),
                    &graphs,
                    true
                )
                .is_err()
            );
        }
        let dir = tempdir()?;
        let reader = dir.path().join(if cfg!(target_os = "macos") {
            "otool"
        } else {
            "readelf"
        });
        script(&reader, "printf '(NEEDED) libc.so\\n'; exit 1")?;
        let env = Environment::from([("PATH".into(), dir.path().to_str().unwrap().into())]);
        assert!(runtime_libraries(dir.path(), Path::new("node"), &env, &graphs).is_err());
        Ok(())
    }
}
