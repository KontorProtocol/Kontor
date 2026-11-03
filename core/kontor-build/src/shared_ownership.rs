use std::collections::{BTreeMap, BTreeSet};
use std::ffi::{CStr, CString, OsString, c_void};
use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::ptr::NonNull;
use std::sync::LazyLock;

use anyhow::{Context, Result, ensure};
use libc::{RTLD_LOCAL, RTLD_NOW, dlclose, dlerror, dlopen, dlsym};
use regex::Regex;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::container::sha256;
use crate::object_tools::ObjectTools;
use crate::symbol_audit::{Definitions, GDB_SCRIPT, Graph, INPUT_RUNTIME, Inspector, Kind};
use crate::toolchain::{Environment, output};

type Names = BTreeSet<String>;
type Owners = BTreeMap<String, Vec<PathBuf>>;
type References = BTreeMap<String, Names>;
const LINUX_RUNTIME: &[&str] = &[
    "libgcc_s.so.1",
    "libm.so.6",
    "libc.so.6",
    "libpthread.so.0",
    "libdl.so.2",
    "librt.so.1",
    "ld-linux-aarch64.so.1",
    "ld-linux-x86-64.so.2",
];
const MAC_RUNTIME: &[&str] = &[
    "/usr/lib/libSystem.B.dylib",
    "/usr/lib/libiconv.2.dylib",
    "/System/Library/Frameworks/CoreFoundation.framework/Versions/A/CoreFoundation",
    "/System/Library/Frameworks/SystemConfiguration.framework/Versions/A/SystemConfiguration",
    "/System/Library/Frameworks/Security.framework/Versions/A/Security",
];
const OPTIONAL_UNWIND: &[&str] = &[
    "__unw_add_dynamic_fde",
    "__unw_add_dynamic_eh_frame_section",
    "__unw_remove_dynamic_eh_frame_section",
];
static RUSTC_ALLOCATOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A_RNvCs[0-9A-Za-z]+_7___rustc(?:12___rust_alloc|14___rust_dealloc|14___rust_realloc|19___rust_alloc_zeroed|35___rust_no_alloc_shim_is_unstable_v2)\z").unwrap()
});
static DARWIN_REFERENCE: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\A\s*\(undefined\)\s+(weak\s+)?(?:private\s+)?external\s+(\S+)(?:\s+\(from .+\))?\s*\z",
    )
    .unwrap()
});
static LINUX_PATH: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"(?:=>\s+)?(/\S+)").unwrap());

#[derive(Deserialize)]
pub struct Request {
    working_directory: PathBuf,
    #[serde(flatten)]
    operation: Operation,
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum Operation {
    References {
        path: PathBuf,
    },
    RuntimePaths {
        executable: PathBuf,
        kind: Kind,
    },
    PlatformOwners {
        executable: PathBuf,
        candidates: Names,
        kind: Kind,
    },
    RejectShadow {
        graph: String,
        names: Names,
        owners: Names,
        node: bool,
    },
    GraphReferences {
        graph: Graph,
        index: usize,
        sets: Vec<Names>,
    },
    LinkerOwners {
        executable: PathBuf,
    },
    RejectUnowned {
        graph: String,
        names: Names,
        refs: Names,
        common: Names,
        platform: Names,
        optional: Names,
        linker: Names,
        compiler: Names,
    },
    Verify {
        graphs: Vec<Graph>,
        sets: Vec<Names>,
        host_objects: Vec<PathBuf>,
        executable: PathBuf,
        env: Environment,
        kind: Kind,
        node_objects: Vec<PathBuf>,
        compiler_objects: Vec<PathBuf>,
    },
}

pub fn run(request: Request) -> Result<Value> {
    let cwd = &request.working_directory;
    match request.operation {
        Operation::References { path } => {
            Ok(json!(references(&ObjectTools::discover(cwd)?, &path)?))
        }
        Operation::RuntimePaths { executable, kind } => {
            Ok(json!(runtime_paths(cwd, &executable, kind)?))
        }
        Operation::PlatformOwners {
            executable,
            candidates,
            kind,
        } => Ok(json!(platform_owners(
            cwd,
            &runtime_paths(cwd, &executable, kind)?,
            &candidates
        )?)),
        Operation::RejectShadow {
            graph,
            names,
            owners,
            node,
        } => {
            reject_shadow(&graph, &names, &owners, node)?;
            Ok(Value::Null)
        }
        Operation::GraphReferences { graph, index, sets } => Ok(json!(graph_references(
            &ObjectTools::discover(cwd)?,
            &graph,
            index,
            &sets
        )?)),
        Operation::LinkerOwners { executable } => Ok(json!(linker_owners(
            &ObjectTools::discover(cwd)?,
            &executable
        )?)),
        Operation::RejectUnowned {
            graph,
            names,
            refs,
            common,
            platform,
            optional,
            linker,
            compiler,
        } => {
            reject_unowned(
                &graph, &names, &refs, &common, &platform, &optional, &linker, &compiler,
            )?;
            Ok(Value::Null)
        }
        Operation::Verify {
            graphs,
            sets,
            host_objects,
            executable,
            env,
            kind,
            node_objects,
            compiler_objects,
        } => verify(
            cwd,
            &graphs,
            &sets,
            &host_objects,
            &executable,
            &env,
            kind,
            &node_objects,
            &compiler_objects,
        ),
    }
}

pub fn parse_references(text: &str, darwin: bool) -> Result<References> {
    let mut names = References::new();
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.is_empty() || line.ends_with(':') {
            continue;
        }
        let (name, kind) = if darwin {
            let captures = DARWIN_REFERENCE
                .captures(line)
                .with_context(|| format!("unknown Darwin undefined-symbol attributes: {line}"))?;
            let name = captures.get(2).unwrap().as_str();
            (
                name.strip_prefix('_').unwrap_or(name),
                if captures.get(1).is_some() { "w" } else { "U" },
            )
        } else {
            ensure!(
                fields.len() == 1 || (fields.len() == 2 && ["U", "w", "v"].contains(&fields[0])),
                "unknown undefined-symbol output: {line}"
            );
            if fields.len() == 1 {
                (fields[0], "U")
            } else {
                (fields[1], fields[0])
            }
        };
        names.entry(name.into()).or_default().insert(kind.into());
    }
    Ok(names)
}

fn references(tools: &ObjectTools, path: &Path) -> Result<References> {
    let mut arguments = Vec::<OsString>::new();
    if cfg!(target_os = "macos") {
        arguments.push("-m".into());
    }
    arguments.extend(["-u".into(), path.as_os_str().into()]);
    parse_references(&tools.inspect(&arguments)?, cfg!(target_os = "macos"))
}

fn parse_runtime_paths(text: &str, kind: Kind, darwin: bool) -> Result<Vec<PathBuf>> {
    let paths: Vec<&str> = if darwin {
        text.lines()
            .skip(1)
            .map(|line| line.trim().split(" (").next().unwrap())
            .collect()
    } else {
        LINUX_PATH
            .captures_iter(text)
            .map(|c| c.get(1).unwrap().as_str())
            .collect()
    };
    let permitted = |path: &&str| {
        if darwin {
            MAC_RUNTIME.contains(path)
                || (kind == Kind::Executor && *path == "/usr/lib/libc++.1.dylib")
        } else {
            Path::new(path)
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| {
                    LINUX_RUNTIME.contains(&name)
                        || (kind == Kind::Executor && name == "libstdc++.so.6")
                })
        }
    };
    ensure!(
        (darwin || !paths.is_empty()) && paths.iter().all(permitted),
        "undeclared shared platform libraries: {paths:?}"
    );
    let mut seen = BTreeSet::new();
    Ok(paths
        .into_iter()
        .filter(|path| seen.insert(*path))
        .map(PathBuf::from)
        .collect())
}

fn runtime_paths(cwd: &Path, executable: &Path, kind: Kind) -> Result<Vec<PathBuf>> {
    let path = executable
        .to_str()
        .context("runtime executable must be UTF8")?;
    let text = if cfg!(target_os = "macos") {
        output(cwd, Path::new("otool"), &["-L", path], None)?
    } else {
        output(cwd, Path::new("ldd"), &[path], None)?
    };
    parse_runtime_paths(&text, kind, cfg!(target_os = "macos"))
}

struct Library(NonNull<c_void>);
impl Library {
    fn open(path: &Path) -> Result<Self> {
        let path = CString::new(path.as_os_str().as_bytes())?;
        // Match ctypes' local, eager load. Handles stay live until all lookups finish.
        let pointer = unsafe { dlopen(path.as_ptr(), RTLD_NOW | RTLD_LOCAL) };
        NonNull::new(pointer)
            .map(Self)
            .with_context(|| format!("load platform library: {}", Self::error()))
    }
    fn error() -> String {
        // dlerror's message is copied before another loader call can replace it.
        unsafe {
            let error = dlerror();
            if error.is_null() {
                "unknown loader error".into()
            } else {
                CStr::from_ptr(error).to_string_lossy().into_owned()
            }
        }
    }
    fn contains(&self, name: &str) -> Result<bool> {
        let name = CString::new(name)?;
        // A null symbol address is legal; dlerror determines whether lookup failed.
        unsafe {
            dlerror();
            dlsym(self.0.as_ptr(), name.as_ptr());
            Ok(dlerror().is_null())
        }
    }
}
impl Drop for Library {
    fn drop(&mut self) {
        // No addresses escape Library, so this releases only our loader reference.
        unsafe {
            dlclose(self.0.as_ptr());
        }
    }
}

fn platform_owners(
    cwd: &Path,
    paths: &[PathBuf],
    candidates: &Names,
) -> Result<(Owners, Vec<Value>)> {
    let mut owners = Owners::new();
    let mut libraries = Vec::new();
    for path in paths {
        let library = Library::open(&cwd.join(path))?;
        let mut names = Vec::new();
        for name in candidates {
            if library.contains(name)? {
                names.push(name);
                owners.entry(name.clone()).or_default().push(path.clone());
            }
        }
        let path_exists = cwd.join(path).is_file();
        libraries.push(json!({"path":path, "sha256": if path_exists { Some(sha256(&cwd.join(path))?) } else { None },
            "symbols_resolved_in_library_scope":names, "dyld_shared_cache":cfg!(target_os = "macos") && !path_exists}));
    }
    Ok((owners, libraries))
}

fn reject_shadow(graph: &str, names: &Names, owners: &Names, node: bool) -> Result<()> {
    let overlap: Vec<_> = names
        .intersection(owners)
        .filter(|name| !INPUT_RUNTIME.contains(&name.as_str()))
        .take(100)
        .collect();
    ensure!(
        overlap.is_empty(),
        "{graph} shadows {} definitions: {overlap:?}",
        if node {
            "node input"
        } else {
            "common host/sysroot"
        }
    );
    Ok(())
}

fn graph_references(
    tools: &ObjectTools,
    graph: &Graph,
    index: usize,
    sets: &[Names],
) -> Result<(Names, Names)> {
    ensure!(index < sets.len(), "graph reference index out of bounds");
    let mut names = Names::new();
    let mut strong = Names::new();
    for path in graph.paths()? {
        for (name, kinds) in references(tools, path)? {
            if kinds.contains("U") {
                strong.insert(name.clone());
            }
            names.insert(name);
        }
    }
    ensure!(
        !names.contains(GDB_SCRIPT),
        "{} references compiler debug metadata as code",
        graph.graph
    );
    for (other, definitions) in sets.iter().enumerate() {
        if other != index {
            let foreign: Vec<_> = names
                .intersection(definitions)
                .filter(|name| !INPUT_RUNTIME.contains(&name.as_str()))
                .take(100)
                .collect();
            ensure!(
                foreign.is_empty(),
                "{} references another graph: {foreign:?}",
                graph.graph
            );
        }
    }
    let optional = names
        .difference(&strong)
        .filter(|name| OPTIONAL_UNWIND.contains(&name.as_str()))
        .cloned()
        .collect();
    Ok((names, optional))
}

fn got_owner(symbols: &Definitions) -> Result<Definitions> {
    if let Some(symbol) = symbols.get("_GLOBAL_OFFSET_TABLE_") {
        ensure!(
            ["d", "a"].contains(&symbol.kind.as_str()),
            "ELF GOT anchor is not local linker data or an absolute symbol"
        );
        Ok(BTreeMap::from([(
            "_GLOBAL_OFFSET_TABLE_".into(),
            symbol.clone(),
        )]))
    } else {
        Ok(Definitions::new())
    }
}
fn linker_owners(tools: &ObjectTools, executable: &Path) -> Result<Definitions> {
    if cfg!(target_os = "linux") {
        got_owner(&tools.definitions(executable, false)?)
    } else {
        Ok(Definitions::new())
    }
}

#[allow(clippy::too_many_arguments)]
fn reject_unowned(
    graph: &str,
    names: &Names,
    refs: &Names,
    common: &Names,
    platform: &Names,
    optional: &Names,
    linker: &Names,
    compiler: &Names,
) -> Result<()> {
    let shadowed: Vec<_> = names.intersection(platform).take(100).collect();
    ensure!(
        shadowed.is_empty(),
        "{graph} shadows a platform export: {shadowed:?}"
    );
    let unresolved: Vec<_> = refs
        .iter()
        .filter(|name| {
            ![names, common, platform, optional, linker, compiler]
                .iter()
                .any(|owners| owners.contains(*name))
        })
        .take(100)
        .collect();
    ensure!(
        unresolved.is_empty(),
        "{graph} imports have no declared owner: {unresolved:?}"
    );
    Ok(())
}

fn inventory(cwd: &Path, tools: &ObjectTools, path: &Path) -> Result<(Definitions, Value)> {
    let names = tools.definitions(path, true)?;
    if names.contains_key(GDB_SCRIPT) {
        tools.compiler_debug_metadata(path, false)?;
    }
    let record = json!({"path":path, "sha256":sha256(&cwd.join(path))?, "definitions":names});
    Ok((names, record))
}

#[allow(clippy::too_many_arguments)]
fn verify(
    cwd: &Path,
    graphs: &[Graph],
    sets: &[Names],
    host_objects: &[PathBuf],
    executable: &Path,
    env: &Environment,
    kind: Kind,
    node_objects: &[PathBuf],
    compiler_objects: &[PathBuf],
) -> Result<Value> {
    ensure!(
        graphs.len() == sets.len() && !graphs.is_empty(),
        "shared audit graph evidence lengths differ or are empty"
    );
    ensure!(
        kind != Kind::Proof || (node_objects.is_empty() && compiler_objects.is_empty()),
        "proof audit has unexpected node inputs"
    );
    ensure!(
        kind != Kind::Executor
            || (host_objects.is_empty()
                && !node_objects.is_empty()
                && !compiler_objects.is_empty()),
        "executor audit requires separate node and root compiler inputs"
    );
    let compiler_paths: BTreeSet<_> = compiler_objects.iter().collect();
    let node_paths: BTreeSet<_> = node_objects.iter().collect();
    ensure!(
        compiler_paths.is_subset(&node_paths),
        "root compiler inputs are absent from node inventory"
    );
    let tools = ObjectTools::discover(cwd)?;
    let rustc = Path::new(env.get("RUSTC").context("missing RUSTC")?);
    let sysroot = output(cwd, rustc, &["--print", "sysroot"], Some(env))?;
    let version = output(cwd, rustc, &["-Vv"], Some(env))?;
    let host = version
        .lines()
        .find_map(|line| line.strip_prefix("host: "))
        .context("missing compiler host")?;
    let directory = Path::new(sysroot.trim())
        .join("lib/rustlib")
        .join(host)
        .join("lib");
    let mut paths = Vec::new();
    if cwd.join(&directory).is_dir() {
        for entry in fs::read_dir(cwd.join(&directory))? {
            let entry = entry?;
            if entry.path().extension().is_some_and(|ext| ext == "rlib") {
                paths.push(directory.join(entry.file_name()));
            }
        }
    }
    paths.sort();
    paths.extend_from_slice(host_objects);
    if cfg!(target_os = "linux") {
        let path = output(
            cwd,
            Path::new(env.get("CC").map(String::as_str).unwrap_or("cc")),
            &["-print-file-name=libc_nonshared.a"],
            Some(env),
        )?;
        let path = cwd.join(path.trim());
        ensure!(
            path.is_file(),
            "missing compiler-selected libc_nonshared archive"
        );
        paths.push(path.canonicalize()?);
    }
    ensure!(
        (kind != Kind::Proof || !host_objects.is_empty()) && !paths.is_empty(),
        "missing concrete host/sysroot input inventory"
    );
    let mut common = Owners::new();
    let mut inventories = Vec::new();
    for path in paths {
        let (names, record) = inventory(cwd, &tools, &path)?;
        inventories.push(record);
        for name in names.keys() {
            common.entry(name.clone()).or_default().push(path.clone());
        }
    }
    let mut node = Owners::new();
    let mut node_inventories = Vec::new();
    let mut compiler = Owners::new();
    for path in node_paths {
        let (names, record) = inventory(cwd, &tools, path)?;
        node_inventories.push(record);
        for name in names.keys() {
            node.entry(name.clone()).or_default().push(path.clone());
            if compiler_paths.contains(path) && RUSTC_ALLOCATOR.is_match(name) {
                compiler.entry(name.clone()).or_default().push(path.clone());
            }
        }
    }
    let ambiguous: Vec<_> = compiler
        .keys()
        .filter(|name| node[*name] != compiler[*name])
        .take(100)
        .collect();
    ensure!(
        ambiguous.is_empty(),
        "node duplicates root compiler runtime definitions: {ambiguous:?}"
    );
    let common_names: Names = common.keys().cloned().collect();
    let node_names: Names = node.keys().cloned().collect();
    reject_shadow("node", &node_names, &common_names, false)?;
    let mut graph_refs = Vec::new();
    let mut graph_optional = Vec::new();
    for (index, (graph, names)) in graphs.iter().zip(sets).enumerate() {
        reject_shadow(&graph.graph, names, &common_names, false)?;
        reject_shadow(&graph.graph, names, &node_names, true)?;
        let (refs, optional) = graph_references(&tools, graph, index, sets)?;
        graph_refs.push(refs);
        graph_optional.push(optional);
    }
    let candidates: Names = graph_refs
        .iter()
        .chain(sets)
        .flat_map(|names| names.iter())
        .filter(|name| !common_names.contains(*name))
        .cloned()
        .collect();
    let (platform, libraries) =
        platform_owners(cwd, &runtime_paths(cwd, executable, kind)?, &candidates)?;
    let platform_names: Names = platform.keys().cloned().collect();
    let compiler_names: Names = compiler.keys().cloned().collect();
    let overlap: Vec<_> = compiler_names
        .intersection(&platform_names)
        .take(100)
        .collect();
    ensure!(
        overlap.is_empty(),
        "root compiler runtime shadows platform exports: {overlap:?}"
    );
    let linker = linker_owners(&tools, executable)?;
    let linker_names: Names = linker.keys().cloned().collect();
    let mut reference_report = Vec::new();
    for (((graph, names), refs), optional) in graphs
        .iter()
        .zip(sets)
        .zip(&graph_refs)
        .zip(&graph_optional)
    {
        reject_unowned(
            &graph.graph,
            names,
            refs,
            &common_names,
            &platform_names,
            optional,
            &linker_names,
            &compiler_names,
        )?;
        let selected = |owners: &Names| refs.intersection(owners).cloned().collect::<Vec<_>>();
        reference_report.push(json!({"graph":graph.graph, "own":selected(names), "common":selected(&common_names), "platform":selected(&platform_names), "linker":selected(&linker_names), "compiler_runtime":selected(&compiler_names)}));
    }
    Ok(
        json!({"common":common, "node":node, "report":{"common_inputs":inventories, "platform_libraries":libraries, "linker_definitions":linker, "optional_weak_system_unwind":graph_optional, "references":reference_report}, "node_report":if kind == Kind::Executor { Some(json!({"node_inputs":node_inventories, "compiler_runtime":compiler})) } else { None }}),
    )
}

#[cfg(test)]
mod tests;
