use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use anyhow::{Context, Result, bail, ensure};
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::container::sha256;
pub use crate::object_tools::GDB_SCRIPT;
use crate::object_tools::ObjectTools;

pub const INPUT_RUNTIME: &[&str] = &["DW.ref.rust_eh_personality", GDB_SCRIPT];
pub(crate) const FINAL_RUNTIME: &[&str] = &[
    "rust_eh_personality",
    "main",
    "_start",
    "__TMC_END__",
    "__bss_end__",
    "__bss_start",
    "__bss_start__",
    "__dso_handle",
    "__end__",
    "_bss_end__",
    "_edata",
    "_end",
    "_fini",
    "_init",
    "__aarch64_cpu_features",
    "__aarch64_have_lse_atomics",
    "__init_cpu_features",
    "__pthread_atfork",
    "__udivti3",
    "__umodti3",
];
pub(crate) const CRYPTO: &[&str] = &[
    "blst_keygen",
    "rustsecp256k1_v0_10_0_ecdsa_sign_recoverable",
    "rustsecp256k1_v0_10_0_default_illegal_callback_fn",
    "ring_core_0_17_14__CRYPTO_memcmp",
];
pub(crate) static RUST: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"\A(?:_ZN.+17h[0-9a-f]{16}E|_R[A-Z].+)(?:\.llvm\.\d+)?\z").unwrap()
});
pub(crate) static ANONYMOUS: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\Aanon\.[0-9a-f]+\.\d+(?:\.llvm\.\d+)?\z").unwrap());
static ALLOCATOR: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"__(?:rg|rust)_(?:alloc|dealloc|realloc|alloc_zeroed|alloc_error_handler)(?:\z|[^a-z_])",
    )
    .unwrap()
});
static PSM: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\Alibpsm-[0-9a-f]{16}\.rlib\z").unwrap());

type Names = BTreeSet<String>;
pub type Definitions = BTreeMap<String, Symbol>;
type Owners = BTreeMap<String, Value>;

#[derive(Clone, Debug, Deserialize, PartialEq, Serialize)]
pub struct Symbol {
    pub address: Option<String>,
    pub kind: String,
}

#[derive(Clone, Deserialize)]
pub struct Graph {
    pub(crate) graph: String,
    namespace: String,
    packages: Option<Vec<Package>>,
    #[serde(default = "empty_identity")]
    identity: Value,
    artifacts: Option<Vec<Artifact>>,
    native_artifacts: Option<Vec<Artifact>>,
}
#[derive(Clone, Deserialize)]
struct Package {
    name: String,
    version: String,
}
#[derive(Clone, Deserialize)]
struct Artifact {
    path: PathBuf,
    sha256: Option<String>,
}

fn empty_identity() -> Value {
    json!({})
}
impl Graph {
    fn artifacts(&self) -> Result<impl Iterator<Item = &Artifact>> {
        Ok(self
            .artifacts
            .as_ref()
            .context("graph artifact inventory missing")?
            .iter()
            .chain(
                self.native_artifacts
                    .as_ref()
                    .context("graph native artifact inventory missing")?,
            ))
    }
    pub(crate) fn paths(&self) -> Result<BTreeSet<&Path>> {
        Ok(self.artifacts()?.map(|item| item.path.as_path()).collect())
    }
}

#[derive(Clone, Copy, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Proof,
    Executor,
}

#[derive(Deserialize)]
pub struct Request {
    working_directory: PathBuf,
    #[serde(flatten)]
    operation: Operation,
}
#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum Operation {
    ParseDefinitions {
        text: String,
        darwin: bool,
    },
    Owner {
        name: String,
        graph: Graph,
        version: Option<String>,
        path: Option<PathBuf>,
        value: Option<Symbol>,
    },
    Inputs {
        graphs: Vec<Graph>,
    },
    PrivateLocal {
        graphs: Vec<Graph>,
    },
    Final {
        executable: PathBuf,
        graphs: Vec<Graph>,
        sets: Vec<Names>,
        versions: Vec<Option<String>>,
        common: Owners,
        kind: Kind,
        node: Owners,
    },
}

pub fn run(request: Request) -> Result<Value> {
    if let Operation::ParseDefinitions { text, darwin } = request.operation {
        return Ok(serde_json::to_value(parse_definitions(&text, darwin)?)?);
    }
    let tools = ObjectTools::discover(&request.working_directory)?;
    let audit = Audit {
        inspector: &tools,
        cwd: &request.working_directory,
    };
    match request.operation {
        Operation::Owner {
            name,
            graph,
            version,
            path,
            value,
        } => Ok(json!(audit.owner(
            &name,
            &graph,
            version.as_deref(),
            path.as_deref(),
            value.as_ref()
        )?)),
        Operation::Inputs { graphs } => audit.inputs(&graphs),
        Operation::PrivateLocal { graphs } => {
            Ok(serde_json::to_value(audit.private_local(&graphs)?)?)
        }
        Operation::Final {
            executable,
            graphs,
            sets,
            versions,
            common,
            kind,
            node,
        } => audit.final_audit(&executable, &graphs, &sets, &versions, &common, kind, &node),
        Operation::ParseDefinitions { .. } => unreachable!(),
    }
}

pub fn parse_definitions(text: &str, darwin: bool) -> Result<Definitions> {
    let mut symbols = Definitions::new();
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.is_empty() || line.ends_with(':') {
            continue;
        }
        if fields.len() == 2 && ["U", "w", "v"].contains(&fields[0]) {
            continue;
        }
        ensure!(
            fields.len() == 3
                && (fields[0].bytes().all(|b| b.is_ascii_hexdigit())
                    || fields[0].bytes().all(|b| b == b'-')),
            "unknown defined-symbol output: {line}"
        );
        let (address, kind, name) = (fields[0], fields[1], fields[2]);
        if kind.eq_ignore_ascii_case("u") {
            continue;
        }
        let name = if darwin {
            name.strip_prefix('_').unwrap_or(name)
        } else {
            name
        };
        // Bitcode owns a symbol even though it has no linked address yet.
        symbols.insert(
            name.into(),
            Symbol {
                address: (!address.starts_with('-')).then(|| address.into()),
                kind: kind.into(),
            },
        );
    }
    Ok(symbols)
}

pub fn suffix(version: &str) -> String {
    version
        .chars()
        .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
        .collect()
}

pub(crate) trait Inspector {
    fn definitions(&self, path: &Path, globals_only: bool) -> Result<Definitions>;
    fn debug_metadata(&self, path: &Path, linked: bool) -> Result<()>;
    fn members(&self, path: &Path) -> Result<Vec<String>>;
    fn member(&self, path: &Path, name: &str) -> Result<Vec<u8>>;
}
impl Inspector for ObjectTools {
    fn definitions(&self, path: &Path, globals_only: bool) -> Result<Definitions> {
        let mut args = Vec::<OsString>::new();
        if globals_only {
            args.push("-g".into());
        }
        args.push(path.as_os_str().into());
        parse_definitions(&self.inspect(&args)?, cfg!(target_os = "macos"))
    }
    fn debug_metadata(&self, path: &Path, linked: bool) -> Result<()> {
        self.compiler_debug_metadata(path, linked).map(|_| ())
    }
    fn members(&self, path: &Path) -> Result<Vec<String>> {
        self.archive_members(path)
    }
    fn member(&self, path: &Path, name: &str) -> Result<Vec<u8>> {
        self.archive_member(path, name)
    }
}

struct Audit<'a> {
    inspector: &'a dyn Inspector,
    cwd: &'a Path,
}
impl Audit<'_> {
    fn owner(
        &self,
        name: &str,
        graph: &Graph,
        version: Option<&str>,
        path: Option<&Path>,
        value: Option<&Symbol>,
    ) -> Result<String> {
        if name == GDB_SCRIPT {
            ensure!(
                path.is_some() && value.is_some_and(|symbol| symbol.kind == "V"),
                "unverified compiler GDB metadata definition: {name}"
            );
            self.inspector.debug_metadata(path.unwrap(), false)?;
            return Ok("common compiler debug metadata".into());
        }
        if INPUT_RUNTIME.contains(&name) {
            return Ok("common compiler runtime".into());
        }
        ensure!(
            !ALLOCATOR.is_match(name),
            "bundle defines process allocator: {name}"
        );
        if RUST.is_match(name)
            || ANONYMOUS.is_match(name)
            || version.is_some_and(|version| {
                name.starts_with("wasmtime_") && name.ends_with(&format!("_{}", suffix(version)))
            })
            || name.starts_with(&format!("{}_", graph.namespace))
        {
            return Ok(graph.graph.clone());
        }
        bail!("unowned native input definition in {}: {name}", graph.graph)
    }

    fn verify_psm(&self, graph: &Graph) -> Result<()> {
        let rlibs: Vec<_> = graph
            .artifacts
            .as_ref()
            .context("graph artifact inventory missing")?
            .iter()
            .filter(|item| {
                item.path
                    .file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| PSM.is_match(n))
            })
            .collect();
        let archives: Vec<_> = graph
            .native_artifacts
            .as_ref()
            .context("graph native artifact inventory missing")?
            .iter()
            .filter(|item| item.path.file_name().is_some_and(|n| n == "libpsm_s.a"))
            .collect();
        if rlibs.is_empty() && archives.is_empty() {
            return Ok(());
        }
        ensure!(
            rlibs.len() == 1 && archives.len() == 1,
            "expected one psm rlib and native archive in {}",
            graph.graph
        );
        let (rlib, archive) = (&rlibs[0].path, &archives[0].path);
        let members = self.inspector.members(archive)?;
        ensure!(
            members.len() == 1 && members[0].ends_with(".o"),
            "unexpected psm native archive members: {}",
            archive.display()
        );
        ensure!(
            self.inspector
                .members(rlib)?
                .iter()
                .filter(|name| *name == &members[0])
                .count()
                == 1,
            "psm native object missing from rlib: {}",
            rlib.display()
        );
        ensure!(
            self.inspector.member(rlib, &members[0])?
                == self.inspector.member(archive, &members[0])?,
            "psm native archive copies differ in {}",
            graph.graph
        );
        Ok(())
    }

    fn private_local(&self, graphs: &[Graph]) -> Result<(Vec<Names>, Vec<Value>)> {
        let mut sets = Vec::new();
        let mut inventories = Vec::new();
        for graph in graphs {
            let prefix = format!("{}_", graph.namespace);
            let mut expected = BTreeMap::new();
            for item in graph.artifacts()? {
                if let Some(previous) = expected.insert(&item.path, &item.sha256) {
                    ensure!(
                        previous == &item.sha256,
                        "conflicting staged graph input hashes: {}",
                        item.path.display()
                    );
                }
            }
            let mut names = Names::new();
            let mut inputs = Vec::new();
            for (path, expected) in expected {
                let hash = sha256(&self.cwd.join(path))?;
                ensure!(
                    expected.as_ref() == Some(&hash),
                    "staged graph input changed before local ownership audit: {}",
                    path.display()
                );
                let globals = self.inspector.definitions(path, true)?;
                let local: Definitions = self
                    .inspector
                    .definitions(path, false)?
                    .into_iter()
                    .filter(|(name, _)| name.starts_with(&prefix) && !globals.contains_key(name))
                    .collect();
                names.extend(local.keys().cloned());
                inputs.push(json!({"path": path, "sha256": hash, "definitions": local}));
            }
            sets.push(names);
            inventories.push(json!({"graph": graph.graph, "inputs": inputs}));
        }
        Ok((sets, inventories))
    }

    fn inputs(&self, graphs: &[Graph]) -> Result<Value> {
        ensure!(
            graphs
                .iter()
                .map(|g| &g.graph)
                .collect::<BTreeSet<_>>()
                .len()
                == graphs.len()
                && graphs
                    .iter()
                    .map(|g| &g.namespace)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == graphs.len(),
            "independent graphs must have unique names and namespaces"
        );
        let mut versions = Vec::new();
        for graph in graphs {
            ensure!(graph.identity.is_object(), "invalid graph identity record");
            let resolved: Vec<_> = graph
                .packages
                .as_ref()
                .context("graph package inventory missing")?
                .iter()
                .filter(|p| p.name == "wasmtime")
                .collect();
            let consensus = graph.identity["kind"] == "consensus";
            ensure!(
                resolved.len() == usize::from(!consensus),
                "graph role does not match resolved Wasmtime dependencies"
            );
            versions.push(resolved.first().map(|p| p.version.clone()));
        }
        let vm: Vec<_> = versions.iter().flatten().collect();
        ensure!(
            vm.iter().collect::<BTreeSet<_>>().len() == vm.len()
                && vm.iter().map(|v| suffix(v)).collect::<BTreeSet<_>>().len() == vm.len(),
            "independent Wasmtime graphs must have unique versions and native prefixes"
        );
        let mut sets = Vec::<Names>::new();
        let mut inventory = Vec::new();
        for (graph, version) in graphs.iter().zip(&versions) {
            let mut names = Names::new();
            let mut inputs = Vec::new();
            for path in graph.paths()? {
                let symbols = self.inspector.definitions(path, true)?;
                for (name, value) in &symbols {
                    self.owner(name, graph, version.as_deref(), Some(path), Some(value))?;
                }
                names.extend(symbols.keys().cloned());
                inputs.push(json!({"path": path, "sha256": sha256(&self.cwd.join(path))?, "definitions": symbols}));
            }
            self.verify_psm(graph)?;
            for previous in &sets {
                let collisions: Vec<_> = names
                    .intersection(previous)
                    .filter(|n| !INPUT_RUNTIME.contains(&n.as_str()))
                    .take(100)
                    .collect();
                ensure!(
                    collisions.is_empty(),
                    "cross-graph definitions would coalesce: {collisions:?}"
                );
            }
            sets.push(names);
            inventory.push(json!({"graph": graph.graph, "inputs": inputs}));
        }
        Ok(json!({"sets": sets, "versions": versions, "inventory": inventory}))
    }

    #[allow(clippy::too_many_arguments)]
    fn final_audit(
        &self,
        executable: &Path,
        graphs: &[Graph],
        sets: &[Names],
        versions: &[Option<String>],
        common: &Owners,
        kind: Kind,
        node: &Owners,
    ) -> Result<Value> {
        ensure!(
            graphs.len() == sets.len() && graphs.len() == versions.len(),
            "final audit graph evidence lengths differ"
        );
        ensure!(
            kind != Kind::Proof || node.is_empty(),
            "proof final audit has unexpected node inputs"
        );
        let symbols = self.inspector.definitions(executable, true)?;
        let mut attributed = BTreeMap::<String, Value>::new();
        for (name, value) in &symbols {
            ensure!(
                value.address.is_some(),
                "final definition has no linked address: {name}"
            );
            let matches: Vec<_> = graphs
                .iter()
                .zip(sets)
                .filter(|(_, names)| names.contains(name))
                .map(|(graph, _)| &graph.graph)
                .collect();
            let owner = if name == GDB_SCRIPT {
                ensure!(
                    !matches.is_empty() || common.contains_key(name),
                    "unowned final compiler GDB metadata"
                );
                self.inspector.debug_metadata(executable, true)?;
                json!("common compiler debug metadata")
            } else if INPUT_RUNTIME.contains(&name.as_str())
                || FINAL_RUNTIME.contains(&name.as_str())
                || (cfg!(target_os = "macos") && name == "_mh_execute_header")
            {
                json!("common compiler/linker runtime")
            } else if matches.len() == 1 {
                json!(matches[0])
            } else if matches.is_empty() && common.contains_key(name) {
                json!({"common_inputs": common[name]})
            } else if kind == Kind::Executor && matches.is_empty() && node.contains_key(name) {
                json!({"node_inputs": node[name]})
            } else {
                bail!("ambiguous or unowned final definition: {name}: {matches:?}");
            };
            attributed.insert(name.clone(), attributed_symbol(value, owner));
        }
        let vm: Vec<_> = graphs
            .iter()
            .zip(sets)
            .zip(versions)
            .filter_map(|((graph, names), version)| {
                version.as_ref().map(|version| {
                    (
                        graph,
                        names,
                        format!("wasmtime_libunwind_{}", suffix(version)),
                    )
                })
            })
            .collect();
        let crypto: Vec<_> = graphs
            .iter()
            .flat_map(|graph| {
                CRYPTO
                    .iter()
                    .map(|name| format!("{}_{name}", graph.namespace))
            })
            .collect();
        let local = self.inspector.definitions(executable, false)?;
        let mut observed = Definitions::new();
        let mut local_inventory = None;
        if kind == Kind::Proof {
            ensure!(
                vm.iter().all(|(_, _, name)| symbols.contains_key(name)),
                "missing graph-private Wasmtime native helper"
            );
            ensure!(
                vm.iter()
                    .map(|(_, _, n)| &symbols[n].address)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == vm.len(),
                "Wasmtime graph-private helpers alias one address"
            );
            ensure!(
                crypto.iter().all(|n| local.contains_key(n)),
                "a required native crypto definition disappeared at final link"
            );
            ensure!(
                crypto
                    .iter()
                    .map(|n| &local[n].address)
                    .collect::<BTreeSet<_>>()
                    .len()
                    == crypto.len(),
                "independent native crypto helpers alias one address"
            );
            observed.extend(crypto.iter().map(|n| (n.clone(), local[n].clone())));
        } else {
            let (locals, inventory) = self.private_local(graphs)?;
            local_inventory = Some(inventory);
            let mut addresses = Vec::<BTreeSet<String>>::new();
            for ((graph, names), private) in graphs.iter().zip(sets).zip(locals) {
                let prefix = format!("{}_", graph.namespace);
                let current: Definitions = local
                    .iter()
                    .filter(|(n, _)| n.starts_with(&prefix))
                    .map(|(n, v)| (n.clone(), v.clone()))
                    .collect();
                let unowned: Vec<_> = current
                    .keys()
                    .filter(|n| {
                        !names.contains(*n) && (symbols.contains_key(*n) || !private.contains(*n))
                    })
                    .take(100)
                    .collect();
                ensure!(
                    unowned.is_empty(),
                    "unowned graph-private final definition: {unowned:?}"
                );
                let mut owned_addresses = BTreeSet::new();
                for (name, value) in &current {
                    owned_addresses.insert(value.address.clone().with_context(|| {
                        format!(
                            "graph-private final definition has no linked address: {}",
                            graph.graph
                        )
                    })?);
                    attributed
                        .entry(name.clone())
                        .or_insert_with(|| attributed_symbol(value, json!(graph.graph)));
                }
                ensure!(
                    addresses
                        .iter()
                        .all(|other| other.is_disjoint(&owned_addresses)),
                    "independent graph-private native definitions alias one address"
                );
                addresses.push(owned_addresses);
                observed.extend(current);
            }
            let mut helper_addresses = BTreeSet::new();
            let mut count = 0;
            for (graph, names, name) in &vm {
                if let Some(value) = local.get(name) {
                    ensure!(
                        names.contains(name) && value.address.is_some(),
                        "unowned graph-private Wasmtime native helper: {name}"
                    );
                    attributed
                        .entry(name.clone())
                        .or_insert_with(|| attributed_symbol(value, json!(graph.graph)));
                    helper_addresses.insert(value.address.clone());
                    count += 1;
                }
            }
            ensure!(
                helper_addresses.len() == count,
                "Wasmtime graph-private helpers alias one address"
            );
        }
        let helpers: BTreeMap<_, _> = vm
            .iter()
            .filter(|(_, _, n)| kind == Kind::Proof || local.contains_key(n))
            .map(|(_, _, n)| (n, &attributed[n]))
            .collect();
        let mut result = json!({"wasmtime": helpers, "crypto": crypto.iter().filter_map(|n| observed.get(n).map(|v| (n, v))).collect::<BTreeMap<_, _>>()});
        if kind == Kind::Executor {
            result["native"] = serde_json::to_value(observed)?;
        }
        Ok(json!({"result": result, "attributed": attributed, "local_inventory": local_inventory}))
    }
}

fn attributed_symbol(symbol: &Symbol, owner: Value) -> Value {
    json!({"address": symbol.address, "kind": symbol.kind, "owner": owner})
}

#[cfg(test)]
mod tests;
