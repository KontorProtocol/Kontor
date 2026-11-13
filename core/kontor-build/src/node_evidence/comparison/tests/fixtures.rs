use super::*;
use crate::interface::{Request as InterfaceRequest, inputs_for, run as interface};
use crate::node_evidence::runner::tests::sample;
use crate::provenance::{package_sources, repository_sources};
use tempfile::{TempDir, tempdir};

pub fn inventory(source_root: &Path, kind: GraphKind, graph_directory: &str) -> Result<Value> {
    let root = root();
    let mut inherited = BTreeMap::new();
    for relative in [
        "core/Cargo.toml".into(),
        "core/numerics/Cargo.toml".into(),
        format!("protocol-bundles/{graph_directory}/Cargo.toml"),
    ] {
        inherited.insert(
            format!("/fixture/{relative}"),
            sha256(&source_root.join(relative))?,
        );
    }
    inherited.insert(
        "/cargo/git/checkouts/wasmtime/crates/core/Cargo.toml".into(),
        "external workspace".into(),
    );
    let mut value = json!({"qualification_sources":repository_sources(source_root,kind)?,"rust_build_tools":package_sources(&root.join("core/kontor-build"),Some(&root))?,
        "packages":[{"package":"path+file://<repository>/core/numerics#0.1.0","files":package_sources(&source_root.join("core/numerics"),Some(source_root))?}],
        "inherited_manifests_and_configuration":inherited});
    if source_root != root {
        value["build_tools"] = json!(package_sources(
            &root.join("tools/protocol-bundles"),
            Some(&root)
        )?);
    }
    Ok(value)
}
fn controls(graphs: &[Value], directory: &Path, target: &str) -> Result<Value> {
    fs::create_dir_all(directory)?;
    let probes = interface(InterfaceRequest::Probes {
        graphs: graphs.to_vec(),
    })?;
    let mut controls = BTreeMap::new();
    let mut names = vec![];
    for probe in probes.as_array().unwrap() {
        let name = probe[0].as_str().unwrap();
        let expected = &probe[1];
        fs::write(
            directory.join(format!("{name}.rs")),
            probe[2].as_str().unwrap(),
        )?;
        fs::write(
            directory.join(format!("{name}.log")),
            if expected.is_null() {
                String::new()
            } else {
                json!({"level":"error","code":{"code":expected}}).to_string()
            },
        )?;
        controls.insert(name,json!({"expected_error":expected,"returncode":if expected.is_null(){0}else{1},"source_sha256":sha256(&directory.join(format!("{name}.rs")))?,"diagnostics_sha256":sha256(&directory.join(format!("{name}.log")))?}));
        names.push(name);
    }
    write_json(
        &directory.join("result.json"),
        &json!({"schema":1,"status":"passed","target":target,"libraries":inputs_for(graphs,false,&root())?.1,"graph_inputs":graph_inputs(graphs)?,"controls":controls}),
    )?;
    Ok(json!({"report_sha256":sha256(&directory.join("result.json"))?,"controls":names}))
}
fn graph_inputs(graphs: &[Value]) -> Result<Value> {
    Ok(json!(
        graphs
            .iter()
            .map(|g| Ok((text(g, "graph")?, fingerprint(g)?)))
            .collect::<Result<BTreeMap<_, _>>>()?
    ))
}
pub struct Archive {
    pub temporary: TempDir,
    pub cells: Vec<PathBuf>,
    pub link: Option<&'static str>,
}
impl Archive {
    pub fn new(link: Option<&'static str>) -> Result<Self> {
        let mut result = Self {
            temporary: tempdir()?,
            cells: vec![],
            link,
        };
        for target in TARGETS {
            let cell = result.cell(target, "release")?;
            result.cells.push(cell);
        }
        Ok(result)
    }
    pub fn compare(&self, profiles: &str) -> Result<Value> {
        compare(
            self.temporary.path(),
            &root(),
            profiles,
            "success",
            self.link,
        )
    }
    pub fn cell(&self, target: &str, profile: &str) -> Result<PathBuf> {
        let root = root();
        let directory = self
            .temporary
            .path()
            .join(format!("{target}-{profile}"))
            .join("executors")
            .join(self.link.unwrap_or("default"));
        let node_dir = directory.join("node");
        fs::create_dir_all(&node_dir)?;
        let recipes = executor_graphs(self.link)?;
        let consensus_recipes = consensus_graphs();
        let mut graphs = vec![];
        let mut consensus = vec![];
        let entries = recipes
            .iter()
            .map(|(name, recipe)| ("executor", name, recipe, &recipes))
            .chain(
                consensus_recipes
                    .iter()
                    .filter(|_| self.link == Some("managed-node"))
                    .map(|(name, recipe)| ("consensus", name, recipe, &consensus_recipes)),
            );
        for (role, name, recipe, selected) in entries {
            let graph_dir = if role == "consensus" {
                directory
                    .ancestors()
                    .nth(2)
                    .unwrap()
                    .join("consensus")
                    .join(name)
            } else {
                directory.join(name)
            };
            fs::create_dir_all(&graph_dir)?;
            let source_root = graph_root(&root, recipe)?;
            let source = inventory(
                &source_root,
                if role == "consensus" {
                    GraphKind::Consensus
                } else {
                    GraphKind::Executor
                },
                &recipe.directory,
            )?;
            write_json(&graph_dir.join("source-inputs.json"), &source)?;
            fs::write(graph_dir.join("build.log"), "synthetic build transcript")?;
            let id = identity(&root, name, selected)?;
            let facade = format!("/synthetic/{role}/{name}/libkontor_{role}_{name}.rlib");
            let mut paths = vec![
                facade.clone(),
                format!("/synthetic/{role}/{name}/libtokio-test.rlib"),
            ];
            if role == "executor" {
                paths.push(format!("/synthetic/{role}/{name}/libwasmtime-test.rlib"));
            }
            let graph = json!({"graph":name,"identity":id,"lock_sha256":id["lock_sha256"],"manifest_sha256":id["manifest_sha256"],"source_inputs_sha256":fingerprint(&source)?,
                "build_log_sha256":sha256(&graph_dir.join("build.log"))?,"wrapper_sha256":sha256(&root.join("core/kontor-build/src/bin/kontor-graph-rustc.rs"))?,
                "wrapper_binary_sha256":"ab".repeat(32),"wrapper":format!("/synthetic/compiler-wrapper/{}/kontor-graph-rustc","ab".repeat(32)),
                "link_inputs":format!("/synthetic/{role}/{name}"),"facade":facade,"artifacts":paths.iter().map(|path|json!({"path":path,"sha256":format!("synthetic-{path}")})).collect::<Vec<_>>()});
            write_json(&graph_dir.join("build-inputs.json"), &graph)?;
            if role == "consensus" {
                consensus.push(graph)
            } else {
                graphs.push(graph)
            };
        }
        let source = inventory(&root, GraphKind::Node, "node")?;
        write_json(&node_dir.join("source-inputs.json"), &source)?;
        fs::write(node_dir.join("build.log"), "synthetic node transcript")?;
        let linker_sources = [
            "core/kontor-build/src/bin/kontor-node-linker.rs",
            "core/kontor-build/src/linker_record.rs",
        ]
        .into_iter()
        .map(|path| Ok((path, sha256(&root.join(path))?)))
        .collect::<Result<BTreeMap<_, _>>>()?;
        let mut node = json!({"qualification_command":true,"executable_sha256":"ef".repeat(32),"installed":{"sha256":"ef".repeat(32)},"source_inputs_sha256":fingerprint(&source)?,
            "lock_sha256":sha256(&root.join("protocol-bundles/node/Cargo.lock"))?,"build_log_sha256":sha256(&node_dir.join("build.log"))?,
            "wrapper_sha256":sha256(&root.join("core/kontor-build/src/bin/kontor-node-rustc.rs"))?,"wrapper_binary_sha256":"bc".repeat(32),"linker_wrapper_binary_sha256":"cd".repeat(32),"linker_wrapper_sha256":fingerprint(&json!(linker_sources))?});
        let linked = graphs
            .iter()
            .map(|g| ("executor", g))
            .chain(consensus.iter().map(|g| ("consensus", g)))
            .map(|(role, g)| {
                Ok(json!({"role":role,"graph":g["graph"],"build_inputs_sha256":fingerprint(g)?}))
            })
            .collect::<Result<Vec<_>>>()?;
        let spec = json!({"features":["protocol-qualification"],"lock_sha256":node["lock_sha256"],"link_set":self.link,"source_inputs_sha256":node["source_inputs_sha256"],"graphs":linked,
            "linker_wrapper_sha256":node["linker_wrapper_binary_sha256"],"linker_wrapper":format!("/synthetic/compiler-wrapper/{}/kontor-node-linker","cd".repeat(32))});
        write_json(&node_dir.join("link-spec.json"), &spec)?;
        node["wrapper"] = json!(format!(
            "/synthetic/rustc-wrapper-{}-{}",
            fingerprint(&spec)?,
            node["wrapper_binary_sha256"].as_str().unwrap()
        ));
        node["link_spec_sha256"] = json!(sha256(&node_dir.join("link-spec.json"))?);
        let link = json!({"schema":1,"spec_sha256":node["link_spec_sha256"],"output_sha256":node["executable_sha256"],"output":"/synthetic/kontor","arguments":["-o","/synthetic/kontor"],"expanded_arguments":["-o","/synthetic/kontor"],"working_directory":"/synthetic",
            "driver":{"invocation_path":"/synthetic/cc","path":"/synthetic/cc","sha256":"ab".repeat(32)},"backend":{"invocation_path":"/synthetic/ld","path":"/synthetic/ld","sha256":"cd".repeat(32)},
            "selection":{"method":"compiler-driver-plan","command":["/synthetic/cc","-###","-o","/synthetic/kontor"],"stderr":"synthetic driver plan"}});
        write_json(&node_dir.join("linker-record.json"), &link)?;
        node["linker_record_sha256"] = json!(sha256(&node_dir.join("linker-record.json"))?);
        write_json(
            &node_dir.join("root-objects.json"),
            &json!({"spec_sha256":node["link_spec_sha256"],"linker_record_sha256":node["linker_record_sha256"],"compiler_output":{"path":link["output"],"sha256":node["executable_sha256"]}}),
        )?;
        node["root_codegen_sha256"] = json!(sha256(&node_dir.join("root-objects.json"))?);
        node["ownership"] = json!({});
        for name in OWNERSHIP {
            write_json(&node_dir.join(name), &json!({"synthetic":name}))?;
            node["ownership"][*name] = json!(sha256(&node_dir.join(name))?);
        }
        node["interface_checks"] = controls(&graphs, &node_dir.join("type-boundary"), target)?;
        if !consensus.is_empty() {
            node["consensus_interface_checks"] = controls(
                &consensus,
                &node_dir.join("consensus/type-boundary"),
                target,
            )?;
            let adapter = node_dir.join("consensus/node-adapter");
            fs::create_dir_all(&adapter)?;
            fs::write(
                adapter.join("adapter.rs"),
                "mod managed {\n#[path = \"/fixture/core/indexer/src/protocol/coordinator/managed/types.rs\"]\npub(crate) mod types;\n#[path = \"/fixture/core/indexer/src/protocol/coordinator/managed/adapter.rs\"]\npub(crate) mod adapter;\n}\n",
            )?;
            fs::write(adapter.join("compile.log"), "synthetic successful compile")?;
            let tests = interface(InterfaceRequest::Catalog)?["adapter_tests"].clone();
            let tests_array = tests.as_array().unwrap();
            fs::write(
                adapter.join("test.log"),
                format!(
                    "{}\ntest result: ok. {} passed; 0 failed; 0 ignored;",
                    tests_array
                        .iter()
                        .map(|name| format!("test {} ... ok", name.as_str().unwrap()))
                        .collect::<Vec<_>>()
                        .join("\n"),
                    tests_array.len()
                ),
            )?;
            node["consensus_adapter_checks"] = json!({"tests":tests,"source_sha256":sha256(&adapter.join("adapter.rs"))?,"compiler_log_sha256":sha256(&adapter.join("compile.log"))?,"test_log_sha256":sha256(&adapter.join("test.log"))?,"libraries":inputs_for(&consensus,false,&root)?.1,"graph_inputs":graph_inputs(&consensus)?});
        }
        let compiler = format!(
            "rustc {TOOLCHAIN}\nrelease: {TOOLCHAIN}\nhost: {target}\ncommit-hash: test-commit\nLLVM version: test-llvm\n"
        );
        write_json(
            &directory.join("node-build.json"),
            &json!({"target":target,"profile":profile,"compiler":compiler,"toolchain_inputs":{"compiler":compiler},"link_set":self.link,"node":node,"graphs":graphs,"consensus_graphs":consensus}),
        )?;
        let observations = sample(self.link)?;
        write_json(&directory.join("node-execution.stdout.json"), &observations)?;
        fs::write(
            directory.join("node-execution.stderr.log"),
            "synthetic execution log",
        )?;
        let mut execution = json!({"schema":1,"matching_observations":true,"target":target,"profile":profile,"link_set":self.link,"executable_sha256":node["executable_sha256"],"cases":observations["cases"],"graphs":recipes.keys().collect::<Vec<_>>(),"semantic_baseline":semantics::verify(&observations,&root,&baseline_graphs(self.link)?,self.link)?});
        if self.link == Some("managed-node") {
            for name in ["transition", "recovery", "authorization", "join"] {
                fs::copy(
                    Path::new(env!("CARGO_MANIFEST_DIR"))
                        .join("tests/fixtures/node-evidence")
                        .join(format!("{name}.json")),
                    directory.join(format!("node-{name}.stdout.json")),
                )?;
                fs::write(
                    directory.join(format!("node-{name}.stderr.log")),
                    "synthetic lifecycle log",
                )?;
                execution[name] = json!({"stdout_sha256":sha256(&directory.join(format!("node-{name}.stdout.json")))?,"stderr_sha256":sha256(&directory.join(format!("node-{name}.stderr.log")))?});
            }
        }
        write_json(&directory.join("node-execution.json"), &execution)?;
        bind(&directory)?;
        Ok(directory)
    }
}
pub fn bind(directory: &Path) -> Result<()> {
    let mut execution = read(&directory.join("node-execution.json"))?;
    for (key, name) in [
        ("node_build_sha256", "node-build.json"),
        ("stdout_sha256", "node-execution.stdout.json"),
        ("stderr_sha256", "node-execution.stderr.log"),
    ] {
        execution[key] = json!(sha256(&directory.join(name))?);
    }
    write_json(&directory.join("node-execution.json"), &execution)
}
pub fn change(path: &Path, update: impl FnOnce(&mut Value)) -> Result<()> {
    let mut value = read(path)?;
    update(&mut value);
    write_json(path, &value)
}
pub fn rejects(archive: &Archive, expected: &str) {
    let error = format!("{:#}", archive.compare("release").unwrap_err());
    assert!(error.contains(expected), "expected {expected}, got {error}");
}

pub fn rebind_source(directory: &Path, source: &Value) -> Result<()> {
    let node = directory.join("node");
    write_json(&node.join("source-inputs.json"), source)?;
    let hash = fingerprint(source)?;
    let mut build = read(&directory.join("node-build.json"))?;
    build["node"]["source_inputs_sha256"] = json!(hash);
    change(&node.join("link-spec.json"), |v| {
        v["source_inputs_sha256"] = json!(hash)
    })?;
    let spec = read(&node.join("link-spec.json"))?;
    build["node"]["wrapper"] = json!(format!(
        "/synthetic/rustc-wrapper-{}-{}",
        fingerprint(&spec)?,
        build["node"]["wrapper_binary_sha256"].as_str().unwrap()
    ));
    let spec_hash = sha256(&node.join("link-spec.json"))?;
    build["node"]["link_spec_sha256"] = json!(spec_hash);
    change(&node.join("linker-record.json"), |v| {
        v["spec_sha256"] = json!(spec_hash)
    })?;
    let link_hash = sha256(&node.join("linker-record.json"))?;
    build["node"]["linker_record_sha256"] = json!(link_hash);
    change(&node.join("root-objects.json"), |v| {
        v["spec_sha256"] = json!(spec_hash);
        v["linker_record_sha256"] = json!(link_hash);
    })?;
    build["node"]["root_codegen_sha256"] = json!(sha256(&node.join("root-objects.json"))?);
    write_json(&directory.join("node-build.json"), &build)?;
    bind(directory)
}
