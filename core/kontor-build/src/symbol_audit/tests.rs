use super::*;
use std::fs;
use tempfile::tempdir;

#[derive(Default)]
struct Fixture {
    globals: BTreeMap<PathBuf, Definitions>,
    locals: BTreeMap<PathBuf, Definitions>,
}
impl Inspector for Fixture {
    fn definitions(&self, path: &Path, global: bool) -> Result<Definitions> {
        Ok(if global { &self.globals } else { &self.locals }
            .get(path)
            .cloned()
            .unwrap_or_default())
    }
    fn debug_metadata(&self, _: &Path, _: bool) -> Result<()> {
        bail!("unverified fixture debug metadata")
    }
    fn members(&self, _: &Path) -> Result<Vec<String>> {
        bail!("unexpected archive fixture")
    }
    fn member(&self, _: &Path, _: &str) -> Result<Vec<u8>> {
        bail!("unexpected archive fixture")
    }
}
fn graphs() -> Vec<Graph> {
    serde_json::from_value(json!([
        {"graph":"first", "namespace":"kontor_first", "artifacts":[], "native_artifacts":[], "packages":[{"name":"wasmtime", "version":"51.0.0-dev"}]},
        {"graph":"second", "namespace":"kontor_second", "artifacts":[], "native_artifacts":[], "packages":[{"name":"wasmtime", "version":"51.0.0-kontor.1"}]}
    ])).unwrap()
}
fn symbol(address: Option<&str>, kind: &str) -> Symbol {
    Symbol {
        address: address.map(str::to_owned),
        kind: kind.into(),
    }
}
fn definitions(items: &[(&str, Option<&str>, &str)]) -> Definitions {
    items
        .iter()
        .map(|(name, address, kind)| (name.to_string(), symbol(*address, kind)))
        .collect()
}
fn names(items: &[&str]) -> Names {
    items.iter().map(|n| n.to_string()).collect()
}
fn versions() -> Vec<Option<String>> {
    vec![Some("51.0.0-dev".into()), Some("51.0.0-kontor.1".into())]
}

#[test]
fn parsing_keeps_bitcode_ownership_and_rejects_unknown_output() -> Result<()> {
    let output = "archive(member.o):\n---------------- T _RNvCs123_5probe5STATE\n0000 V weak\n U imported\n w optional\n v weak_object\n0000 u unused\n";
    let parsed = parse_definitions(output, false)?;
    assert_eq!(parsed.len(), 2);
    assert_eq!(parsed["_RNvCs123_5probe5STATE"].address, None);
    assert_eq!(
        parse_definitions("0000 T _darwin_name", true)?["darwin_name"].kind,
        "T"
    );
    for invalid in [
        "plugin failed to decode object",
        "?? T unknown",
        "0- T mixed",
        "U",
        "0 T too many fields",
    ] {
        assert!(parse_definitions(invalid, false).is_err());
    }
    Ok(())
}

#[test]
fn inputs_reject_collisions_namespaces_roles_and_normalized_versions() -> Result<()> {
    let dir = tempdir()?;
    let mut graphs = graphs();
    let mut fixture = Fixture::default();
    for graph in &mut graphs {
        let path = PathBuf::from(&graph.graph);
        fs::write(dir.path().join(&path), "fixture")?;
        graph.artifacts.as_mut().unwrap().push(Artifact {
            path: path.clone(),
            sha256: None,
        });
        fixture
            .globals
            .insert(path, definitions(&[("_RNvCs123_5probe5STATE", None, "T")]));
    }
    let audit = Audit {
        inspector: &fixture,
        cwd: dir.path(),
    };
    assert!(
        audit
            .inputs(&graphs)
            .unwrap_err()
            .to_string()
            .contains("would coalesce")
    );
    let mut invalid = graphs.clone();
    invalid[1].namespace = invalid[0].namespace.clone();
    assert!(
        audit
            .inputs(&invalid)
            .unwrap_err()
            .to_string()
            .contains("unique names")
    );
    invalid = graphs.clone();
    invalid[1].packages.as_mut().unwrap()[0].version = invalid[0].packages.as_ref().unwrap()[0]
        .version
        .replace('-', ".");
    assert!(
        audit
            .inputs(&invalid)
            .unwrap_err()
            .to_string()
            .contains("unique versions")
    );
    for graph in &mut graphs {
        graph.identity = json!({"kind":"consensus"});
    }
    assert!(
        audit
            .inputs(&graphs)
            .unwrap_err()
            .to_string()
            .contains("role does not match")
    );
    for graph in &mut graphs {
        graph.packages.as_mut().unwrap().clear();
    }
    assert!(
        audit
            .inputs(&graphs)
            .unwrap_err()
            .to_string()
            .contains("would coalesce")
    );
    for symbols in fixture.globals.values_mut() {
        *symbols = definitions(&[("DW.ref.rust_eh_personality", Some("0"), "V")]);
    }
    let audit = Audit {
        inspector: &fixture,
        cwd: dir.path(),
    };
    let result = audit.inputs(&graphs)?;
    assert_eq!(result["versions"], json!([null, null]));
    assert_eq!(
        result["sets"],
        json!([
            ["DW.ref.rust_eh_personality"],
            ["DW.ref.rust_eh_personality"]
        ])
    );
    Ok(())
}

#[test]
fn owner_exceptions_remain_narrow() -> Result<()> {
    let fixture = Fixture::default();
    let audit = Audit {
        inspector: &fixture,
        cwd: Path::new("."),
    };
    let graph = &graphs()[0];
    for name in [
        "__rust_alloc",
        "prefix__rust_realloc.llvm.42",
        "__rg_alloc_error_handler",
    ] {
        assert!(
            audit
                .owner(name, graph, None, None, None)
                .unwrap_err()
                .to_string()
                .contains("process allocator")
        );
    }
    for name in [
        "blst_keygen",
        "wasmtime_libunwind_51_0_0",
        "_ZNmissinghash",
        "__rust_allocator",
    ] {
        assert!(audit.owner(name, graph, None, None, None).is_err());
    }
    for name in [
        "_RNvCs123_5probe5STATE",
        "_ZN5probe5STATE17h1234567890abcdefE",
        "anon.1234abcd.0",
        "kontor_first_blst_keygen",
    ] {
        assert_eq!(audit.owner(name, graph, None, None, None)?, "first");
    }
    assert_eq!(
        audit.owner(
            "wasmtime_libunwind_51_0_0",
            graph,
            Some("51.0.0"),
            None,
            None
        )?,
        "first"
    );
    assert!(audit.owner(GDB_SCRIPT, graph, None, None, None).is_err());
    assert!(
        audit
            .owner(
                GDB_SCRIPT,
                graph,
                None,
                Some(Path::new("object")),
                Some(&symbol(Some("0"), "V"))
            )
            .is_err()
    );
    assert_eq!(suffix("51.0-é"), "51_0__");
    Ok(())
}

#[test]
fn final_requires_concrete_owners_and_linked_addresses() -> Result<()> {
    let fixture = Fixture {
        globals: BTreeMap::from([(PathBuf::from("node"), definitions(&[("_start", None, "T")]))]),
        ..Fixture::default()
    };
    let graphs = graphs();
    let sets = vec![Names::new(), Names::new()];
    let audit = Audit {
        inspector: &fixture,
        cwd: Path::new("."),
    };
    assert!(
        audit
            .final_audit(
                Path::new("node"),
                &graphs,
                &sets,
                &versions(),
                &Owners::new(),
                Kind::Executor,
                &Owners::new()
            )
            .unwrap_err()
            .to_string()
            .contains("no linked address")
    );
    let fixture = Fixture {
        globals: BTreeMap::from([(
            PathBuf::from("node"),
            definitions(&[("blst_keygen", Some("1000"), "T")]),
        )]),
        ..Fixture::default()
    };
    let audit = Audit {
        inspector: &fixture,
        cwd: Path::new("."),
    };
    assert!(
        audit
            .final_audit(
                Path::new("node"),
                &graphs,
                &sets,
                &versions(),
                &Owners::new(),
                Kind::Executor,
                &Owners::new()
            )
            .unwrap_err()
            .to_string()
            .contains("unowned final definition")
    );
    let node = Owners::from([("blst_keygen".into(), json!(["node/libblst.a"]))]);
    let result = audit.final_audit(
        Path::new("node"),
        &graphs,
        &sets,
        &versions(),
        &Owners::new(),
        Kind::Executor,
        &node,
    )?;
    assert_eq!(
        result["attributed"]["blst_keygen"]["owner"],
        json!({"node_inputs":["node/libblst.a"]})
    );
    assert!(
        audit
            .final_audit(
                Path::new("node"),
                &graphs,
                &sets,
                &versions(),
                &Owners::new(),
                Kind::Proof,
                &node
            )
            .is_err()
    );
    assert!(
        audit
            .final_audit(
                Path::new("node"),
                &graphs,
                &sets[..1],
                &versions(),
                &Owners::new(),
                Kind::Executor,
                &node
            )
            .is_err()
    );
    Ok(())
}

#[test]
fn executor_accepts_only_owned_private_subset_with_distinct_graph_addresses() -> Result<()> {
    let graphs = graphs();
    let sets = vec![
        names(&["kontor_first_blst_keygen"]),
        names(&["kontor_second_rustsecp256k1_v0_10_0_default_illegal_callback_fn"]),
    ];
    let mut fixture = Fixture::default();
    let first = "kontor_first_blst_keygen";
    let second = "kontor_second_rustsecp256k1_v0_10_0_default_illegal_callback_fn";
    fixture.locals.insert(
        "node".into(),
        definitions(&[(first, Some("1000"), "t"), (second, Some("2000"), "t")]),
    );
    let audit = Audit {
        inspector: &fixture,
        cwd: Path::new("."),
    };
    let result = audit.final_audit(
        Path::new("node"),
        &graphs,
        &sets,
        &versions(),
        &Owners::new(),
        Kind::Executor,
        &Owners::new(),
    )?;
    assert_eq!(result["result"]["native"].as_object().unwrap().len(), 2);
    assert_eq!(result["attributed"][first]["owner"], "first");
    assert_eq!(result["attributed"][second]["owner"], "second");
    assert!(
        audit
            .final_audit(
                Path::new("node"),
                &graphs,
                &sets,
                &versions(),
                &Owners::new(),
                Kind::Proof,
                &Owners::new()
            )
            .unwrap_err()
            .to_string()
            .contains("missing graph-private")
    );
    for (changed, message) in [
        (
            definitions(&[(first, Some("1000"), "t"), (second, Some("1000"), "t")]),
            "alias one address",
        ),
        (
            definitions(&[("kontor_first_unknown", Some("1000"), "t")]),
            "unowned graph-private",
        ),
        (definitions(&[(first, None, "t")]), "no linked address"),
    ] {
        fixture.locals.insert("node".into(), changed);
        let audit = Audit {
            inspector: &fixture,
            cwd: Path::new("."),
        };
        assert!(
            audit
                .final_audit(
                    Path::new("node"),
                    &graphs,
                    &sets,
                    &versions(),
                    &Owners::new(),
                    Kind::Executor,
                    &Owners::new()
                )
                .unwrap_err()
                .to_string()
                .contains(message)
        );
    }
    Ok(())
}

#[test]
fn mixed_graph_helper_uses_actual_graph_and_local_input_cannot_become_global() -> Result<()> {
    let dir = tempdir()?;
    fs::write(dir.path().join("input"), "fixture")?;
    let mut graphs = graphs();
    graphs[0].identity = json!({"kind":"consensus"});
    graphs[0].packages.as_mut().unwrap().clear();
    graphs[0].artifacts.as_mut().unwrap().push(Artifact {
        path: "input".into(),
        sha256: Some(sha256(&dir.path().join("input"))?),
    });
    let helper = "wasmtime_libunwind_51_0_0";
    let local = "kontor_first_static";
    let public = "kontor_first_public";
    let mut fixture = Fixture::default();
    fixture
        .globals
        .insert("node".into(), definitions(&[(helper, Some("1000"), "T")]));
    fixture.locals.insert(
        "node".into(),
        definitions(&[(helper, Some("1000"), "T"), (local, Some("2000"), "t")]),
    );
    fixture
        .globals
        .insert("input".into(), definitions(&[(public, Some("0"), "T")]));
    fixture.locals.insert(
        "input".into(),
        definitions(&[(public, Some("0"), "T"), (local, Some("10"), "t")]),
    );
    let sets = vec![names(&[public]), names(&[helper])];
    let versions = vec![None, Some("51.0.0".into())];
    let audit = Audit {
        inspector: &fixture,
        cwd: dir.path(),
    };
    let (locals, _) = audit.private_local(&graphs)?;
    assert_eq!(locals[0], names(&[local]));
    let result = audit.final_audit(
        Path::new("node"),
        &graphs,
        &sets,
        &versions,
        &Owners::new(),
        Kind::Executor,
        &Owners::new(),
    )?;
    assert_eq!(result["result"]["wasmtime"][helper]["owner"], "second");
    fixture
        .globals
        .get_mut(Path::new("node"))
        .unwrap()
        .insert(local.into(), symbol(Some("2000"), "T"));
    let audit = Audit {
        inspector: &fixture,
        cwd: dir.path(),
    };
    assert!(
        audit
            .final_audit(
                Path::new("node"),
                &graphs,
                &sets,
                &versions,
                &Owners::from([(local.into(), json!(["host"]))]),
                Kind::Executor,
                &Owners::new()
            )
            .unwrap_err()
            .to_string()
            .contains("unowned graph-private")
    );
    fs::write(dir.path().join("input"), "changed")?;
    assert!(
        audit
            .private_local(&graphs)
            .unwrap_err()
            .to_string()
            .contains("staged graph input changed")
    );
    Ok(())
}

#[test]
fn proof_requires_all_native_helpers_with_distinct_addresses() -> Result<()> {
    let graphs = graphs();
    let mut fixture = Fixture::default();
    let mut globals = Definitions::new();
    let mut locals = Definitions::new();
    let mut sets = Vec::new();
    for (index, graph) in graphs.iter().enumerate() {
        let helper = format!(
            "wasmtime_libunwind_{}",
            suffix(&graph.packages.as_ref().unwrap()[0].version)
        );
        globals.insert(helper.clone(), symbol(Some(&format!("{index}000")), "T"));
        sets.push(names(&[&helper]));
        for (j, name) in CRYPTO.iter().enumerate() {
            locals.insert(
                format!("{}_{name}", graph.namespace),
                symbol(Some(&format!("{index}10{j}")), "t"),
            );
        }
    }
    locals.extend(globals.clone());
    fixture.globals.insert("node".into(), globals);
    fixture.locals.insert("node".into(), locals);
    let audit = Audit {
        inspector: &fixture,
        cwd: Path::new("."),
    };
    let result = audit.final_audit(
        Path::new("node"),
        &graphs,
        &sets,
        &versions(),
        &Owners::new(),
        Kind::Proof,
        &Owners::new(),
    )?;
    assert_eq!(result["result"]["wasmtime"].as_object().unwrap().len(), 2);
    assert_eq!(result["result"]["crypto"].as_object().unwrap().len(), 8);
    fixture
        .locals
        .get_mut(Path::new("node"))
        .unwrap()
        .get_mut("kontor_second_blst_keygen")
        .unwrap()
        .address = Some("0100".into());
    let audit = Audit {
        inspector: &fixture,
        cwd: Path::new("."),
    };
    assert!(
        audit
            .final_audit(
                Path::new("node"),
                &graphs,
                &sets,
                &versions(),
                &Owners::new(),
                Kind::Proof,
                &Owners::new()
            )
            .unwrap_err()
            .to_string()
            .contains("crypto helpers alias")
    );
    Ok(())
}

#[test]
fn inventory_operations_reject_missing_fields_without_breaking_minimal_owner_requests() -> Result<()>
{
    let fixture = Fixture::default();
    let audit = Audit {
        inspector: &fixture,
        cwd: Path::new("."),
    };
    let complete = json!({"graph":"consensus", "namespace":"kontor_consensus", "identity":{"kind":"consensus"}, "packages":[], "artifacts":[], "native_artifacts":[]});
    for field in ["packages", "artifacts", "native_artifacts"] {
        for missing in [true, false] {
            let mut value = complete.clone();
            if missing {
                value.as_object_mut().unwrap().remove(field);
            } else {
                value[field] = Value::Null;
            }
            let graph: Graph = serde_json::from_value(value)?;
            assert!(
                audit.inputs(std::slice::from_ref(&graph)).is_err(),
                "accepted absent {field}"
            );
            if field != "packages" {
                assert!(audit.private_local(std::slice::from_ref(&graph)).is_err());
                assert!(
                    audit
                        .final_audit(
                            Path::new("node"),
                            &[graph],
                            &[Names::new()],
                            &[None],
                            &Owners::new(),
                            Kind::Executor,
                            &Owners::new()
                        )
                        .is_err()
                );
            }
        }
    }
    let minimal: Graph =
        serde_json::from_value(json!({"graph":"first", "namespace":"kontor_first"}))?;
    for identity in [Value::Null, json!([]), json!("consensus")] {
        let mut graph = graphs().remove(0);
        graph.identity = identity;
        assert!(audit.inputs(&[graph]).is_err());
    }
    assert_eq!(
        audit.owner("kontor_first_entry", &minimal, None, None, None)?,
        "first"
    );
    Ok(())
}
