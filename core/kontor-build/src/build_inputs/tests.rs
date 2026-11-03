use super::*;
use crate::recipes::{consensus_graphs, executor_graphs, proof_graphs};
use tempfile::tempdir;

fn repository() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_owned()
}
fn metadata(root: &Path, recipe: &Graph) -> Value {
    let mut packages =
        vec![json!({"id":"root", "name":"fixture", "version":"0.1.0", "source":null})];
    if let Some(version) = &recipe.version {
        packages.push(json!({"id":"vm", "name":"wasmtime", "version":version,
            "source":format!("git+fixture#{}", recipe.revision.as_ref().unwrap())}));
    }
    if recipe.malachite_engine {
        for name in [
            "arc-malachitebft-app-channel",
            "arc-malachitebft-signing",
            "if-watch",
        ] {
            packages.push(json!({"id":name, "name":name, "version":if name=="if-watch" {"3.2.2"} else {MALACHITE_VERSION},
                "source":format!("git+fixture#{MALACHITE_REVISION}")}));
        }
    }
    if let Some(itoa) = &recipe.itoa {
        packages.push(json!({"id":"itoa", "name":"itoa", "version":itoa, "source":null}));
    }
    for name in &recipe.native_patches {
        packages.push(json!({"id":name, "name":name, "version":"0", "source":null,
            "manifest_path":root.join("core/vendor").join(name).join("Cargo.toml")}));
    }
    let deps: Vec<_> = packages
        .iter()
        .skip(1)
        .map(|p| json!({"pkg":p["id"]}))
        .collect();
    let nodes: Vec<_> = packages
        .iter()
        .map(|p| {
            json!({"id":p["id"], "features":[],
        "deps":if p["id"]=="root" {deps.clone()} else {vec![]}})
        })
        .collect();
    json!({"packages":packages, "resolve":{"root":"root", "nodes":nodes}})
}
fn check(recipe: &Graph, data: Value) -> Result<Value> {
    identities(&repository(), recipe, &serde_json::from_value(data)?)
}
#[test]
fn resolved_roles_require_pins_patches_features_and_conflicting_proof_dependencies() -> Result<()> {
    for graphs in [proof_graphs(), executor_graphs(None)?, consensus_graphs()] {
        for recipe in graphs.values() {
            let original = metadata(&repository(), recipe);
            check(recipe, original.clone())?;
            for index in 1..original["packages"].as_array().unwrap().len() {
                let mut changed = original.clone();
                let package = &mut changed["packages"][index];
                package["source"] = json!("git+substituted#wrong");
                package["version"] = json!("wrong");
                package["manifest_path"] = json!("/unpatched/Cargo.toml");
                // Signing's identity is checked for consensus; proof retains its
                // historical app-channel and if-watch revision checks.
                if recipe.kind == Kind::Proof && package["name"] == "arc-malachitebft-signing" {
                    continue;
                }
                assert!(check(recipe, changed).is_err());
            }
            if recipe.version.is_some() {
                for feature in ["cache", "profiling", "debug-builtins"] {
                    let mut changed = original.clone();
                    changed["resolve"]["nodes"][1]["features"] = json!([feature]);
                    assert!(check(recipe, changed).is_err());
                }
            }
        }
    }
    Ok(())
}
#[test]
fn reachable_closure_rejects_node_services_and_ambiguous_or_missing_nodes() -> Result<()> {
    let executor = executor_graphs(None)?.remove("first").unwrap();
    let consensus = consensus_graphs().remove("first").unwrap();
    for (recipe, forbidden) in [
        (
            &executor,
            vec!["libsql", "arc-malachitebft-app-channel", "if-watch", "ring"],
        ),
        (&consensus, vec!["wasmtime", "libsql"]),
    ] {
        for name in forbidden {
            let mut data = metadata(&repository(), recipe);
            data["packages"].as_array_mut().unwrap().push(
                json!({"id":"extra", "name":name, "version":"0", "source":null,
                "manifest_path":"/unpatched/Cargo.toml"}),
            );
            data["resolve"]["nodes"]
                .as_array_mut()
                .unwrap()
                .push(json!({"id":"extra", "features":[], "deps":[]}));
            check(recipe, data.clone())?;
            data["resolve"]["nodes"][0]["deps"]
                .as_array_mut()
                .unwrap()
                .push(json!({"pkg":"extra"}));
            assert!(check(recipe, data).is_err());
        }
    }
    let original = metadata(&repository(), &executor);
    for field in ["packages", "nodes"] {
        let mut data = original.clone();
        let items = if field == "packages" {
            &mut data["packages"]
        } else {
            &mut data["resolve"]["nodes"]
        };
        let item = items[0].clone();
        items.as_array_mut().unwrap().push(item);
        assert!(check(&executor, data).is_err());
    }
    let mut data = original.clone();
    data["resolve"]["nodes"].as_array_mut().unwrap().pop();
    assert!(check(&executor, data).is_err());
    let mut data = original.clone();
    data["packages"].as_array_mut().unwrap().pop();
    assert!(check(&executor, data).is_err());
    let mut data = original.clone();
    data["packages"][0]
        .as_object_mut()
        .unwrap()
        .remove("source");
    assert!(check(&executor, data).is_err());
    let expected = check(&executor, original.clone())?;
    let mut data = original;
    data["resolve"]["nodes"][1]["deps"] = json!([{"pkg":"root"}]);
    data["packages"].as_array_mut().unwrap().reverse();
    data["resolve"]["nodes"].as_array_mut().unwrap().reverse();
    assert_eq!(check(&executor, data)?, expected);
    Ok(())
}
#[test]
fn capability_guard_checks_actual_sources_and_rejects_enable_omit_duplicate_and_facade_changes()
-> Result<()> {
    capabilities(&repository())?;
    let calls: Vec<_> = DISABLED
        .iter()
        .map(|name| format!("config.{name}(false);"))
        .collect();
    settings(&calls.join("\n"))?;
    for index in 0..calls.len() {
        let mut changed = calls.clone();
        changed[index] = changed[index].replace("false", "true");
        assert!(settings(&changed.join("\n")).is_err());
        let mut changed = calls.clone();
        changed.remove(index);
        assert!(settings(&changed.join("\n")).is_err());
        let mut changed = calls.clone();
        changed.push(calls[index].clone());
        assert!(settings(&changed.join("\n")).is_err());
    }
    let dir = tempdir()?;
    for relative in [
        "core/indexer/src/runtime/mod.rs",
        "core/indexer/src/protocol/v1/engine.rs",
        "protocol-bundles/proof/vm.rs",
    ] {
        let path = dir.path().join(relative);
        fs::create_dir_all(path.parent().unwrap())?;
        fs::copy(repository().join(relative), path)?;
    }
    capabilities(dir.path())?;
    for relative in [
        "core/indexer/src/protocol/v1/engine.rs",
        "protocol-bundles/proof/vm.rs",
        "core/indexer/src/runtime/mod.rs",
    ] {
        let path = dir.path().join(relative);
        let original = fs::read_to_string(&path)?;
        let changed = if relative.ends_with("mod.rs") {
            original.replace("engine::new_engine()", "other::new_engine()")
        } else {
            original.replace("wasm_threads(false)", "wasm_threads(true)")
        };
        fs::write(&path, changed)?;
        assert!(capabilities(dir.path()).is_err());
        fs::write(path, original)?;
    }
    Ok(())
}
#[test]
fn cargo_artifacts_use_only_current_target_and_require_one_facade() -> Result<()> {
    let dir = tempdir()?;
    let log = dir.path().join("cargo.log");
    let target = dir.path().join("target");
    let facade = target.join("triple/debug/libmy_bundle.rlib");
    let dependency = target.join("triple/debug/libdep.rlib");
    let macro_path = target.join("debug/libmacro.so");
    let native = json!({"reason":"build-script-executed","out_dir":target.join("triple/debug/build/pkg/out"),"linked_libs":["static=owned"]});
    let artifact = |name: &str, kind: &str, files: Vec<PathBuf>| json!({"reason":"compiler-artifact", "target":{"name":name,"kind":[kind]}, "filenames":files});
    let values = [
        artifact("my_bundle", "lib", vec![facade.clone(), dependency.clone()]),
        artifact(
            "my_bundle",
            "lib",
            vec![target.join("other/debug/libmy_bundle.rlib")],
        ),
        artifact(
            "macro",
            "proc-macro",
            vec![macro_path.clone(), target.join("debug/libmacro.rmeta")],
        ),
        native.clone(),
        json!({"reason":"build-script-executed","out_dir":target.join("debug/build/pkg/out")}),
    ];
    let lines = values
        .iter()
        .map(Value::to_string)
        .collect::<Vec<_>>()
        .join("\n");
    fs::write(&log, format!("not JSON\n42\n{lines}\n"))?;
    // A package target's multiple rlibs are ambiguous, even within one message.
    assert!(current_artifacts(&log, &target, "triple", "my-bundle").is_err());
    let lines = lines.replace(&format!(",{}", json!(dependency)), "");
    fs::write(&log, &lines)?;
    let report = current_artifacts(&log, &target, "triple", "my-bundle")?;
    assert_eq!(report["facade"], json!(facade));
    assert_eq!(report["proc_macros"], json!([macro_path]));
    assert_eq!(report["native_outputs"], json!([native]));
    assert!(current_artifacts(&log, &target, "triple", "missing").is_err());
    fs::write(
        &log,
        "{\"reason\":\"compiler-artifact\",\"filenames\":null}\n",
    )?;
    assert!(current_artifacts(&log, &target, "triple", "my-bundle").is_err());
    Ok(())
}
