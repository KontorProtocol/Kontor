use super::compile;
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{Result, ensure};
#[cfg(target_os = "linux")]
use kontor_build::object_tools::GDB_SCRIPT;
use kontor_build::object_tools::ObjectTools;
use kontor_build::shared_ownership::run as audit_shared;
use kontor_build::symbol_audit::{parse_definitions, run as audit_symbols};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn symbols(root: &Path, operation: &str, mut values: Value) -> Result<Value> {
    values["operation"] = json!(operation);
    values["working_directory"] = json!(root);
    audit_symbols(serde_json::from_value(values)?)
}
fn shared(root: &Path, operation: &str, mut values: Value) -> Result<Value> {
    values["operation"] = json!(operation);
    values["working_directory"] = json!(root);
    audit_shared(serde_json::from_value(values)?)
}
fn graphs() -> Value {
    json!([
        {"graph":"first","namespace":"kontor_first","packages":[{"name":"wasmtime","version":"51.0.0-dev"}],"artifacts":[],"native_artifacts":[]},
        {"graph":"second","namespace":"kontor_second","packages":[{"name":"wasmtime","version":"51.0.0-kontor.1"}],"artifacts":[],"native_artifacts":[]}
    ])
}
fn hash(path: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(fs::read(path)?)))
}
fn native(symbol: &str) -> String {
    format!(
        "{}{symbol}",
        if cfg!(target_os = "macos") { "_" } else { "" }
    )
}
fn archive(root: &Path, name: &str, object: &Path) -> Result<PathBuf> {
    let path = root.join(name);
    if path.exists() {
        fs::remove_file(&path)?;
    }
    ensure!(
        Command::new("ar")
            .arg("crs")
            .arg(&path)
            .arg(object)
            .status()?
            .success(),
        "archive fixture"
    );
    Ok(path)
}
fn inputs(root: &Path, graphs: &Value) -> Result<Value> {
    symbols(root, "inputs", json!({"graphs":graphs}))
}

#[test]
#[ignore = "requires LLVM and a native compiler; exercised by protocol bundle controls"]
fn real_collisions_foreign_references_and_weak_shadow_are_rejected() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path();
    for name in ["_ZN5probe5STATE17h1234567890abcdefE", "anon.1234abcd.0"] {
        let mut graphs = graphs();
        for index in 0..2 {
            let object = compile(
                root,
                &format!("int state __asm__(\"{}\") = 1;", native(name)),
                &format!("collision{index}.c"),
            )?;
            graphs[index]["artifacts"] = json!([{"path":object}]);
        }
        assert!(
            inputs(root, &graphs)
                .unwrap_err()
                .to_string()
                .contains("would coalesce")
        );
    }
    let mut graphs = graphs();
    let foreign = compile(
        root,
        "int kontor_second_secret(void) { return 1; }",
        "foreign.c",
    )?;
    let importer = compile(
        root,
        "extern int kontor_second_secret(void); int kontor_first_call(void) { return kontor_second_secret(); }",
        "importer.c",
    )?;
    graphs[0]["artifacts"] = json!([{"path":importer}]);
    graphs[1]["artifacts"] = json!([{"path":foreign}]);
    let sets = inputs(root, &graphs)?["sets"].clone();
    assert!(
        shared(
            root,
            "graph_references",
            json!({"graph":graphs[0],"index":0,"sets":sets})
        )
        .unwrap_err()
        .to_string()
        .contains("references another graph")
    );
    let name = "_ZN5probe5STATE17h1234567890abcdefE";
    let weak = compile(
        root,
        &format!(
            "int state __asm__(\"{}\") __attribute__((weak)) = 1;",
            native(name)
        ),
        "weak.c",
    )?;
    graphs[0]["artifacts"] = json!([{"path":weak}]);
    let sets = inputs(root, &graphs)?["sets"].clone();
    let tools = ObjectTools::discover(root)?;
    let definitions = parse_definitions(
        &tools.inspect(&[
            "-g".into(),
            "--defined-only".into(),
            weak.as_os_str().to_owned(),
        ])?,
        cfg!(target_os = "macos"),
    )?;
    assert!(shared(root, "reject_shadow", json!({"graph":"first","names":sets[0],"owners":definitions.keys().collect::<Vec<_>>(),"node":false})).is_err());
    assert!(symbols(root, "final", json!({"executable":weak,"graphs":graphs,"sets":[[],[]],"versions":["51.0.0-dev","51.0.0-kontor.1"],"common":{},"kind":"proof","node":{}})).unwrap_err().to_string().contains("unowned final definition"));
    Ok(())
}

#[test]
#[ignore = "requires LLVM and a native compiler; exercised by protocol bundle controls"]
fn real_private_archives_and_native_helpers_keep_their_owners() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path();
    let mut graphs = graphs();
    for (index, label) in ["first", "second"].iter().enumerate() {
        let object = compile(
            root,
            &format!(
                "static int kontor_{label}_local(void) {{ return 1; }} int kontor_{label}_call(void) {{ return kontor_{label}_local(); }}"
            ),
            &format!("{label}.c"),
        )?;
        let object = if index == 1 {
            archive(root, "libnative.a", &object)?
        } else {
            object
        };
        graphs[index][if index == 1 {
            "native_artifacts"
        } else {
            "artifacts"
        }] = json!([{"path":object,"sha256":hash(&object)?}]);
    }
    let input = inputs(root, &graphs)?;
    let local = symbols(root, "private_local", json!({"graphs":graphs}))?;
    for (index, label) in ["first", "second"].iter().enumerate() {
        assert_eq!(
            input["sets"][index],
            json!([format!("kontor_{label}_call")])
        );
        assert_eq!(local[0][index], json!([format!("kontor_{label}_local")]));
        assert!(local[1][index]["inputs"][0]["sha256"].is_string());
    }
    fs::write(
        graphs[0]["artifacts"][0]["path"].as_str().unwrap(),
        "changed",
    )?;
    assert!(
        symbols(root, "private_local", json!({"graphs":graphs}))
            .unwrap_err()
            .to_string()
            .contains("staged graph input changed")
    );
    graphs[0]["artifacts"] = json!([]);
    graphs[1]["native_artifacts"] = json!([]);
    for symbol in [
        "rust_psm_on_stack",
        "rust_psm_replace_stack",
        "rust_psm_stack_direction",
        "rust_psm_stack_pointer",
        "cabi_realloc_wit_bindgen_0_63_0",
    ] {
        let object = compile(
            root,
            &format!("int {symbol}(void) {{ return 1; }}"),
            "unprefixed.c",
        )?;
        let (package, version, filename) = if symbol.starts_with("rust_psm") {
            ("psm", "0.1.32", "libpsm-1234567890abcdef.rlib")
        } else {
            (
                "wit-bindgen",
                "0.63.0",
                "libwit_bindgen-1234567890abcdef.rlib",
            )
        };
        let library = archive(root, filename, &object)?;
        graphs[0]["packages"]
            .as_array_mut()
            .unwrap()
            .push(json!({"name":package,"version":version}));
        graphs[0]["artifacts"] =
            json!([{"path":library,"source_path":root.join("target/debug/deps").join(filename)}]);
        assert!(
            inputs(root, &graphs)
                .unwrap_err()
                .to_string()
                .contains("unowned native input definition")
        );
        graphs[0]["packages"].as_array_mut().unwrap().pop();
    }
    for (index, label) in ["first", "second"].iter().enumerate() {
        let object = compile(
            root,
            &format!(
                "int kontor_{label}_rust_psm_on_stack(void) {{ return 1; }} int kontor_{label}_cabi_realloc_wit_bindgen_0_63_0(void) {{ return 1; }}"
            ),
            &format!("{label}_helper.c"),
        )?;
        let caller = compile(
            root,
            &format!(
                "extern int kontor_{label}_rust_psm_on_stack(void); int kontor_{label}_call(void) {{ return kontor_{label}_rust_psm_on_stack(); }}"
            ),
            &format!("{label}_caller.c"),
        )?;
        graphs[index]["artifacts"] = json!([{"path":object},{"path":caller}]);
    }
    let sets = inputs(root, &graphs)?["sets"].clone();
    for (index, label) in ["first", "second"].iter().enumerate() {
        let refs = shared(
            root,
            "graph_references",
            json!({"graph":graphs[index],"index":index,"sets":sets}),
        )?;
        assert_eq!(
            refs[0],
            json!([format!("kontor_{label}_rust_psm_on_stack")])
        );
    }
    Ok(())
}

#[test]
#[ignore = "requires LLVM and a native compiler; exercised by protocol bundle controls"]
fn psm_archive_copy_and_weak_unwind_imports_are_checked_before_linking() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path();
    let mut graphs = graphs();
    let object = compile(
        root,
        "int kontor_first_rust_psm_on_stack(void) { return 1; }",
        "psm_native.c",
    )?;
    let library = archive(root, "libpsm-1234567890abcdef.rlib", &object)?;
    let native_archive = archive(root, "libpsm_s.a", &object)?;
    graphs[0]["artifacts"] = json!([{"path":library}]);
    graphs[0]["native_artifacts"] = json!([{"path":native_archive}]);
    inputs(root, &graphs)?;
    let changed = compile(
        root,
        "int kontor_first_rust_psm_on_stack(void) { return 2; }",
        "psm_native.c",
    )?;
    archive(root, "libpsm_s.a", &changed)?;
    assert!(
        inputs(root, &graphs)
            .unwrap_err()
            .to_string()
            .contains("psm native archive copies differ")
    );
    graphs[0]["native_artifacts"] = json!([]);
    for weak in [true, false] {
        let attribute = if !weak {
            ""
        } else if cfg!(target_os = "macos") {
            "__attribute__((weak_import))"
        } else {
            "__attribute__((weak))"
        };
        let object = compile(
            root,
            &format!(
                "extern void __unw_add_dynamic_fde(void) {attribute}; void kontor_first_call(void) {{ if (__unw_add_dynamic_fde) __unw_add_dynamic_fde(); }}"
            ),
            "unwind.c",
        )?;
        graphs[0]["artifacts"] = json!([{"path":object}]);
        let sets = inputs(root, &graphs)?["sets"].clone();
        let refs = shared(
            root,
            "graph_references",
            json!({"graph":graphs[0],"index":0,"sets":sets}),
        )?;
        assert_eq!(
            refs[1],
            if weak {
                json!(["__unw_add_dynamic_fde"])
            } else {
                json!([])
            }
        );
        let mut linker = json!({});
        if weak && cfg!(target_os = "linux") {
            let executable = root.join("weak-node");
            ensure!(
                Command::new("cc")
                    .args(["-nostdlib", "-pie", "-Wl,-e,kontor_first_call"])
                    .arg(&object)
                    .arg("-o")
                    .arg(&executable)
                    .status()?
                    .success(),
                "link weak import"
            );
            linker = shared(root, "linker_owners", json!({"executable":executable}))?;
        }
        let result = shared(
            root,
            "reject_unowned",
            json!({"graph":"first","names":sets[0],"refs":refs[0],"common":[],"platform":[],"optional":refs[1],"linker":linker.as_object().unwrap().keys().collect::<Vec<_>>(),"compiler":[]}),
        );
        assert_eq!(result.is_ok(), weak);
    }
    Ok(())
}

fn verify(
    root: &Path,
    graphs: &Value,
    executable: &Path,
    node: &[PathBuf],
    compiler: &[PathBuf],
) -> Result<Value> {
    let sets = inputs(root, graphs)?["sets"].clone();
    let mut env: BTreeMap<_, _> = env::vars().collect();
    env.insert("RUSTC".into(), "rustc".into());
    shared(
        root,
        "verify",
        json!({"graphs":graphs,"sets":sets,"host_objects":[],"executable":executable,"env":env,"kind":"executor","node_objects":node,"compiler_objects":compiler}),
    )
}

#[test]
#[ignore = "requires LLVM and a native compiler; exercised by protocol bundle controls"]
fn node_native_and_allocator_ownership_cannot_satisfy_foreign_graph_imports() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path();
    let mut graphs = graphs();
    let names = [
        "blst_keygen",
        "rustsecp256k1_v0_10_0_ecdsa_sign_recoverable",
        "ring_core_0_17_14__CRYPTO_memcmp",
    ];
    let native_object = compile(
        root,
        &names
            .iter()
            .map(|name| format!("int {name}(void) {{ return 1; }}"))
            .collect::<String>(),
        "native.c",
    )?;
    let codegen = compile(
        root,
        "int kontor_node_root(void) { return 1; }",
        "codegen.c",
    )?;
    let main = compile(root, "int main(void) { return 0; }", "main.c")?;
    let executable = root.join("node");
    ensure!(
        Command::new("cc")
            .arg(main)
            .arg("-o")
            .arg(&executable)
            .status()?
            .success(),
        "link fixture"
    );
    let node = [native_object.clone(), codegen.clone()];
    for name in names {
        let importer = compile(
            root,
            &format!("extern int {name}(void); int kontor_first_call(void) {{ return {name}(); }}"),
            "importer.c",
        )?;
        graphs[0]["artifacts"] = json!([{"path":importer}]);
        assert!(
            verify(
                root,
                &graphs,
                &executable,
                &node,
                std::slice::from_ref(&codegen)
            )
            .unwrap_err()
            .to_string()
            .contains("imports have no declared owner")
        );
    }
    for symbol in ["puts", "rust_eh_personality"] {
        let source = if symbol == "puts" {
            "extern int puts(const char *); int kontor_first_call(void) { return puts(\"ok\"); }"
        } else {
            "extern void rust_eh_personality(void); int kontor_first_call(void) { rust_eh_personality(); return 1; }"
        };
        let importer = compile(root, source, "importer.c")?;
        graphs[0]["artifacts"] = json!([{"path":importer}]);
        let result = verify(
            root,
            &graphs,
            &executable,
            &node,
            std::slice::from_ref(&codegen),
        )?;
        assert!(result["node"].get("blst_keygen").is_some());
        assert!(result["common"].get("blst_keygen").is_none());
        assert!(
            result["report"]["references"][0][if symbol == "puts" {
                "platform"
            } else {
                "common"
            }]
            .as_array()
            .unwrap()
            .contains(&json!(symbol))
        );
    }
    let collision = compile(
        root,
        "int kontor_first_call(void) { return 1; }",
        "collision.c",
    )?;
    assert!(
        verify(
            root,
            &graphs,
            &executable,
            &[collision, codegen.clone()],
            std::slice::from_ref(&codegen)
        )
        .unwrap_err()
        .to_string()
        .contains("shadows node input")
    );
    let symbol = "_RNvCs1234_7___rustc12___rust_alloc";
    let allocator = compile(
        root,
        &format!(
            "int shim(void) __asm__(\"{}\"); int shim(void) {{ return 1; }}",
            native(symbol)
        ),
        "allocator.c",
    )?;
    let importer = compile(
        root,
        &format!(
            "extern int shim(void) __asm__(\"{}\"); int kontor_first_call(void) {{ return shim(); }}",
            native(symbol)
        ),
        "importer.c",
    )?;
    graphs[0]["artifacts"] = json!([{"path":importer}]);
    let node = [allocator.clone(), codegen.clone()];
    assert!(
        verify(
            root,
            &graphs,
            &executable,
            &node,
            std::slice::from_ref(&codegen)
        )
        .is_err()
    );
    let result = verify(
        root,
        &graphs,
        &executable,
        &node,
        std::slice::from_ref(&allocator),
    )?;
    assert_eq!(
        result["report"]["references"][0]["compiler_runtime"],
        json!([symbol])
    );
    assert_eq!(
        result["node_report"]["compiler_runtime"][symbol],
        json!([allocator])
    );
    let duplicate = compile(
        root,
        &format!(
            "int shim(void) __asm__(\"{}\"); int shim(void) {{ return 2; }}",
            native(symbol)
        ),
        "duplicate.c",
    )?;
    assert!(
        verify(
            root,
            &graphs,
            &executable,
            &[allocator.clone(), duplicate],
            &[allocator]
        )
        .unwrap_err()
        .to_string()
        .contains("duplicates root compiler runtime")
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires LLVM and a native compiler; exercised by protocol bundle controls"]
fn compiler_debug_metadata_cannot_be_imported_as_code() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path();
    let mut graphs = graphs();
    let object = compile(
        root,
        &format!("extern char {GDB_SCRIPT}; char *kontor_first_pointer = &{GDB_SCRIPT};"),
        "metadata-import.c",
    )?;
    graphs[0]["artifacts"] = json!([{"path":object}]);
    let sets = inputs(root, &graphs)?["sets"].clone();
    assert!(
        shared(
            root,
            "graph_references",
            json!({"graph":graphs[0],"index":0,"sets":sets})
        )
        .unwrap_err()
        .to_string()
        .contains("references compiler debug metadata as code")
    );
    Ok(())
}
