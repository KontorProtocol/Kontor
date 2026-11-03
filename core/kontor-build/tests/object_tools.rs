use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Result, ensure};
use kontor_build::object_tools::ObjectTools;
use kontor_build::shared_ownership::run as audit_shared;
#[cfg(target_os = "linux")]
use kontor_build::symbol_audit::run as audit_symbols;
use kontor_build::toolchain::symbol_reader;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tempfile::tempdir;

fn compile(root: &Path, source: &str, name: &str) -> Result<PathBuf> {
    let input = root.join(name);
    let output = input.with_extension("o");
    fs::write(&input, source)?;
    ensure!(
        Command::new("cc")
            .args(["-c", name, "-o"])
            .arg(output.file_name().unwrap())
            .current_dir(root)
            .status()?
            .success(),
        "compile object fixture"
    );
    Ok(output)
}

#[test]
#[ignore = "requires llvm-tools-preview; exercised by protocol bundle controls"]
fn pinned_readers_preserve_symbols_archives_and_relative_working_directory() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path();
    let object = compile(root, "int fixture_data = 42;\n", "input space.c")?;
    let tools = ObjectTools::discover(root)?;
    let reader = symbol_reader(root)?;
    let archive = root.join("archive space.a");
    ensure!(
        Command::new(reader.with_file_name("llvm-ar"))
            .arg("rcs")
            .arg(&archive)
            .arg(&object)
            .status()?
            .success(),
        "archive fixture"
    );
    let member = object.file_name().unwrap().to_str().unwrap();
    assert_eq!(
        tools.archive_members(Path::new("archive space.a"))?,
        vec![member]
    );
    assert_eq!(
        tools.archive_member(Path::new("archive space.a"), member)?,
        fs::read(&object)?
    );
    assert!(
        tools
            .inspect(&["-g".into(), "input space.o".into()])?
            .contains("fixture_data")
    );
    if cfg!(target_os = "linux") {
        let records = tools.object_records(Path::new("input space.o"))?;
        let record = &records[0];
        let section = record["Sections"]
            .as_array()
            .unwrap()
            .iter()
            .map(|item| &item["Section"])
            .find(|section| section["Name"]["Name"] == ".data")
            .unwrap();
        let bytes = tools.section_bytes(Path::new("input space.o"), record, section)?;
        assert_eq!(bytes, 42i32.to_ne_bytes());
        let archived = tools.object_records(Path::new("archive space.a"))?;
        assert_eq!(
            tools.section_bytes(Path::new("archive space.a"), &archived[0], section)?,
            bytes
        );
        assert!(
            tools
                .section_bytes(
                    Path::new("archive space.a"),
                    &archived[0],
                    &json!({"Offset": u64::MAX - 1, "Size": 1})
                )
                .is_err()
        );
    }
    let request = json!({"operation": "inspect", "working_directory": root, "arguments": ["-g", "input space.o"]});
    let cli = Command::new(env!("CARGO_BIN_EXE_kontor-build"))
        .arg("inspect-object")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .current_dir(env::temp_dir())
        .spawn()?;
    // A different launcher directory must not reinterpret the recorded relative path.
    let mut cli = cli;
    serde_json::to_writer(cli.stdin.take().unwrap(), &request)?;
    let output = cli.wait_with_output()?;
    ensure!(output.status.success(), "object CLI");
    assert!(
        serde_json::from_slice::<Value>(&output.stdout)?
            .as_str()
            .unwrap()
            .contains("fixture_data")
    );
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires llvm-tools-preview; exercised by protocol bundle controls"]
fn compiler_debug_metadata_binds_shape_payload_and_linked_offsets() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path();
    let tools = ObjectTools::discover(root)?;
    let symbol = "__rustc_debug_gdb_scripts_section__";
    let source = format!(
        ".section .debug_gdb_scripts,\"aMS\",%progbits,1\n.weak {symbol}\n.type {symbol}, %object\n{symbol}:\n.byte 1\n.asciz \"gdb_load_rust_pretty_printers.py\"\n.size {symbol}, .-{symbol}\n"
    );
    let object = compile(root, &source, "good.S")?;
    assert_eq!(tools.compiler_debug_metadata(&object, false)?, 1);
    let linked = root.join("linked.so");
    ensure!(
        Command::new("cc")
            .args(["-nostdlib", "-shared"])
            .arg(&object)
            .arg("-o")
            .arg(&linked)
            .status()?
            .success(),
        "link metadata fixture"
    );
    assert_eq!(tools.compiler_debug_metadata(&linked, true)?, 1);
    for (name, source) in [
        ("payload.S", source.replace("printers.py", "printers.pz")),
        ("binding.S", source.replace(".weak", ".globl")),
        (
            "section.S",
            source.replace(".debug_gdb_scripts", ".rodata.fake_gdb_scripts"),
        ),
        (
            "alignment.S",
            source.replace(&format!("{symbol}:"), &format!(".balign 2\n{symbol}:")),
        ),
        (
            "offset.S",
            source.replace(&format!("{symbol}:"), &format!(".byte 7\n{symbol}:")),
        ),
    ] {
        let object = compile(root, &source, name)?;
        assert!(
            tools.compiler_debug_metadata(&object, false).is_err(),
            "accepted {name}"
        );
        if name == "offset.S" {
            assert_eq!(tools.compiler_debug_metadata(&object, true)?, 1);
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires llvm-tools-preview; exercised by protocol bundle controls"]
fn real_linked_graphs_preserve_global_and_private_ownership() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path();
    let mut graphs = Vec::new();
    let mut objects = Vec::new();
    for name in ["first", "second"] {
        let object = compile(
            root,
            &format!(
                "static int kontor_{name}_local(void) {{ return 1; }} int kontor_{name}_call(void) {{ return kontor_{name}_local(); }}\n"
            ),
            &format!("{name}.c"),
        )?;
        let hash = hex::encode(Sha256::digest(fs::read(&object)?));
        graphs.push(json!({"graph":name, "namespace":format!("kontor_{name}"), "packages":[], "identity":{"kind":"consensus"}, "artifacts":[{"path":object,"sha256":hash}], "native_artifacts":[]}));
        objects.push(object);
    }
    let request = json!({"operation":"inputs", "working_directory":root, "graphs":graphs});
    let input = audit_symbols(serde_json::from_value(request)?)?;
    assert_eq!(input["versions"], json!([null, null]));
    assert_eq!(
        input["sets"],
        json!([["kontor_first_call"], ["kontor_second_call"]])
    );
    let linked = root.join("node.so");
    ensure!(
        Command::new("cc")
            .args(["-nostdlib", "-shared"])
            .args(&objects)
            .arg("-o")
            .arg(&linked)
            .status()?
            .success(),
        "link graph fixture"
    );
    let request = json!({"operation":"final", "working_directory":root, "executable":linked, "graphs":graphs, "sets":input["sets"], "versions":input["versions"], "common":{}, "kind":"executor", "node":{}});
    let result = audit_symbols(serde_json::from_value(request)?)?;
    for name in ["first", "second"] {
        for suffix in ["call", "local"] {
            assert_eq!(
                result["attributed"][format!("kontor_{name}_{suffix}")]["owner"],
                name
            );
        }
    }
    assert_eq!(result["result"]["native"].as_object().unwrap().len(), 4);
    Ok(())
}

#[test]
#[ignore = "native compiler/runtime fixture; exercised by protocol bundle controls"]
fn shared_runtime_lookup_uses_actual_library_handles_and_hashes() -> Result<()> {
    let dir = tempdir()?;
    let root = dir.path();
    let object = compile(root, "int main(void) { return 0; }\n", "main.c")?;
    let executable = root.join("node");
    ensure!(
        Command::new("cc")
            .arg(object)
            .arg("-o")
            .arg(&executable)
            .status()?
            .success(),
        "link platform fixture"
    );
    let request = json!({"operation":"platform_owners", "working_directory":root, "executable":executable, "kind":"executor", "candidates":["puts", "kontor_definitely_absent", "_handle"]});
    let result = audit_shared(serde_json::from_value(request)?)?;
    let owners = result[0].as_object().unwrap();
    assert!(!owners["puts"].as_array().unwrap().is_empty());
    assert!(!owners.contains_key("kontor_definitely_absent"));
    assert!(!owners.contains_key("_handle"));
    for library in result[1].as_array().unwrap() {
        let path = Path::new(library["path"].as_str().unwrap());
        if path.is_file() {
            assert_eq!(
                library["sha256"],
                hex::encode(Sha256::digest(fs::read(path)?))
            );
            assert_eq!(library["dyld_shared_cache"], false);
        } else {
            ensure!(
                cfg!(target_os = "macos"),
                "non-cache runtime library missing"
            );
            assert_eq!(library["sha256"], Value::Null);
            assert_eq!(library["dyld_shared_cache"], true);
        }
    }
    Ok(())
}
