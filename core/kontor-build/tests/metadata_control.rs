#![cfg(unix)]

use std::env::{self, consts::DLL_EXTENSION};
use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::Result;
use kontor_build::metadata_control::{Graph, proc_macro_hashes};
use serde_json::{Value, json};
use tempfile::tempdir;

fn compile(compiler: &Path, args: &[&str]) -> Result<()> {
    let output = Command::new(compiler).args(args).output()?;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(())
}

#[test]
fn real_compiler_rejects_foreign_plugins_in_both_directions() -> Result<()> {
    let directory = tempdir()?;
    let root = directory.path().canonicalize()?;
    let output = Command::new("rustup")
        .args(["which", "--toolchain", "1.99.1", "rustc"])
        .output()?;
    assert!(output.status.success());
    let compiler = String::from_utf8(output.stdout)?.trim().to_owned();
    let compiler = Path::new(&compiler);
    let macro_source = root.join("macro.rs");
    fs::write(
        &macro_source,
        "extern crate proc_macro;\nuse proc_macro::TokenStream;\n#[proc_macro_attribute]\npub fn attr(_: TokenStream, item: TokenStream) -> TokenStream { item }\n",
    )?;
    let source = root.join("bundle.rs");
    fs::write(&source, "#[rustversion::attr]\npub fn shape() {}\n")?;
    let mut graphs = Vec::<Value>::new();
    for label in ["first", "second"] {
        let links = root.join(label);
        fs::create_dir(&links)?;
        let plugin = links.join(format!("librustversion-{label}.{DLL_EXTENSION}"));
        compile(
            compiler,
            &[
                "--crate-name",
                "rustversion",
                "--crate-type",
                "proc-macro",
                "--edition=2024",
                "-C",
                &format!("metadata={label}"),
                macro_source.to_str().unwrap(),
                "-o",
                plugin.to_str().unwrap(),
            ],
        )?;
        let facade = links.join(format!("libkontor_proof_{label}.rlib"));
        compile(
            compiler,
            &[
                "--crate-name",
                &format!("kontor_proof_{label}"),
                "--crate-type",
                "rlib",
                "--edition=2024",
                "--extern",
                &format!("rustversion={}", plugin.display()),
                source.to_str().unwrap(),
                "-o",
                facade.to_str().unwrap(),
            ],
        )?;
        graphs.push(json!({"graph": label, "compiler_proc_macros": [{"path": plugin, "staged": plugin, "sha256": "fixture"}], "link_inputs": links, "facade": facade}));
    }
    let env = env::vars()
        .chain([("RUSTC".into(), compiler.to_str().unwrap().into())])
        .collect();
    let decode =
        |values: &[Value]| -> Result<Vec<Graph>> { Ok(serde_json::from_value(json!(values))?) };
    let result = proc_macro_hashes(
        &decode(&graphs)?,
        &["--edition=2024".into()],
        &env,
        &root,
        &root,
    )?;
    assert_eq!(result[0]["svh"], result[1]["foreign_svh"]);
    assert_ne!(result[0]["svh"], result[0]["foreign_svh"]);
    assert_eq!(result[0]["artifact"], graphs[0]["compiler_proc_macros"][0]);
    assert!(fs::read_to_string(root.join("first-wrong-proc-macro.log"))?.contains("E0463"));
    assert!(!fs::read_dir(&root)?.any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("metadata-control-")
    }));
    graphs[0]["compiler_proc_macros"] = json!([]);
    assert!(proc_macro_hashes(&decode(&graphs)?, &[], &env, &root, &root).is_err());
    graphs[0]["graph"] = json!("../../escape");
    assert!(proc_macro_hashes(&decode(&graphs)?, &[], &env, &root, &root).is_err());
    Ok(())
}
