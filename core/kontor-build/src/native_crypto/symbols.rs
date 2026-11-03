use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;
use std::process::Command;

use anyhow::{Result, ensure};
use serde_json::json;

use super::build::Graph;
use super::{capture, write_json};
use crate::container::sha256;
use crate::symbol_audit::{ANONYMOUS, CRYPTO, FINAL_RUNTIME, RUST, parse_definitions};

type Names = BTreeSet<String>;

fn addresses(path: &Path, globals_only: bool) -> Result<BTreeMap<String, u64>> {
    let mut command = Command::new("nm");
    if globals_only {
        command.arg("-g");
    }
    let text = String::from_utf8(capture(command.arg(path))?)?;
    parse_definitions(&text, cfg!(target_os = "macos"))?
        .into_iter()
        .filter(|(name, _)| !RUST.is_match(name) && !ANONYMOUS.is_match(name))
        .filter_map(|(name, symbol)| {
            symbol
                .address
                .map(|address| Ok((name, u64::from_str_radix(&address, 16)?)))
        })
        .collect()
}

fn crypto_owned(name: &str) -> bool {
    name.starts_with("rustsecp256k1_v0_10_0_")
        || name.starts_with("ring_core_0_17_14_")
        || include_str!("../../../vendor/blst/kontor-symbols.txt")
            .lines()
            .any(|symbol| Some(symbol) == name.split('.').next())
}

fn parse_references(text: &str, darwin: bool) -> Result<Names> {
    let mut names = Names::new();
    for line in text.lines() {
        let fields: Vec<_> = line.split_whitespace().collect();
        if fields.is_empty() || line.ends_with(':') {
            continue;
        }
        ensure!(
            fields.len() == 1 || (fields.len() == 2 && ["U", "w", "v"].contains(&fields[0])),
            "unrecognized nm undefined-symbol output: {line}"
        );
        let name = fields[fields.len() - 1];
        names.insert(
            if darwin {
                name.strip_prefix('_').unwrap_or(name)
            } else {
                name
            }
            .into(),
        );
    }
    Ok(names)
}

fn references(path: &Path) -> Result<Names> {
    parse_references(
        &String::from_utf8(capture(Command::new("nm").arg("-u").arg(path))?)?,
        cfg!(target_os = "macos"),
    )
}

fn validate_references(names: &Names, namespace: &str) -> Result<()> {
    let bare: Vec<_> = names
        .iter()
        .filter(|name| !namespace.is_empty() && crypto_owned(name))
        .collect();
    ensure!(
        bare.is_empty(),
        "unnamespaced crypto references in {namespace}: {bare:?}"
    );
    Ok(())
}

pub(super) fn audit(graphs: &[Graph], output: &Path) -> Result<Vec<Names>> {
    let mut inventories = Vec::new();
    let mut names = Vec::new();
    let mut graph_references = Vec::new();
    for graph in graphs {
        let mut inventory = Vec::new();
        let mut symbols = Names::new();
        let mut refs = Names::new();
        for path in &graph.inputs {
            let definitions: Names = addresses(path, true)?.into_keys().collect();
            let references = references(path)?;
            inventory.push(json!({"path":path,"sha256":sha256(path)?,"definitions":definitions,"undefined_references":references}));
            symbols.extend(definitions);
            refs.extend(references);
        }
        symbols.remove("DW.ref.rust_eh_personality");
        let prefix = if graph.namespace.is_empty() {
            String::new()
        } else {
            format!("{}_", graph.namespace)
        };
        let unknown: Vec<_> = symbols
            .iter()
            .filter(|name| {
                if prefix.is_empty() {
                    !crypto_owned(name)
                } else {
                    !name.starts_with(&prefix)
                }
            })
            .collect();
        ensure!(
            unknown.is_empty(),
            "unowned native symbols in {}: {unknown:?}",
            graph.name
        );
        for name in [
            "default_illegal_callback_fn",
            "default_error_callback_fn",
            "context_create",
            "context_destroy",
        ] {
            ensure!(
                symbols.contains(&format!("{prefix}rustsecp256k1_v0_10_0_{name}")),
                "missing secp Rust definition: {name}"
            );
        }
        ensure!(
            !refs.is_empty(),
            "crypto graph has no parsed undefined references"
        );
        validate_references(&refs, &graph.namespace)?;
        inventories.push(inventory);
        names.push(symbols);
        graph_references.push(refs);
    }
    write_json(&output.join("native-inputs.json"), &json!(inventories))?;
    for (index, symbols) in names.iter().enumerate() {
        let others: Names = names
            .iter()
            .enumerate()
            .filter(|(other, _)| *other != index)
            .flat_map(|(_, names)| names.iter().cloned())
            .collect();
        ensure!(symbols.is_disjoint(&others), "native graph collision");
        ensure!(
            graph_references[index].is_disjoint(&others),
            "cross-graph crypto references"
        );
    }
    Ok(names)
}

pub(super) fn audit_final(
    executable: &Path,
    graphs: &[Graph],
    inputs: &[Names],
    output: &Path,
) -> Result<()> {
    let final_names: Names = addresses(executable, true)?.into_keys().collect();
    let mut runtime: Names = FINAL_RUNTIME.iter().map(|name| (*name).into()).collect();
    runtime.insert("DW.ref.rust_eh_personality".into());
    if cfg!(target_os = "macos") {
        runtime.insert("_mh_execute_header".into());
    }
    let allowed: Names = inputs
        .iter()
        .flat_map(|names| names.iter().cloned())
        .chain(runtime.iter().cloned())
        .collect();
    ensure!(
        final_names.is_subset(&allowed),
        "unowned final native definitions: {:?}",
        final_names.difference(&allowed).collect::<Vec<_>>()
    );
    let addresses = addresses(executable, false)?;
    let mut required = BTreeMap::new();
    for graph in graphs {
        for name in CRYPTO {
            let name = if graph.namespace.is_empty() {
                (*name).into()
            } else {
                format!("{}_{name}", graph.namespace)
            };
            let address = addresses.get(&name).ok_or_else(|| {
                anyhow::anyhow!("missing live crypto family after linking: {name}")
            })?;
            required.insert(name, *address);
        }
    }
    ensure!(
        required.values().collect::<BTreeSet<_>>().len() == required.len(),
        "independent crypto function definitions alias after linking"
    );
    write_json(
        &output.join("native-final.json"),
        &json!({"definitions":final_names,"required_live_symbols":required,"runtime_definitions":final_names.intersection(&runtime).collect::<Vec<_>>()}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn references_reject_cross_binding_and_malformed_nm() -> Result<()> {
        let names = parse_references(
            "\ninput.o:\n U blst_keygen\n w optional\n external\n",
            false,
        )?;
        assert!(validate_references(&names, "bundle").is_err());
        validate_references(&names, "")?;
        let names = parse_references(" U _bundle_blst_keygen\n", true)?;
        assert!(names.contains("bundle_blst_keygen"));
        validate_references(&names, "bundle")?;
        assert!(parse_references("00000 U blst_keygen", false).is_err());
        for name in [
            "blst_keygen",
            "blst_keygen.llvm.3",
            "ring_core_0_17_14_test",
            "rustsecp256k1_v0_10_0_test",
        ] {
            assert!(crypto_owned(name));
        }
        Ok(())
    }
}
