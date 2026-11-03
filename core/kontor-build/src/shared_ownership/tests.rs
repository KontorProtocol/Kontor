use super::*;
use crate::symbol_audit::Symbol;
use tempfile::tempdir;

fn names(items: &[&str]) -> Names {
    items.iter().map(|item| item.to_string()).collect()
}

#[test]
fn references_preserve_strong_weak_and_darwin_attributes() -> Result<()> {
    let linux = parse_references(
        "archive(member.o):\n U strong\n w optional\n v weak_object\n standalone\n U optional\n",
        false,
    )?;
    assert_eq!(linux["optional"], names(&["U", "w"]));
    assert_eq!(linux["standalone"], names(&["U"]));
    let darwin = parse_references(
        " (undefined) external _strong (from libSystem)\n(undefined) weak external _optional\n(undefined) weak private external _private_weak\n(undefined) private external _private_strong\n",
        true,
    )?;
    assert_eq!(darwin["strong"], names(&["U"]));
    assert_eq!(darwin["optional"], names(&["w"]));
    assert_eq!(darwin["private_weak"], names(&["w"]));
    assert_eq!(darwin["private_strong"], names(&["U"]));
    for text in ["T unexpected", "U name extra", "reader failed noisily"] {
        assert!(parse_references(text, false).is_err());
    }
    for text in [
        "(undefined) lazy external _foo",
        "(undefined) weak local _foo",
        "_foo",
    ] {
        assert!(parse_references(text, true).is_err());
    }
    Ok(())
}

#[test]
fn system_library_allowlists_distinguish_node_cpp_and_preserve_order() -> Result<()> {
    let mac = |paths: &[&str]| {
        format!(
            "fixture:\n{}",
            paths
                .iter()
                .map(|path| format!("\t{path} (compatibility version 1.0.0)\n"))
                .collect::<String>()
        )
    };
    let base = ["/usr/lib/libSystem.B.dylib", "/usr/lib/libiconv.2.dylib"];
    assert_eq!(
        parse_runtime_paths(&mac(&base), Kind::Proof, true)?,
        base.map(PathBuf::from)
    );
    let cpp = "/usr/lib/libc++.1.dylib";
    assert!(parse_runtime_paths(&mac(&[base[0], cpp]), Kind::Proof, true).is_err());
    assert_eq!(
        parse_runtime_paths(&mac(&[base[0], cpp, base[0]]), Kind::Executor, true)?,
        vec![PathBuf::from(base[0]), PathBuf::from(cpp)]
    );
    for unknown in [
        "@rpath/libiconv.2.dylib",
        "/opt/homebrew/lib/libiconv.2.dylib",
        "/usr/lib/libiconv.3.dylib",
        "/opt/lib/libc++.1.dylib",
    ] {
        assert!(parse_runtime_paths(&mac(&[base[0], unknown]), Kind::Executor, true).is_err());
    }
    let linux = "linux-vdso.so.1 (0x1234)\nlibc.so.6 => /lib64/libc.so.6 (0x1234)\nlibstdc++.so.6 => /lib64/libstdc++.so.6 (0x1234)\n";
    assert!(parse_runtime_paths(linux, Kind::Proof, false).is_err());
    assert_eq!(
        parse_runtime_paths(linux, Kind::Executor, false)?,
        vec![
            PathBuf::from("/lib64/libc.so.6"),
            PathBuf::from("/lib64/libstdc++.so.6")
        ]
    );
    assert!(parse_runtime_paths("", Kind::Executor, false).is_err());
    assert!(
        parse_runtime_paths(
            "libcustom.so => /opt/lib/libcustom.so",
            Kind::Executor,
            false
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn shadow_and_reference_rules_have_no_general_native_exemption() -> Result<()> {
    let empty = Names::new();
    let common = names(&["owned", "DW.ref.rust_eh_personality"]);
    assert!(reject_shadow("graph", &names(&["owned"]), &common, false).is_err());
    assert!(reject_shadow("graph", &names(&["owned"]), &common, true).is_err());
    reject_shadow(
        "graph",
        &names(&["DW.ref.rust_eh_personality"]),
        &common,
        false,
    )?;
    let own = names(&["self"]);
    let platform = names(&["puts"]);
    let compiler = names(&["root_allocator"]);
    let linker = names(&["_GLOBAL_OFFSET_TABLE_"]);
    let optional = names(&["__unw_add_dynamic_fde"]);
    let refs = names(&[
        "self",
        "owned",
        "puts",
        "root_allocator",
        "_GLOBAL_OFFSET_TABLE_",
        "__unw_add_dynamic_fde",
    ]);
    reject_unowned(
        "graph", &own, &refs, &common, &platform, &optional, &linker, &compiler,
    )?;
    assert!(
        reject_unowned(
            "graph", &platform, &refs, &common, &platform, &optional, &linker, &compiler
        )
        .is_err()
    );
    for missing in [
        "blst_keygen",
        "__stack_chk_guard",
        "_ITM_registerTMCloneTable",
        "unknown_rust_symbol",
    ] {
        assert!(
            reject_unowned(
                "graph",
                &empty,
                &names(&[missing]),
                &common,
                &platform,
                &optional,
                &linker,
                &compiler
            )
            .is_err()
        );
    }
    for name in [
        "_RNvCs1234_7___rustc12___rust_alloc",
        "_RNvCsabc_7___rustc35___rust_no_alloc_shim_is_unstable_v2",
    ] {
        assert!(RUSTC_ALLOCATOR.is_match(name));
    }
    for name in [
        "__rust_alloc",
        "_RNvCsabc_7___rustc12___rust_alloc_extra",
        "blst_keygen",
    ] {
        assert!(!RUSTC_ALLOCATOR.is_match(name));
    }
    Ok(())
}

#[test]
fn got_anchor_requires_local_data_or_absolute_definition() -> Result<()> {
    for kind in ["d", "a"] {
        let symbols = Definitions::from([(
            "_GLOBAL_OFFSET_TABLE_".into(),
            Symbol {
                address: Some("10".into()),
                kind: kind.into(),
            },
        )]);
        assert_eq!(got_owner(&symbols)?, symbols);
    }
    for kind in ["D", "A", "T", "t", "U", "w"] {
        let symbols = Definitions::from([(
            "_GLOBAL_OFFSET_TABLE_".into(),
            Symbol {
                address: Some("10".into()),
                kind: kind.into(),
            },
        )]);
        assert!(got_owner(&symbols).is_err());
    }
    assert!(got_owner(&Definitions::new())?.is_empty());
    Ok(())
}

#[test]
fn malformed_roles_reject_before_inspection_and_missing_libraries_fail() -> Result<()> {
    let dir = tempdir()?;
    assert!(Library::open(&dir.path().join("absent.so")).is_err());
    let graph: Graph = serde_json::from_value(
        json!({"graph":"first", "namespace":"first", "artifacts":[], "native_artifacts":[]}),
    )?;
    let check = |graphs: &[Graph],
                 sets: &[Names],
                 host: &[PathBuf],
                 kind,
                 node: &[PathBuf],
                 compiler: &[PathBuf]| {
        verify(
            dir.path(),
            graphs,
            sets,
            host,
            Path::new("node"),
            &Environment::new(),
            kind,
            node,
            compiler,
        )
    };
    assert!(check(&[], &[], &[], Kind::Proof, &[], &[]).is_err());
    assert!(
        check(
            std::slice::from_ref(&graph),
            &[],
            &[],
            Kind::Proof,
            &[],
            &[]
        )
        .is_err()
    );
    assert!(
        check(
            std::slice::from_ref(&graph),
            &[Names::new()],
            &[],
            Kind::Proof,
            &["node.o".into()],
            &[]
        )
        .is_err()
    );
    assert!(
        check(
            std::slice::from_ref(&graph),
            &[Names::new()],
            &[],
            Kind::Executor,
            &[],
            &[]
        )
        .is_err()
    );
    assert!(
        check(
            &[graph],
            &[Names::new()],
            &[],
            Kind::Executor,
            &["node.o".into()],
            &["other.o".into()]
        )
        .is_err()
    );
    Ok(())
}
