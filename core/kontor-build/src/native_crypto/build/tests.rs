use super::*;
use serde_json::json;
use tempfile::tempdir;

#[test]
fn lock_allows_only_facade_and_exact_source_packages() -> Result<()> {
    let dir = tempdir()?;
    let source = dir.path().join("source.lock");
    let candidate = dir.path().join("candidate.lock");
    let package =
        "[[package]]\nname='dep'\nversion='1.0'\nsource='registry+source'\nchecksum='checksum'\n";
    fs::write(&source, package)?;
    fs::write(
        &candidate,
        format!("{package}[[package]]\nname='crypto_first'\nversion='0.0.0'\n"),
    )?;
    check_lock(&source, &candidate, "crypto_first")?;
    for (old, new) in [
        ("1.0", "2.0"),
        ("registry+source", "registry+other"),
        ("checksum='checksum'", "checksum='other'"),
    ] {
        fs::write(&candidate, package.replace(old, new))?;
        assert!(check_lock(&source, &candidate, "crypto_first").is_err());
    }
    fs::write(&candidate, "version=4")?;
    assert!(check_lock(&source, &candidate, "crypto_first").is_err());
    Ok(())
}

#[test]
fn inventory_requires_complete_current_unique_owners_and_facade() -> Result<()> {
    let dir = tempdir()?;
    let mut records = Vec::new();
    let mut packages = Vec::new();
    for name in CRATES {
        let out = dir.path().join(name);
        fs::create_dir(&out)?;
        fs::write(out.join("libbundle_crypto.a"), b"archive")?;
        packages.push(json!({"id":name,"name":name,"version":"1","source":null,"manifest_path":dir.path().join("Cargo.toml")}));
        records.push(Message::Script {
            package_id: name.into(),
            out_dir: out,
        });
    }
    let metadata: Metadata =
        serde_json::from_value(json!({"workspace_root":dir.path(),"packages":packages}))?;
    assert!(inventory(&records, &metadata, "bundle").is_err());
    records.push(Message::Artifact {
        target: Target {
            name: "crypto_first".into(),
        },
        filenames: vec![dir.path().join("facade.rlib")],
    });
    let (native, _, _) = inventory(&records, &metadata, "bundle")?;
    assert!(native.contains_key("blst/libcrypto.a"));
    records.push(Message::Script {
        package_id: "blst".into(),
        out_dir: dir.path().join("blst"),
    });
    assert!(inventory(&records, &metadata, "bundle").is_err());
    records.pop();
    records.remove(0);
    assert!(inventory(&records, &metadata, "bundle").is_err());
    let log = dir.path().join("build.log");
    fs::write(
        &log,
        "ordinary diagnostic\n{\"reason\":\"build-script-executed\"}\n",
    )?;
    assert!(messages(&log).is_err());
    Ok(())
}
