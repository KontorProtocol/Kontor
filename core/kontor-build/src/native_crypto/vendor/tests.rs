use super::*;
use flate2::{Compression, write::GzEncoder};
use std::io::Cursor;
use tar::{Builder, Header};

#[test]
fn patch_roundtrip_add_remove_and_recreate_tracks_modes() -> Result<()> {
    let dir = tempdir()?;
    let pristine = dir.path().join("pristine");
    let vendor = dir.path().join("vendor");
    fs::create_dir(&pristine)?;
    fs::create_dir(&vendor)?;
    fs::write(pristine.join("changed"), "before\n")?;
    fs::write(pristine.join("removed"), "removed\n")?;
    fs::write(vendor.join("changed"), "after\n")?;
    fs::write(vendor.join("added"), "added without newline")?;
    let path = dir.path().join("change.patch");
    fs::write(&path, patch(&pristine, &vendor)?)?;
    apply_patch(&pristine, &path)?;
    assert_eq!(files(&pristine)?, files(&vendor)?);
    fs::set_permissions(pristine.join("changed"), fs::Permissions::from_mode(0o755))?;
    assert_ne!(files(&pristine)?, files(&vendor)?);
    fs::write(vendor.join("obsolete"), "obsolete")?;
    replace_files(&pristine, &vendor)?;
    assert_eq!(files(&pristine)?, files(&vendor)?);
    fs::write(vendor.join("changed"), b"binary\0")?;
    assert!(patch(&pristine, &vendor).is_err());
    Ok(())
}

#[test]
fn extraction_rejects_escaping_links_and_wrong_package() -> Result<()> {
    for (name, target, valid) in [
        ("crate-1/file", None, true),
        ("other/file", None, false),
        ("crate-1/link", Some("../../outside"), false),
        ("crate-1/link", Some("/tmp/outside"), false),
    ] {
        let dir = tempdir()?;
        let path = dir.path().join("fixture.crate");
        let mut builder =
            Builder::new(GzEncoder::new(File::create(&path)?, Compression::default()));
        let mut header = Header::new_gnu();
        header.set_mode(0o644);
        if let Some(target) = target {
            header.set_size(0);
            header.set_entry_type(tar::EntryType::Symlink);
            builder.append_link(&mut header, name, target)?;
        } else {
            header.set_size(4);
            builder.append_data(&mut header, name, Cursor::new(b"data"))?;
        }
        builder.into_inner()?.finish()?;
        assert_eq!(
            extract(&path, dir.path(), "crate-1").is_ok(),
            valid,
            "{name}: {target:?}"
        );
    }
    Ok(())
}

#[test]
fn inventory_refuses_external_symlinks_before_applying() -> Result<()> {
    let dir = tempdir()?;
    let tree = dir.path().join("tree");
    fs::create_dir(&tree)?;
    fs::write(dir.path().join("outside"), "untouched")?;
    symlink("../outside", tree.join("alias"))?;
    assert!(files(&tree).is_err());
    assert_eq!(fs::read_to_string(dir.path().join("outside"))?, "untouched");
    Ok(())
}
