use super::*;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

const SOURCE: &str = "extern int dependency(int);\nint state = 17;\nint zeros[8];\nint operation(int value) { return dependency(value) + state + zeros[0]; }\n";
static NEXT: AtomicU64 = AtomicU64::new(0);

struct Fixture(PathBuf);
impl Fixture {
    fn new() -> Result<Self> {
        let directory = env::temp_dir().join(format!(
            "kontor-object-test-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory)?;
        Ok(Self(directory))
    }
    fn compile(&self, source: &str, target: Option<&str>, debug: bool) -> Result<PathBuf> {
        let path = self.0.join(format!(
            "fixture-{}.c",
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::write(&path, source)?;
        let mut command = Command::new(if target.is_some() { "clang" } else { "cc" });
        if let Some(target) = target {
            command.args(["-target", target]);
        }
        let output = command
            .env("CCACHE_DISABLE", "1")
            .args(["-O2", if debug { "-g" } else { "-g0" }, "-fno-ident", "-c"])
            .arg(&path)
            .arg("-o")
            .arg(path.with_extension("o"))
            .output()?;
        if !output.status.success() {
            return Err(String::from_utf8_lossy(&output.stderr).into_owned().into());
        }
        Ok(path.with_extension("o"))
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn normalized(path: &Path, namespace: &str) -> Result<Value> {
    let mut value = report(&fs::read(path)?, namespace)?;
    value
        .as_object_mut()
        .unwrap()
        .remove("namespace_audit")
        .unwrap();
    Ok(value)
}
fn renamed() -> String {
    ["dependency", "operation", "state", "zeros"]
        .into_iter()
        .fold(SOURCE.into(), |source, name| {
            source.replace(name, &format!("bundle_{name}"))
        })
}
fn has_clang() -> bool {
    let available = Command::new("clang")
        .arg("--version")
        .output()
        .is_ok_and(|output| output.status.success());
    if !available {
        eprintln!("cross-format controls skipped: clang unavailable");
    }
    available
}

#[test]
fn renaming_preserves_identity_but_code_data_and_relocation_changes_do_not() -> Result<()> {
    let fixture = Fixture::new()?;
    let original = normalized(&fixture.compile(SOURCE, None, false)?, "")?;
    assert_eq!(
        original,
        normalized(&fixture.compile(&renamed(), None, false)?, "bundle")?
    );
    for (old, new) in [
        ("dependency(value)", "dependency(value + 1)"),
        ("state = 17", "state = 18"),
        ("zeros[8]", "zeros[9]"),
        ("dependency", "other_dependency"),
        ("int state", "__attribute__((weak)) int state"),
        ("int state", "__attribute__((aligned(64))) int state"),
    ] {
        assert_ne!(
            original,
            normalized(
                &fixture.compile(&SOURCE.replace(old, new), None, false)?,
                ""
            )?,
            "{old} -> {new}"
        );
    }
    let source = "const char message[] = \"bundle_operation\";";
    assert_ne!(
        normalized(&fixture.compile(source, None, false)?, "bundle")?,
        normalized(
            &fixture.compile(
                &source.replace("\"bundle_operation\"", "\"operation\""),
                None,
                false
            )?,
            ""
        )?
    );
    Ok(())
}

#[test]
fn bare_crypto_reference_is_rejected_even_when_default_copy_links() -> Result<()> {
    let fixture = Fixture::new()?;
    let source = "extern int bundle_blst_keygen(int); int bundle_operation(int x) { return bundle_blst_keygen(x); }";
    normalized(&fixture.compile(source, None, false)?, "bundle")?;
    let bad = fixture.compile(
        &source.replace("bundle_blst_keygen", "blst_keygen"),
        None,
        false,
    )?;
    let error = report(&fs::read(&bad)?, "bundle").unwrap_err();
    assert!(
        error
            .to_string()
            .contains("unprefixed crypto symbol or reference")
    );
    let provider=fixture.compile("int blst_keygen(int x) { return x + 1; } int bundle_operation(int); int main(void) { return bundle_operation(1) != 2; }",None,false)?;
    let executable = fixture.0.join("silent-cross-binding");
    assert!(
        Command::new("cc")
            .env("CCACHE_DISABLE", "1")
            .arg(bad)
            .arg(provider)
            .arg("-o")
            .arg(&executable)
            .status()?
            .success()
    );
    assert!(Command::new(executable).status()?.success());
    Ok(())
}

#[test]
fn macho_arm_debug_layout_does_not_change_section_relative_identity() -> Result<()> {
    if !has_clang() {
        return Ok(());
    }
    let fixture = Fixture::new()?;
    let target = Some("arm64-apple-macos11");
    // x86 unwind data can contain provisional PC-relative values. The strict
    // comparator deliberately rejects those changed bytes instead of masking them.
    assert_eq!(
        normalized(&fixture.compile(SOURCE, target, true)?, "")?,
        normalized(&fixture.compile(SOURCE, target, false)?, "")?
    );
    Ok(())
}

#[test]
fn macho_and_elf_cross_target_objects() -> Result<()> {
    if !has_clang() {
        return Ok(());
    }
    let fixture = Fixture::new()?;
    for target in [
        "aarch64-unknown-linux-gnu",
        "x86_64-unknown-linux-gnu",
        "arm64-apple-macos11",
        "x86_64-apple-macos11",
    ] {
        let original = normalized(&fixture.compile(SOURCE, Some(target), false)?, "")?;
        assert_eq!(
            original,
            normalized(&fixture.compile(&renamed(), Some(target), false)?, "bundle")?,
            "{target}"
        );
        assert_ne!(
            original,
            normalized(
                &fixture.compile(
                    &SOURCE.replace("state = 17", "state = 19"),
                    Some(target),
                    false
                )?,
                ""
            )?,
            "{target}"
        );
    }
    Ok(())
}

#[test]
fn empty_archive_and_truncated_objects_fail_closed() {
    for data in [b"!<arch>\n".as_slice(), b"\x7fELF", b""] {
        assert!(report(data, "").is_err());
    }
}
