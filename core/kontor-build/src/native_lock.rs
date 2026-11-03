use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use toml::Value;

#[derive(Deserialize)]
struct Lock {
    package: Vec<Package>,
}

#[derive(Clone, Deserialize)]
struct Package {
    name: String,
    version: String,
    source: Option<String>,
    checksum: Option<String>,
    #[serde(default)]
    dependencies: Vec<String>,
}

impl Package {
    fn identity(&self) -> (&str, &str, Option<&str>, Option<&str>) {
        (
            &self.name,
            &self.version,
            self.source.as_deref(),
            self.checksum.as_deref(),
        )
    }
}

fn one<'a>(lock: &'a Lock, name: &str) -> Result<&'a Package> {
    let mut packages = lock.package.iter().filter(|package| package.name == name);
    let package = packages
        .next()
        .with_context(|| format!("missing {name} package"))?;
    ensure!(
        packages.next().is_none(),
        "expected one {name} version per graph"
    );
    Ok(package)
}

pub fn check_native_helper_lock(root: &Path) -> Result<String> {
    let helper = root.join("core/vendor/kontor-native-build");
    let core: Lock = toml::from_str(&fs::read_to_string(root.join("core/Cargo.lock"))?)?;
    let helper_lock: Lock = toml::from_str(&fs::read_to_string(helper.join("Cargo.lock"))?)?;
    let manifest: Value = toml::from_str(&fs::read_to_string(helper.join("Cargo.toml"))?)?;
    verify(&core, &helper_lock, &manifest)
}

fn verify(core: &Lock, helper: &Lock, manifest: &Value) -> Result<String> {
    let version = &one(core, "cc")?.version;
    ensure!(
        one(helper, "cc")?.version == *version,
        "helper and core cc versions differ"
    );
    let pin = manifest
        .get("dependencies")
        .and_then(|deps| deps.get("cc"))
        .and_then(Value::as_str);
    ensure!(
        pin == Some(format!("={version}").as_str()),
        "helper must pin the core cc version exactly"
    );
    for package in &helper.package {
        ensure!(
            core.package
                .iter()
                .any(|other| other.identity() == package.identity()),
            "helper dependency absent from core lock: {} {}",
            package.name,
            package.version
        );
    }
    for name in ["blst", "ring", "secp256k1-sys"] {
        let package = one(core, name)?;
        ensure!(package.source.is_none(), "{name} must be vendored");
        ensure!(
            package
                .dependencies
                .iter()
                .any(|dependency| dependency == "kontor-native-build"),
            "{name} lost helper"
        );
    }
    Ok(version.clone())
}

#[cfg(test)]
mod tests {
    use anyhow::Result;
    use toml::Value;

    use super::{Lock, Package, verify};

    fn fixture() -> Result<(Lock, Lock, Value)> {
        let cc = Package {
            name: "cc".into(),
            version: "1.8.0".into(),
            source: Some("registry".into()),
            checksum: Some("digest".into()),
            dependencies: Vec::new(),
        };
        let mut core = Lock {
            package: vec![cc.clone()],
        };
        for name in ["blst", "ring", "secp256k1-sys"] {
            core.package.push(Package {
                name: name.into(),
                version: "1.0.0".into(),
                source: None,
                checksum: None,
                dependencies: vec!["kontor-native-build".into()],
            });
        }
        Ok((
            core,
            Lock { package: vec![cc] },
            toml::from_str("[dependencies]\ncc = '=1.8.0'")?,
        ))
    }

    #[test]
    fn helper_requires_exact_version_and_unambiguous_resolution() -> Result<()> {
        let (mut core, mut helper, manifest) = fixture()?;
        assert_eq!(verify(&core, &helper, &manifest)?, "1.8.0");
        let loose = toml::from_str("[dependencies]\ncc = '1.8.0'")?;
        assert!(verify(&core, &helper, &loose).is_err());
        helper.package[0].version = "1.9.0".into();
        assert!(verify(&core, &helper, &manifest).is_err());
        helper.package[0].version = "1.8.0".into();
        core.package.push(core.package[0].clone());
        assert!(verify(&core, &helper, &manifest).is_err());
        core.package.pop();
        helper.package.push(helper.package[0].clone());
        assert!(verify(&core, &helper, &manifest).is_err());
        helper.package.clear();
        assert!(verify(&core, &helper, &manifest).is_err());
        Ok(())
    }

    #[test]
    fn same_version_cannot_substitute_source_checksum_or_missing_dependency() -> Result<()> {
        let (core, helper, manifest) = fixture()?;
        for replacement in [None, Some("substituted".into())] {
            let mut changed = Lock {
                package: helper.package.clone(),
            };
            changed.package[0].source = replacement.clone();
            assert!(verify(&core, &changed, &manifest).is_err());
            changed.package[0].source = helper.package[0].source.clone();
            changed.package[0].checksum = replacement;
            assert!(verify(&core, &changed, &manifest).is_err());
        }
        let mut changed = Lock {
            package: helper.package.clone(),
        };
        let mut extra = helper.package[0].clone();
        extra.name = "untracked".into();
        changed.package.push(extra);
        assert!(verify(&core, &changed, &manifest).is_err());
        Ok(())
    }

    #[test]
    fn crypto_packages_must_remain_vendored_and_use_the_helper() -> Result<()> {
        let (core, helper, manifest) = fixture()?;
        for index in 1..core.package.len() {
            let mut changed = Lock {
                package: core.package.clone(),
            };
            changed.package[index].source = Some("registry".into());
            assert!(verify(&changed, &helper, &manifest).is_err());
            changed.package[index].source = None;
            changed.package[index].dependencies.clear();
            assert!(verify(&changed, &helper, &manifest).is_err());
        }
        Ok(())
    }
}
