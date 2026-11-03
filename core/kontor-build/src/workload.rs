use std::path::Path;

use anyhow::{Result, ensure};
use serde::Serialize;
use serde_json::Value;

use fixture::Fixture;
use model::{Manifest, Numeric, Report};

mod assembly;
mod fixture;
mod model;
mod validation;

pub use assembly::assemble;

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct VerifiedDocuments {
    pub manifest_sha256: String,
    pub manifest: Value,
    pub before: Value,
    pub after: Value,
    pub numeric: Value,
    pub bitcoin: Value,
    pub lifecycle: Value,
}

fn manifest(value: &Value) -> Result<Manifest> {
    let parsed: Manifest = serde_json::from_value(value.clone())?;
    // Version one omits effective retention; an explicit null is not an omission.
    ensure!(
        serde_json::to_value(&parsed)? == *value,
        "manifest field representation differs"
    );
    validation::manifest(&parsed)?;
    Ok(parsed)
}

fn check_reports(
    manifest: &Manifest,
    before: &Value,
    after: &Value,
    numeric: &Value,
) -> Result<()> {
    let before: Report = serde_json::from_value(before.clone())?;
    let after: Report = serde_json::from_value(after.clone())?;
    let numeric: Numeric = serde_json::from_value(numeric.clone())?;
    validation::reports(manifest, &before, &after, &numeric)
}

pub fn verify(path: &Path, expected_sha256: &str) -> Result<VerifiedDocuments> {
    let fixture = Fixture::open(path)?;
    ensure!(
        fixture.sha256 == expected_sha256,
        "manifest differs from pinned SHA-256"
    );
    load(fixture)
}

fn load(fixture: Fixture) -> Result<VerifiedDocuments> {
    let manifest = manifest(&fixture.manifest)?;
    fixture.verify_references(&fixture.manifest)?;
    let before = fixture.document(&manifest.snapshot.reset_report)?;
    let after = fixture.document(&manifest.expected_report)?;
    let numeric = fixture.document(&manifest.numeric_check)?;
    check_reports(&manifest, &before, &after, &numeric)?;
    let bitcoin = fixture.document(&manifest.input.bitcoin_validation.record)?;
    let lifecycle = fixture.document(&manifest.execution.lifecycle_parameters)?;
    Ok(VerifiedDocuments {
        manifest_sha256: fixture.sha256,
        manifest: fixture.manifest,
        before,
        after,
        numeric,
        bitcoin,
        lifecycle,
    })
}

#[cfg(test)]
mod tests;
