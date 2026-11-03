use super::*;
use tempfile::tempdir;

#[test]
fn object_reports_must_contain_explicit_namespace_audits() -> Result<()> {
    let mut report =
        json!({"members":[{"sections":[1],"namespace_audit":{"names":["bundle_name"]}}]});
    let audits = strip_audits(&mut report)?;
    assert_eq!(audits, vec![json!({"names":["bundle_name"]})]);
    assert_eq!(report, json!({"members":[{"sections":[1]}]}));
    assert!(strip_audits(&mut report).is_err());
    Ok(())
}

#[test]
fn qualification_never_reuses_an_evidence_directory() -> Result<()> {
    let dir = tempdir()?;
    let output = dir.path().join("evidence");
    fs::create_dir(&output)?;
    fs::write(output.join("old"), "preserved")?;
    let error = qualify(
        dir.path(),
        QualifyArgs {
            output: output.clone(),
        },
    )
    .unwrap_err();
    assert!(error.to_string().contains("must be new"));
    assert_eq!(fs::read_to_string(output.join("old"))?, "preserved");
    Ok(())
}
