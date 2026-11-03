mod dependencies;
mod paths;

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result, bail, ensure};
use clap::ValueEnum;
use serde_json::{Value, json};

use dependencies::{docker_target_paths, validate_repro_dependencies};
use paths::{bundle_relevant, classify, stack_relevant};

const JOBS: [&str; 5] = ["rust", "sdk", "reproducible", "docker_cache", "tooling"];

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
pub enum CiScope {
    Pr,
    Stack,
    Bundles,
}

pub fn ci_scope(root: &Path, kind: CiScope) -> Result<()> {
    let event_name = env::var("GITHUB_EVENT_NAME").context("GITHUB_EVENT_NAME is required")?;
    let event: Value = serde_json::from_slice(&fs::read(env::var("GITHUB_EVENT_PATH")?)?)?;
    let report = select(root, kind, &event_name, &event)?;
    println!("{}", serde_json::to_string_pretty(&report)?);
    if let Some(path) = env::var_os("GITHUB_OUTPUT") {
        let mut output = OpenOptions::new().create(true).append(true).open(path)?;
        for (name, value) in outputs(kind, &report)? {
            writeln!(output, "{name}={value}")?;
        }
    }
    Ok(())
}

fn outputs(kind: CiScope, report: &Value) -> Result<BTreeMap<String, String>> {
    let mut result = BTreeMap::new();
    if kind == CiScope::Pr {
        for name in JOBS {
            let selected = report["jobs"][name]
                .as_bool()
                .context("invalid job selection")?;
            result.insert(name.into(), selected.to_string());
        }
    } else {
        result.insert(
            "required".into(),
            report["required"]
                .as_bool()
                .context("invalid qualification selection")?
                .to_string(),
        );
        result.insert(
            "profile_policy".into(),
            report["profile_policy"]
                .as_str()
                .context("invalid profile policy")?
                .into(),
        );
        if kind == CiScope::Bundles {
            result.insert(
                "controls".into(),
                report["controls"]
                    .as_bool()
                    .context("invalid controls selection")?
                    .to_string(),
            );
        }
    }
    Ok(result)
}

fn profile_policy<'a>(name: &str, event: &'a Value) -> Result<&'a str> {
    let policy = if name == "workflow_dispatch" {
        match event
            .get("inputs")
            .and_then(|inputs| inputs.get("profiles"))
        {
            Some(value) => value
                .as_str()
                .context("invalid qualification profile policy")?,
            None => "release",
        }
    } else {
        "release"
    };
    ensure!(
        ["release", "full"].contains(&policy),
        "unknown qualification profile policy"
    );
    Ok(policy)
}

fn changed_paths(root: &Path, name: &str, event: &Value) -> Result<Vec<String>> {
    let (base, head, separator) = match name {
        "pull_request" => (
            &event["pull_request"]["base"]["sha"],
            &event["pull_request"]["head"]["sha"],
            "...",
        ),
        "push" => (&event["before"], &event["after"], ".."),
        _ => bail!("unsupported event: {name}"),
    };
    let commit = |value: &Value| -> Result<String> {
        let sha = value.as_str().context("missing comparison commit")?;
        ensure!(
            sha.len() == 40
                && sha
                    .bytes()
                    .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
                && sha.bytes().any(|byte| byte != b'0'),
            "invalid comparison commit"
        );
        Ok(sha.into())
    };
    let revision = format!("{}{separator}{}", commit(base)?, commit(head)?);
    // No rename detection: both the removed and added names must participate.
    let output = Command::new("git")
        .current_dir(root)
        .args(["diff", "--name-only", "--no-renames", "-z", &revision, "--"])
        .output()?;
    ensure!(
        output.status.success(),
        "cannot read comparison commits: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|path| !path.is_empty())
        .map(|path| String::from_utf8(path.to_vec()).context("changed path is not UTF-8"))
        .collect()
}

fn select(root: &Path, kind: CiScope, name: &str, event: &Value) -> Result<Value> {
    let mut result = match select_known(root, kind, name, event) {
        Ok(result) => result,
        Err(error) => {
            // Unknown scope increases coverage instead of silently skipping CI.
            if kind == CiScope::Pr {
                json!({"jobs": job_flags(&JOBS.into_iter().collect()), "reason": format!("cannot establish scope: {error:#}"), "paths": []})
            } else {
                json!({"required": true, "reason": format!("cannot establish change scope: {error:#}"), "paths": []})
            }
        }
    };
    if kind != CiScope::Pr {
        result["profile_policy"] = json!(profile_policy(name, event)?);
        if kind == CiScope::Bundles && result.get("controls").is_none() {
            result["controls"] = json!(true);
        }
    }
    Ok(result)
}

fn select_known(root: &Path, kind: CiScope, name: &str, event: &Value) -> Result<Value> {
    if kind == CiScope::Pr {
        validate_repro_dependencies(root)?;
    }
    if name == "workflow_dispatch" {
        return Ok(if kind == CiScope::Pr {
            json!({"jobs": job_flags(&JOBS.into_iter().collect()), "reason": "manual run", "paths": []})
        } else {
            json!({"required": true, "reason": "manual qualification", "paths": []})
        });
    }
    let paths = changed_paths(root, name, event)?;
    if kind == CiScope::Pr {
        let targets = docker_target_paths(root)?;
        let jobs = paths
            .iter()
            .flat_map(|path| classify(path, &targets))
            .collect();
        return Ok(json!({"jobs": job_flags(&jobs), "reason": "changed inputs", "paths": paths}));
    }
    let mut selected = Vec::new();
    for path in &paths {
        let relevant = match kind {
            CiScope::Stack => stack_relevant(path),
            CiScope::Bundles => bundle_relevant(path),
            CiScope::Pr => unreachable!(),
        };
        if relevant {
            selected.push(path.clone());
        }
    }
    selected.sort();
    let required = !selected.is_empty();
    let reason = match (kind, required) {
        (CiScope::Stack, true) => "execution or build inputs changed",
        (CiScope::Stack, false) => "no stack qualification inputs changed",
        (_, true) => "node or build inputs changed",
        (_, false) => "no linked-node inputs changed",
    };
    let mut result = json!({"required": required, "reason": reason, "paths": selected});
    if kind == CiScope::Bundles {
        result["controls"] = json!(required);
    }
    Ok(result)
}

fn job_flags(selected: &BTreeSet<&str>) -> BTreeMap<&'static str, bool> {
    JOBS.into_iter()
        .map(|name| (name, selected.contains(name)))
        .collect()
}

#[cfg(test)]
mod tests;
