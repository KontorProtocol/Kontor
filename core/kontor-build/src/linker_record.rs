use std::env;
use std::ffi::CString;
use std::fs;
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf, absolute};
use std::process::Command;

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

pub fn digest(path: &Path) -> Result<String> {
    Ok(hex::encode(Sha256::digest(fs::read(path)?)))
}

fn text(bytes: Vec<u8>) -> Result<String> {
    // Match previous text-mode reads, including response files with CRLF.
    Ok(String::from_utf8(bytes)?
        .replace("\r\n", "\n")
        .replace('\r', "\n"))
}

// Python's previous shlex.split used comments=False and retained escaped newlines.
// Shell parsers in common Rust crates differ on these cases and on quoted \$.
fn split_words(text: &str) -> Result<Vec<String>> {
    let mut result = Vec::new();
    let mut word = String::new();
    let mut started = false;
    let mut quote = None;
    let mut characters = text.chars();
    while let Some(character) = characters.next() {
        match (quote, character) {
            (Some('\''), '\'') | (Some('"'), '"') => quote = None,
            (Some('\''), _) => word.push(character),
            (Some('"'), '\\') => {
                let next = characters
                    .next()
                    .context("unterminated escape in linker arguments")?;
                if !matches!(next, '\\' | '"') {
                    word.push('\\');
                }
                word.push(next);
            }
            (Some('"'), _) => word.push(character),
            (None, '\'' | '"') => {
                quote = Some(character);
                started = true;
            }
            (None, '\\') => {
                word.push(
                    characters
                        .next()
                        .context("unterminated escape in linker arguments")?,
                );
                started = true;
            }
            (None, ' ' | '\t' | '\r' | '\n') => {
                if started {
                    result.push(std::mem::take(&mut word));
                    started = false;
                }
            }
            (None, _) => {
                word.push(character);
                started = true;
            }
            _ => unreachable!(),
        }
    }
    ensure!(quote.is_none(), "unterminated quote in linker arguments");
    if started {
        result.push(word);
    }
    Ok(result)
}

fn expand(arguments: &[String], depth: usize) -> Result<Vec<String>> {
    ensure!(
        depth <= 4,
        "nested linker response files exceed supported depth"
    );
    let mut expanded = Vec::new();
    for argument in arguments {
        if let Some(path) = argument.strip_prefix('@') {
            expanded.extend(expand(&split_words(&text(fs::read(path)?)?)?, depth + 1)?);
        } else {
            expanded.push(argument.clone());
        }
    }
    Ok(expanded)
}

fn executable_file(path: &Path) -> bool {
    if !path.is_file() {
        return false;
    }
    let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
        return false;
    };
    // Match shutil.which's access check, including permissions and ACLs. The
    // owned C string remains valid for the call and contains no interior NUL.
    unsafe { libc::access(path.as_ptr(), libc::X_OK) == 0 }
}

pub fn executable(name: &str) -> Result<Value> {
    let candidate = Path::new(name);
    let path = if name.contains('/') {
        ensure!(
            executable_file(candidate),
            "linker executable unavailable: {name}"
        );
        candidate.to_path_buf()
    } else {
        env::split_paths(&env::var_os("PATH").unwrap_or_else(|| "/bin:/usr/bin".into()))
            .map(|directory| directory.join(candidate))
            .find(|path| executable_file(path))
            .context(format!("linker executable unavailable: {name}"))?
    };
    let invocation = absolute(path)?;
    let resolved = invocation.canonicalize()?;
    Ok(json!({"invocation_path": invocation, "path": resolved, "sha256": digest(&resolved)?}))
}

fn string<'a>(value: &'a Value, key: &str) -> Result<&'a str> {
    value
        .get(key)
        .and_then(Value::as_str)
        .context(format!("missing linker {key}"))
}

fn command_output(arguments: &[String]) -> Result<std::process::Output> {
    let output = Command::new(&arguments[0]).args(&arguments[1..]).output()?;
    ensure!(
        output.status.success(),
        "linker driver query failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(output)
}

fn backend(driver: &str, arguments: &[String], expanded: &[String]) -> Result<(Value, Value)> {
    ensure!(
        env::var_os("COLLECT_LD_OVERRIDE").is_none_or(|value| value.is_empty()),
        "COLLECT_LD_OVERRIDE is not supported by linker qualification"
    );
    ensure!(
        !expanded.iter().any(|arg| ["-specs", "--specs", "-wrapper"]
            .iter()
            .any(|prefix| arg.starts_with(prefix))),
        "custom compiler specs/wrappers need explicit linker qualification"
    );
    let mut command = vec![driver.into(), "-###".into()];
    command.extend_from_slice(arguments);
    let plan = command_output(&command)?;
    let stdout = text(plan.stdout)?;
    let stderr = text(plan.stderr)?;
    let mut commands = Vec::new();
    for line in stderr.lines() {
        if let Ok(words) = split_words(line)
            && let Some(first) = words.first()
            && matches!(
                Path::new(first).file_name().and_then(|name| name.to_str()),
                Some(
                    "collect2"
                        | "ld"
                        | "ld.lld"
                        | "ld.gold"
                        | "ld.bfd"
                        | "ld64.lld"
                        | "lld"
                        | "rust-lld"
                        | "mold"
                        | "ld.mold"
                )
            )
        {
            commands.push(words);
        }
    }
    ensure!(
        commands.len() == 1,
        "driver did not identify exactly one supported linker command"
    );
    let mut selected = commands[0][0].clone();
    let mut query = None;
    if Path::new(&selected)
        .file_name()
        .is_some_and(|name| name == "collect2")
    {
        let mut search = Vec::new();
        let mut variant = None;
        let mut arguments = expanded.iter();
        while let Some(argument) = arguments.next() {
            if argument == "-B" {
                search.push(argument.clone());
                search.push(
                    arguments
                        .next()
                        .context("missing linker search directory")?
                        .clone(),
                );
            } else if argument.starts_with("-B") {
                search.push(argument.clone());
            } else if let Some(value) = argument.strip_prefix("-fuse-ld=") {
                variant = Some(value);
            }
        }
        ensure!(
            variant.is_none_or(|value| matches!(value, "bfd" | "gold" | "lld" | "mold")),
            "unsupported GCC linker variant"
        );
        let name = variant
            .map(|value| format!("ld.{value}"))
            .unwrap_or_else(|| "ld".into());
        let mut arguments = vec![driver.into()];
        arguments.extend(search);
        arguments.push(format!("-print-prog-name={name}"));
        selected = text(command_output(&arguments)?.stdout)?.trim().into();
        query = Some(arguments);
    }
    Ok((
        executable(&selected)?,
        json!({"method":"compiler-driver-plan", "command":command,
        "stdout":stdout, "stderr":stderr, "backend_query":query}),
    ))
}

fn hash(value: &Value) -> bool {
    value.as_str().is_some_and(|text| {
        text.len() == 64
            && text
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    })
}

fn strings(value: &Value) -> Option<Vec<&str>> {
    value.as_array()?.iter().map(Value::as_str).collect()
}

fn output_path(arguments: &[&str], directory: &Path) -> Result<PathBuf> {
    ensure!(
        arguments.iter().filter(|arg| **arg == "-o").count() == 1,
        "linker output path missing or ambiguous"
    );
    let index = arguments.iter().position(|arg| *arg == "-o").unwrap();
    let path = Path::new(
        arguments
            .get(index + 1)
            .context("missing linker output path")?,
    );
    Ok(absolute(if path.is_absolute() {
        path.into()
    } else {
        directory.join(path)
    })?)
}

pub fn validate(
    record: &Value,
    spec_hash: &str,
    output_hash: &str,
    compiler_output: Option<&Value>,
) -> Result<()> {
    ensure!(
        record["schema"] == 1
            && record["spec_sha256"] == spec_hash
            && hash(&record["output_sha256"]),
        "linker record does not match the node build"
    );
    if let Some(completed) = compiler_output {
        ensure!(
            completed
                .as_object()
                .is_some_and(|object| object.len() == 2)
                && completed["path"] == record["output"]
                && completed["path"].is_string()
                && completed["sha256"] == output_hash,
            "compiler output does not match the node build"
        );
    } else {
        ensure!(
            record["output_sha256"] == output_hash,
            "linker record does not match the node build"
        );
    }
    for name in ["driver", "backend"] {
        let tool = &record[name];
        ensure!(
            tool.as_object().is_some_and(|object| object.len() == 3)
                && ["invocation_path", "path"].iter().all(|key| tool[key]
                    .as_str()
                    .is_some_and(|path| Path::new(path).is_absolute()))
                && hash(&tool["sha256"]),
            "linker executable provenance is incomplete"
        );
    }
    let arguments =
        strings(&record["arguments"]).context("linker invocation provenance is incomplete")?;
    let expanded = strings(&record["expanded_arguments"])
        .context("linker invocation provenance is incomplete")?;
    let directory = Path::new(string(record, "working_directory")?);
    let selection = &record["selection"];
    let mut expected = vec![string(&record["driver"], "invocation_path")?, "-###"];
    expected.extend(arguments);
    ensure!(
        directory.is_absolute()
            && selection["method"] == "compiler-driver-plan"
            && selection["command"] == json!(expected)
            && selection["stderr"]
                .as_str()
                .is_some_and(|text| !text.is_empty()),
        "linker invocation provenance is incomplete"
    );
    ensure!(
        json!(output_path(&expanded, directory)?) == record["output"],
        "linker invocation targets another output"
    );
    Ok(())
}

#[derive(Deserialize)]
pub struct Verification {
    pub record: Value,
    pub spec_hash: String,
    pub output_hash: String,
    pub compiler_output: Option<Value>,
}

pub fn verify_input() -> Result<()> {
    let input: Verification = serde_json::from_reader(io::stdin().lock())?;
    validate(
        &input.record,
        &input.spec_hash,
        &input.output_hash,
        input.compiler_output.as_ref(),
    )
}

pub fn run() -> Result<i32> {
    let arguments = env::args_os()
        .skip(1)
        .map(|value| {
            value
                .into_string()
                .map_err(|_| anyhow::anyhow!("linker evidence requires UTF-8 arguments"))
        })
        .collect::<Result<Vec<_>>>()?;
    if arguments == ["--verify-record"] {
        verify_input()?;
        return Ok(0);
    }
    let spec_path = PathBuf::from(
        env::var_os("KONTOR_NODE_LINK_SPEC").context("missing node link specification")?,
    );
    let spec_bytes = fs::read(&spec_path)?;
    let spec_hash = hex::encode(Sha256::digest(&spec_bytes));
    let spec: Value = serde_json::from_slice(&spec_bytes)?;
    let record_path = Path::new(string(&spec, "linker_record")?);
    match fs::remove_file(record_path) {
        Ok(()) => (),
        Err(error) if error.kind() == io::ErrorKind::NotFound => (),
        Err(error) => return Err(error.into()),
    }
    let driver = executable(&env::var("KONTOR_REAL_LINKER")?)?;
    let expanded = expand(&arguments, 0)?;
    let (selected, selection) =
        backend(string(&driver, "invocation_path")?, &arguments, &expanded)?;
    let directory = env::current_dir()?;
    let output = output_path(
        &expanded.iter().map(String::as_str).collect::<Vec<_>>(),
        &directory,
    )?;
    ensure!(
        expand(&arguments, 0)? == expanded,
        "linker response arguments changed during driver selection"
    );
    let status = Command::new(string(&driver, "invocation_path")?)
        .args(&arguments)
        .status()?;
    if !status.success() {
        return Ok(status
            .code()
            .unwrap_or_else(|| 128 + status.signal().unwrap_or(0)));
    }
    for tool in [&driver, &selected] {
        ensure!(
            digest(Path::new(string(tool, "path")?))? == tool["sha256"],
            "linker tool changed during invocation"
        );
    }
    ensure!(
        digest(&spec_path)? == spec_hash,
        "node link specification changed during linking"
    );
    ensure!(
        expand(&arguments, 0)? == expanded,
        "linker response arguments changed during linking"
    );
    let record = json!({"schema":1,"spec_sha256":spec_hash,"driver":driver,"backend":selected,"selection":selection,
        "arguments":arguments,"expanded_arguments":expanded,"working_directory":directory,
        "output":output,"output_sha256":digest(&output)?});
    validate(&record, &spec_hash, string(&record, "output_sha256")?, None)?;
    fs::write(record_path, format!("{record}\n"))?;
    Ok(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::slice::from_ref;
    use tempfile::tempdir;

    #[test]
    fn word_splitting_preserves_previous_response_and_plan_syntax() -> Result<()> {
        for (input, expected) in [
            ("a 'b c' \"d e\" f\\ g", vec!["a", "b c", "d e", "f g"]),
            ("'' \"\" a\"\"b #literal", vec!["", "", "ab", "#literal"]),
            ("a\rb\tc\nd", vec!["a", "b", "c", "d"]),
            ("'a\\b' \"a\\$b\" \"a\\`b\"", vec!["a\\b", "a\\$b", "a\\`b"]),
            ("a\\\nb \"a\\\nb\"", vec!["a\nb", "a\\\nb"]),
            ("\"a\\\"b\\\\c\"", vec!["a\"b\\c"]),
        ] {
            assert_eq!(split_words(input)?, expected, "{input:?}");
        }
        for input in ["'open", "\"open", "escape\\", "\"escape\\"] {
            assert!(split_words(input).is_err(), "{input:?}");
        }
        Ok(())
    }

    #[test]
    fn response_expansion_is_bounded_and_rejects_missing_and_malformed_inputs() -> Result<()> {
        let root = tempdir()?;
        for index in (0..4).rev() {
            let content = if index == 3 {
                "'-o' 'program name'".into()
            } else {
                format!("@{}", root.path().join((index + 1).to_string()).display())
            };
            fs::write(root.path().join(index.to_string()), content)?;
        }
        let first = format!("@{}", root.path().join("0").display());
        assert_eq!(expand(from_ref(&first), 0)?, ["-o", "program name"]);
        fs::write(root.path().join("3"), "'-o' 'program\r\nname'")?;
        assert_eq!(expand(from_ref(&first), 0)?, ["-o", "program\nname"]);
        fs::write(root.path().join("3"), &first)?;
        assert!(
            expand(from_ref(&first), 0)
                .unwrap_err()
                .to_string()
                .contains("depth")
        );
        fs::write(root.path().join("3"), "'open")?;
        assert!(expand(from_ref(&first), 0).is_err());
        fs::remove_file(root.path().join("3"))?;
        assert!(expand(&[first], 0).is_err());
        Ok(())
    }

    fn record() -> Value {
        json!({"schema":1,"spec_sha256":"spec","output_sha256":"ab".repeat(32),"output":"/build/program",
            "arguments":["-o","program"],"expanded_arguments":["-o","program"],"working_directory":"/build",
            "driver":{"invocation_path":"/bin/cc","path":"/bin/cc-real","sha256":"cd".repeat(32)},
            "backend":{"invocation_path":"/bin/ld","path":"/bin/ld-real","sha256":"ef".repeat(32)},
            "selection":{"method":"compiler-driver-plan","command":["/bin/cc","-###","-o","program"],"stderr":"linker plan"}})
    }

    #[test]
    fn evidence_binds_spec_output_tools_and_actual_invocation() -> Result<()> {
        let record = record();
        validate(&record, "spec", &"ab".repeat(32), None)?;
        for path in ["./program", "/build/./program", "/build//program"] {
            assert_eq!(
                output_path(&["-o", path], Path::new("/build"))?.to_str(),
                Some("/build/program")
            );
        }
        for field in [
            "schema",
            "spec_sha256",
            "output_sha256",
            "output",
            "driver",
            "backend",
            "arguments",
            "expanded_arguments",
            "working_directory",
            "selection",
        ] {
            let mut changed = record.clone();
            changed[field] = json!("wrong");
            assert!(
                validate(&changed, "spec", &"ab".repeat(32), None).is_err(),
                "{field}"
            );
        }
        for arguments in [
            json!([]),
            json!(["-o"]),
            json!(["-o", "x", "-o", "y"]),
            json!(["-o", 1]),
        ] {
            let mut changed = record.clone();
            changed["expanded_arguments"] = arguments;
            assert!(validate(&changed, "spec", &"ab".repeat(32), None).is_err());
        }
        for field in ["invocation_path", "path", "sha256"] {
            let mut changed = record.clone();
            changed["backend"][field] = json!("invalid");
            assert!(validate(&changed, "spec", &"ab".repeat(32), None).is_err());
        }
        Ok(())
    }

    #[test]
    fn completed_output_allows_post_link_processing_without_replacing_linker_hash() -> Result<()> {
        let record = record();
        let completed = json!({"path":"/build/program","sha256":"00".repeat(32)});
        validate(&record, "spec", &"00".repeat(32), Some(&completed))?;
        assert!(validate(&record, "spec", &"00".repeat(32), None).is_err());
        for changed in [
            json!({}),
            json!([]),
            json!({"path":"/elsewhere","sha256":"00".repeat(32)}),
            json!({"path":"/build/program","sha256":"ab".repeat(32)}),
            json!({"path":"/build/program","sha256":"00".repeat(32),"extra":true}),
        ] {
            assert!(validate(&record, "spec", &"00".repeat(32), Some(&changed)).is_err());
        }
        Ok(())
    }
}
