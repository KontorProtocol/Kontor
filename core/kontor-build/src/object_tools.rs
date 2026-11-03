use std::collections::BTreeSet;
use std::ffi::{OsStr, OsString};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::toolchain::symbol_reader;

pub const GDB_SCRIPT: &str = "__rustc_debug_gdb_scripts_section__";
const GDB_PAYLOAD: &[u8] = b"\x01gdb_load_rust_pretty_printers.py\0";

#[derive(Deserialize)]
pub struct Request {
    working_directory: PathBuf,
    #[serde(flatten)]
    operation: Operation,
}

#[derive(Deserialize)]
#[serde(tag = "operation", rename_all = "snake_case")]
enum Operation {
    Executable,
    Inspect {
        arguments: Vec<String>,
    },
    ObjectRecords {
        path: PathBuf,
    },
    ArchiveMembers {
        path: PathBuf,
    },
    ArchiveMember {
        path: PathBuf,
        member: String,
    },
    SectionBytes {
        path: PathBuf,
        record: Value,
        section: Value,
    },
    CompilerDebugMetadata {
        path: PathBuf,
        #[serde(default)]
        linked: bool,
    },
}

pub fn run(request: Request) -> Result<Value> {
    let tools = ObjectTools::discover(&request.working_directory)?;
    Ok(match request.operation {
        Operation::Executable => json!(tools.reader),
        Operation::Inspect { arguments } => json!(
            tools.inspect(
                &arguments
                    .into_iter()
                    .map(OsString::from)
                    .collect::<Vec<_>>()
            )?
        ),
        Operation::ObjectRecords { path } => json!(tools.object_records(&path)?),
        Operation::ArchiveMembers { path } => json!(tools.archive_members(&path)?),
        // Hex avoids enormous JSON arrays in the audit reports.
        Operation::ArchiveMember { path, member } => {
            json!(hex::encode(tools.archive_member(&path, &member)?))
        }
        Operation::SectionBytes {
            path,
            record,
            section,
        } => json!(hex::encode(tools.section_bytes(&path, &record, &section)?)),
        Operation::CompilerDebugMetadata { path, linked } => {
            json!(tools.compiler_debug_metadata(&path, linked)?)
        }
    })
}

pub struct ObjectTools {
    reader: PathBuf,
    cwd: PathBuf,
}

impl ObjectTools {
    pub fn discover(cwd: &Path) -> Result<Self> {
        Ok(Self {
            reader: symbol_reader(cwd)?,
            cwd: cwd.to_owned(),
        })
    }

    fn output(&self, tool: &str, arguments: &[&OsStr]) -> Result<Vec<u8>> {
        let program = self.reader.with_file_name(tool);
        let result = Command::new(&program)
            .args(arguments)
            .current_dir(&self.cwd)
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("run {}", program.display()))?;
        ensure!(
            result.status.success(),
            "object inspection failed ({}): {}: {}",
            result.status,
            program.display(),
            String::from_utf8_lossy(&result.stderr)
        );
        Ok(result.stdout)
    }

    pub fn inspect(&self, arguments: &[OsString]) -> Result<String> {
        text(
            self.output(
                "llvm-nm",
                &arguments
                    .iter()
                    .map(OsString::as_os_str)
                    .collect::<Vec<_>>(),
            )?,
        )
    }

    pub fn object_records(&self, path: &Path) -> Result<Vec<Value>> {
        let bytes = self.output(
            "llvm-readobj",
            &[
                OsStr::new("--elf-output-style=JSON"),
                OsStr::new("--sections"),
                OsStr::new("--symbols"),
                path.as_os_str(),
            ],
        )?;
        serde_json::from_slice(&bytes)
            .with_context(|| format!("invalid object inspection records: {}", path.display()))
    }

    pub fn archive_members(&self, path: &Path) -> Result<Vec<String>> {
        let names: Vec<String> =
            text(self.output("llvm-ar", &[OsStr::new("t"), path.as_os_str()])?)?
                .lines()
                .map(str::to_owned)
                .collect();
        ensure!(
            !names.is_empty() && names.iter().collect::<BTreeSet<_>>().len() == names.len(),
            "archive has missing or duplicate member names: {}",
            path.display()
        );
        Ok(names)
    }

    pub fn archive_member(&self, path: &Path, member: &str) -> Result<Vec<u8>> {
        self.output(
            "llvm-ar",
            &[OsStr::new("p"), path.as_os_str(), OsStr::new(member)],
        )
    }

    pub fn section_bytes(&self, path: &Path, record: &Value, section: &Value) -> Result<Vec<u8>> {
        let label = record["FileSummary"]["File"]
            .as_str()
            .context("missing object file identity")?;
        let name = path.to_str().context("object input path must be UTF8")?;
        let start = number(section, "Offset")?;
        let size = number(section, "Size")?;
        let end = start.checked_add(size).context("section range overflow")?;
        if let Some(member) = label
            .strip_prefix(&format!("{name}("))
            .and_then(|tail| tail.strip_suffix(')'))
        {
            let bytes = self.archive_member(path, member)?;
            ensure!(
                end <= bytes.len() as u64,
                "section extends beyond archive member: {label}"
            );
            return Ok(bytes[usize::try_from(start)?..usize::try_from(end)?].to_vec());
        }
        ensure!(
            label == name,
            "object reader changed input identity: {label}"
        );
        let mut file = File::open(self.cwd.join(path))?;
        ensure!(
            end <= file.metadata()?.len(),
            "section extends beyond object: {}",
            path.display()
        );
        file.seek(SeekFrom::Start(start))?;
        let mut bytes = Vec::new();
        file.take(size).read_to_end(&mut bytes)?;
        ensure!(
            bytes.len() as u64 == size,
            "section extends beyond object: {}",
            path.display()
        );
        Ok(bytes)
    }

    pub fn compiler_debug_metadata(&self, path: &Path, linked: bool) -> Result<usize> {
        ensure!(
            cfg!(target_os = "linux"),
            "compiler GDB metadata requires an audited ELF object"
        );
        self.check_debug_records(path, &self.object_records(path)?, linked)
    }

    fn check_debug_records(&self, path: &Path, records: &[Value], linked: bool) -> Result<usize> {
        let mut found = 0;
        for record in records {
            let sections = entries(record, "Sections")?;
            for item in entries(record, "Symbols")? {
                let symbol = &item["Symbol"];
                if symbol["Name"]["Name"] != GDB_SCRIPT {
                    continue;
                }
                found += 1;
                let section = sections
                    .iter()
                    .map(|item| &item["Section"])
                    .find(|section| {
                        section["Index"].is_u64() && section["Index"] == symbol["Section"]["Value"]
                    })
                    .context("invalid compiler GDB metadata section")?;
                ensure!(
                    symbol["Binding"]["Name"] == "Weak"
                        && symbol["Type"]["Name"] == "Object"
                        && symbol["Size"] == GDB_PAYLOAD.len()
                        && symbol["Other"]["Value"] == 0
                        && section["Name"]["Name"] == ".debug_gdb_scripts"
                        && section["Type"]["Name"] == "SHT_PROGBITS"
                        && section["Flags"]["Value"] == 0x32
                        && section["AddressAlignment"] == 1
                        && section["EntrySize"] == 1,
                    "invalid compiler GDB metadata definition: {}",
                    record["FileSummary"]["File"]
                );
                let offset = number(symbol, "Value")?
                    .checked_sub(number(section, "Address")?)
                    .context("invalid compiler GDB metadata offset")?;
                let end = offset
                    .checked_add(GDB_PAYLOAD.len() as u64)
                    .context("invalid compiler GDB metadata range")?;
                let size = number(section, "Size")?;
                ensure!(
                    end <= size && (linked || (offset == 0 && size == GDB_PAYLOAD.len() as u64)),
                    "invalid compiler GDB metadata payload: {}",
                    path.display()
                );
                let bytes = self.section_bytes(path, record, section)?;
                ensure!(
                    &bytes[usize::try_from(offset)?..usize::try_from(end)?] == GDB_PAYLOAD,
                    "invalid compiler GDB metadata payload: {}",
                    path.display()
                );
            }
        }
        ensure!(
            found > 0,
            "compiler GDB metadata definition missing: {}",
            path.display()
        );
        Ok(found)
    }
}

fn number(value: &Value, name: &str) -> Result<u64> {
    value[name]
        .as_u64()
        .with_context(|| format!("invalid object {name}"))
}

fn entries<'a>(value: &'a Value, name: &str) -> Result<&'a [Value]> {
    match value.get(name) {
        None => Ok(&[]),
        Some(value) => value
            .as_array()
            .map(Vec::as_slice)
            .with_context(|| format!("invalid object {name}")),
    }
}

fn text(bytes: Vec<u8>) -> Result<String> {
    Ok(String::from_utf8(bytes)?
        .replace("\r\n", "\n")
        .replace('\r', "\n"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::PermissionsExt;
    use tempfile::tempdir;

    #[test]
    fn failed_readers_reject_partial_output_and_malformed_records() -> Result<()> {
        let dir = tempdir()?;
        let reader = dir.path().join("llvm-nm");
        let tools = ObjectTools {
            reader: reader.clone(),
            cwd: dir.path().to_owned(),
        };
        fs::write(
            &reader,
            "#!/bin/sh\nprintf '00000000 T partial\\n'\nprintf 'incompatible bitcode' >&2\nexit 1\n",
        )?;
        fs::set_permissions(&reader, fs::Permissions::from_mode(0o755))?;
        assert!(
            tools
                .inspect(&[])
                .unwrap_err()
                .to_string()
                .contains("incompatible bitcode")
        );
        let object_reader = reader.with_file_name("llvm-readobj");
        for output in ["{}", "not JSON"] {
            fs::write(
                &object_reader,
                format!("#!/bin/sh\nprintf '%s' '{output}'\n"),
            )?;
            fs::set_permissions(&object_reader, fs::Permissions::from_mode(0o755))?;
            assert!(tools.object_records(Path::new("anything")).is_err());
        }
        let archiver = reader.with_file_name("llvm-ar");
        for output in ["", "object.o\\nobject.o\\n"] {
            fs::write(&archiver, format!("#!/bin/sh\nprintf '{output}'\n"))?;
            fs::set_permissions(&archiver, fs::Permissions::from_mode(0o755))?;
            assert!(tools.archive_members(Path::new("anything")).is_err());
        }
        Ok(())
    }

    #[test]
    fn section_ranges_bind_identity_and_reject_overflow_and_truncation() -> Result<()> {
        let dir = tempdir()?;
        fs::write(dir.path().join("input.o"), b"abcd")?;
        let tools = ObjectTools {
            reader: dir.path().join("llvm-nm"),
            cwd: dir.path().to_owned(),
        };
        let path = Path::new("input.o");
        let record = json!({"FileSummary": {"File": "input.o"}});
        assert_eq!(
            tools.section_bytes(path, &record, &json!({"Offset": 1, "Size": 2}))?,
            b"bc"
        );
        for section in [
            json!({"Offset": 3, "Size": 2}),
            json!({"Offset": -1, "Size": 2}),
            json!({"Offset": u64::MAX, "Size": 1}),
            json!({"Offset": 0}),
            json!({"Offset": 0, "Size": "4"}),
        ] {
            assert!(tools.section_bytes(path, &record, &section).is_err());
        }
        assert!(
            tools
                .section_bytes(
                    path,
                    &json!({"FileSummary": {"File": "other.o"}}),
                    &json!({"Offset": 0, "Size": 1})
                )
                .is_err()
        );
        assert!(
            tools
                .check_debug_records(path, &[json!({"Symbols": {}})], false)
                .is_err()
        );
        assert!(tools.check_debug_records(path, &[], false).is_err());
        Ok(())
    }
}
