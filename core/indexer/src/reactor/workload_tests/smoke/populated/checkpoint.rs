use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};

use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use serde_json::Value;
use tempfile::{NamedTempFile, TempDir, TempPath};

use super::super::hash_file;

#[derive(Clone)]
pub(super) struct Checkpoint {
    path: Arc<TempPath>,
}

impl Checkpoint {
    pub(super) fn directory() -> Result<TempDir> {
        // /tmp is tmpfs on the development host. Keep the full checkpoint set
        // in the workspace, whose backing filesystem is recorded with evidence.
        let root =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../../.build-cache/workload-checkpoints");
        fs::create_dir_all(&root)?;
        let directory = TempDir::new_in(root)?;
        eprintln!(
            "workload_checkpoint_directory={}",
            directory.path().display()
        );
        Ok(directory)
    }

    pub(super) fn capture(directory: &Path, projection: &Value) -> Result<Self> {
        let mut file = NamedTempFile::new_in(directory)?;
        {
            let mut writer = BufWriter::new(file.as_file_mut());
            serde_json::to_writer(&mut writer, projection)?;
            writer.flush()?;
        }
        // A full sequence can contain hundreds of complete database projections.
        // Retain bytes on disk and close their descriptors between comparisons.
        Ok(Self {
            path: Arc::new(file.into_temp_path()),
        })
    }

    pub(super) fn check(&self, expected: &Self) -> Result<()> {
        self.check_file(expected.path.as_ref())
    }

    pub(super) fn check_file(&self, expected: &Path) -> Result<()> {
        let mut actual = File::open(self.path.as_ref())?;
        let mut expected = File::open(expected)?;
        let mut remaining = actual.metadata()?.len();
        ensure!(
            remaining == expected.metadata()?.len(),
            "checkpoint byte lengths differ"
        );
        let mut actual_bytes = [0; 65536];
        let mut expected_bytes = [0; 65536];
        while remaining > 0 {
            let count = usize::try_from(remaining.min(actual_bytes.len() as u64))?;
            actual.read_exact(&mut actual_bytes[..count])?;
            expected.read_exact(&mut expected_bytes[..count])?;
            ensure!(
                actual_bytes[..count] == expected_bytes[..count],
                "checkpoint bytes differ"
            );
            remaining -= count as u64;
        }
        Ok(())
    }

    pub(super) fn record(
        checkpoints: &mut Vec<Self>,
        actual: Self,
        expected: Option<&[Self]>,
    ) -> Result<()> {
        let index = checkpoints.len();
        if let Some(expected) = expected {
            let expected = expected.get(index).context("unexpected extra checkpoint")?;
            actual
                .check(expected)
                .with_context(|| format!("replay checkpoint {index} differs"))?;
            // Reuse the first restore's handle in the retained sequence. BatchProof
            // may still hold the second file until its confirmation checks finish.
            checkpoints.push(expected.clone());
        } else {
            checkpoints.push(actual);
        }
        Ok(())
    }

    pub(super) fn export(&self, directory: &Path, name: &str) -> Result<String> {
        let mut source = File::open(self.path.as_ref())?;
        let mut output = NamedTempFile::new_in(directory)?;
        io::copy(&mut source, output.as_file_mut())?;
        output.as_file().sync_all()?;
        let digest = hash_file(output.path())?;
        output.persist_noclobber(directory.join(name))?;
        Ok(digest)
    }

    pub(super) fn load(&self) -> Result<Value> {
        Ok(serde_json::from_reader(BufReader::new(File::open(
            self.path.as_ref(),
        )?))?)
    }
}

#[test]
fn workload_sequence_checkpoints_compare_complete_bytes() -> Result<()> {
    let directory = Checkpoint::directory()?;
    let original = serde_json::json!({"first": "a".repeat(150_000), "last": [1, 2, 3]});
    let expected = Checkpoint::capture(directory.path(), &original)?;
    let copy = Checkpoint::capture(directory.path(), &original)?;
    copy.check(&expected)?;
    ensure!(copy.load()? == original);
    let mut changed = original.clone();
    changed["last"][1] = serde_json::json!(4);
    ensure!(
        Checkpoint::capture(directory.path(), &changed)?
            .check(&expected)
            .is_err()
    );
    changed["last"] = serde_json::json!([1, 2]);
    ensure!(
        Checkpoint::capture(directory.path(), &changed)?
            .check(&expected)
            .is_err()
    );
    let handle = expected.clone();
    drop(expected);
    copy.check(&handle)?;
    Ok(())
}
