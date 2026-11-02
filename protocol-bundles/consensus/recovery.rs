use std::fs::{self, File};
use std::io::{self, Cursor};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use malachitebft_engine::wal::decode_entry;
use malachitebft_wal as wal;
use tempfile::NamedTempFile;

use crate::consensus::{Ctx, codec::ProtobufCodec};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalInspection {
    Missing,
    Present { height: u64, entries: u64 },
}

pub fn inspect_protected_wal(path: &Path) -> io::Result<WalInspection> {
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(WalInspection::Missing),
        Err(error) => return Err(error),
    };
    if !before.file_type().is_file() {
        return Err(invalid("WAL is not a plain file"));
    }
    let mut source = File::open(path)?;
    let opened = source.metadata()?;
    if !opened.file_type().is_file() || !same_file(&before, &opened) {
        return Err(invalid("WAL changed while opening"));
    }

    // The pinned Log::open repairs incomplete tails, so it must only see a private copy.
    let mut copy = NamedTempFile::new()?;
    let copied = io::copy(&mut source, &mut copy)?;
    if copied != before.len() || !same_file(&before, &fs::symlink_metadata(path)?) {
        return Err(invalid("WAL changed while copying"));
    }
    let mut log = wal::Log::open(copy.path())?;
    if copy.as_file().metadata()?.len() != copied {
        return Err(invalid("WAL has an incomplete tail or header"));
    }
    let height = log.sequence();
    let mut entries = 0u64;
    for entry in log.iter()? {
        let bytes = entry?;
        let mut cursor = Cursor::new(bytes.as_slice());
        decode_entry::<Ctx, ProtobufCodec, _>(&ProtobufCodec, &mut cursor)?;
        if cursor.position() != bytes.len() as u64 {
            return Err(invalid("WAL entry has trailing bytes"));
        }
        entries = entries
            .checked_add(1)
            .ok_or_else(|| invalid("WAL entry count overflow"))?;
    }
    if !same_file(&before, &fs::symlink_metadata(path)?) {
        return Err(invalid("WAL changed while inspecting"));
    }
    Ok(WalInspection::Present { height, entries })
}

fn invalid(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, reason)
}

#[cfg(unix)]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.len() == b.len()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}

#[cfg(not(unix))]
fn same_file(a: &fs::Metadata, b: &fs::Metadata) -> bool {
    a.len() == b.len()
}
