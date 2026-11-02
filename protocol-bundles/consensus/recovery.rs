use std::fs::{self, File};
use std::io::{self, Cursor, Read, Write};
use std::path::Path;

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;

use malachitebft_engine::wal::decode_entry;
use malachitebft_wal as wal;
use sha3::{Digest, Keccak256};
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
    let (copied, original_digest) = copy_and_digest(&mut source, &mut copy)?;
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
    if file_digest(copy.path())? != original_digest {
        return Err(invalid("WAL copy changed during validation"));
    }
    Ok(WalInspection::Present { height, entries })
}

fn copy_and_digest(
    source: &mut impl Read,
    destination: &mut impl Write,
) -> io::Result<(u64, [u8; 32])> {
    let mut hasher = Keccak256::new();
    let mut copied = 0u64;
    let mut buffer = [0u8; 8192];
    loop {
        let count = source.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        destination.write_all(&buffer[..count])?;
        hasher.update(&buffer[..count]);
        copied = copied
            .checked_add(count as u64)
            .ok_or_else(|| invalid("WAL length overflow"))?;
    }
    Ok((copied, hasher.finalize().into()))
}

fn file_digest(path: &Path) -> io::Result<[u8; 32]> {
    let mut file = File::open(path)?;
    let mut hasher = Keccak256::new();
    let mut buffer = [0u8; 8192];
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        hasher.update(&buffer[..count]);
    }
    Ok(hasher.finalize().into())
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
