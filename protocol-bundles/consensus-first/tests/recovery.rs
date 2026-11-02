use std::fs;

use kontor_consensus_first::{WalInspection, inspect_protected_wal};
use malachitebft_wal as wal;

#[test]
fn missing_and_valid_empty_wal_are_distinct() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("wal");
    assert_eq!(
        inspect_protected_wal(&path).unwrap(),
        WalInspection::Missing
    );
    let mut log = wal::Log::open(&path).unwrap();
    log.reset(9).unwrap();
    drop(log);
    let original = fs::read(&path).unwrap();
    assert_eq!(
        inspect_protected_wal(&path).unwrap(),
        WalInspection::Present {
            height: 9,
            entries: 0
        }
    );
    assert_eq!(fs::read(&path).unwrap(), original);
}

#[test]
fn valid_entry_and_corrupt_or_truncated_tails() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("wal");
    let mut log = wal::Log::open(&path).unwrap();
    log.reset(12).unwrap();
    let encoded = [2, 2, 0, 0, 0, 0, 0, 0, 0, 2];
    log.write_raw(encoded).unwrap();
    drop(log);
    let valid = fs::read(&path).unwrap();
    assert_eq!(
        inspect_protected_wal(&path).unwrap(),
        WalInspection::Present {
            height: 12,
            entries: 1
        }
    );
    assert_eq!(fs::read(&path).unwrap(), valid);

    fs::write(&path, &valid[..valid.len() - 1]).unwrap();
    assert!(inspect_protected_wal(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), valid[..valid.len() - 1]);

    let mut corrupted = valid;
    *corrupted.last_mut().unwrap() ^= 1;
    fs::write(&path, &corrupted).unwrap();
    assert!(inspect_protected_wal(&path).is_err());
    assert_eq!(fs::read(&path).unwrap(), corrupted);

    fs::write(&path, []).unwrap();
    assert!(inspect_protected_wal(&path).is_err());
}
