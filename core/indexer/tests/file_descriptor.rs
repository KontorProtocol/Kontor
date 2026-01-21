use indexer::database::types::bytes_to_field_element;
use indexer::runtime::RawFileDescriptor;
use indexer::runtime::wit::FileDescriptor;

fn create_valid_seed() -> [u8; 64] {
    let mut seed = [0u8; 64];
    seed[0] = 1;
    seed
}

#[test]
fn test_build_challenge_success() {
    let metadata = create_fake_file_metadata("file1", "test.txt", 800000);
    let descriptor = FileDescriptor::from_row(metadata);

    let seed = create_valid_seed();
    let result = descriptor.build_challenge(800000, 100, &seed, "prover1".to_string());

    assert!(
        result.is_ok(),
        "build_challenge should succeed with valid inputs"
    );
    let challenge = result.unwrap();

    // Verify the challenge has the expected properties
    assert_eq!(challenge.block_height, 800000);
    assert_eq!(challenge.num_challenges, 100);
    assert_eq!(challenge.prover_id, "prover1");
}

#[test]
fn test_build_challenge_invalid_seed_length() {
    let metadata = create_fake_file_metadata("file1", "test.txt", 800000);
    let descriptor = FileDescriptor::from_row(metadata);

    // Use a seed that's too short
    let short_seed = [0u8; 16];
    let result = descriptor.build_challenge(800000, 100, &short_seed, "prover1".to_string());

    assert!(
        result.is_err(),
        "build_challenge should fail with invalid seed length"
    );
    let err = result.unwrap_err();
    assert!(
        matches!(err, indexer::runtime::Error::Validation(_)),
        "Error should be a Validation error"
    );
}

#[test]
fn test_build_challenge_empty_seed() {
    let metadata = create_fake_file_metadata("file1", "test.txt", 800000);
    let descriptor = FileDescriptor::from_row(metadata);

    let result = descriptor.build_challenge(800000, 100, &[], "prover1".to_string());

    assert!(
        result.is_err(),
        "build_challenge should fail with empty seed"
    );
}

#[test]
fn test_compute_challenge_id_success() {
    let metadata = create_fake_file_metadata("file1", "test.txt", 800000);
    let descriptor = FileDescriptor::from_row(metadata);

    let seed = create_valid_seed();
    let result = descriptor.compute_challenge_id(800000, 100, &seed, "prover1".to_string());

    assert!(result.is_ok(), "compute_challenge_id should succeed");
    let challenge_id = result.unwrap();

    // Challenge ID should be a hex-encoded 32-byte hash (64 hex chars)
    assert_eq!(
        challenge_id.len(),
        64,
        "Challenge ID should be 64 hex characters"
    );
    assert!(
        challenge_id.chars().all(|c| c.is_ascii_hexdigit()),
        "Challenge ID should be valid hex"
    );
}

#[test]
fn test_build_challenge_uses_correct_file_metadata() {
    let metadata = create_fake_file_metadata("my_file_id", "metadata_test.txt", 800000);

    let expected_file_id = metadata.file_id.clone();
    let expected_padded_len = metadata.padded_len;
    let expected_original_size = metadata.original_size;
    let expected_filename = metadata.filename.clone();

    let descriptor = FileDescriptor::from_row(metadata);
    let seed = create_valid_seed();

    let challenge = descriptor
        .build_challenge(800000, 100, &seed, "prover1".to_string())
        .unwrap();

    assert_eq!(challenge.file_metadata.file_id, expected_file_id);
    assert_eq!(
        challenge.file_metadata.padded_len,
        expected_padded_len as usize
    );
    assert_eq!(
        challenge.file_metadata.original_size,
        expected_original_size as usize
    );
    assert_eq!(challenge.file_metadata.filename, expected_filename);
}

#[test]
fn test_try_from_raw_rejects_invalid_root_field_element() {
    let mut invalid_root = None;
    for byte in [0x80u8, 0xFFu8] {
        let mut candidate = [0u8; 32];
        candidate[31] = byte;
        if bytes_to_field_element(&candidate).is_none() {
            invalid_root = Some(candidate);
            break;
        }
    }
    let invalid_root = invalid_root.expect("Test requires an invalid field element representation");

    let raw = RawFileDescriptor {
        file_id: "file_invalid_root".to_string(),
        object_id: "object_file_invalid_root".to_string(),
        nonce: vec![0u8; 32],
        root: invalid_root.to_vec(),
        padded_len: 16,
        original_size: 10,
        filename: "invalid_root.txt".to_string(),
    };

    let result = FileDescriptor::try_from_raw(raw, 0);
    assert!(
        matches!(result, Err(indexer::runtime::Error::Validation(_))),
        "Expected invalid root field element to be rejected"
    );
}

// ─────────────────────────────────────────────────────────────────
// Proof Resource Tests
// ─────────────────────────────────────────────────────────────────

use indexer::runtime::wit::Proof;
use indexer::test_utils::create_fake_file_metadata;

#[test]
fn test_proof_from_bytes_invalid_bytes_fails() {
    // Invalid bytes should fail deserialization
    let invalid_bytes = vec![0u8; 100];
    let result = Proof::from_bytes(&invalid_bytes);

    match result {
        Err(indexer::runtime::Error::Validation(_)) => {} // Expected
        Err(_) => panic!("Expected Validation error"),
        Ok(_) => panic!("Invalid proof bytes should fail deserialization"),
    }
}

#[test]
fn test_proof_from_bytes_empty_bytes_fails() {
    // Empty bytes should fail deserialization
    let result = Proof::from_bytes(&[]);

    assert!(
        result.is_err(),
        "Empty proof bytes should fail deserialization"
    );
}

#[test]
fn test_proof_from_bytes_truncated_header_fails() {
    // Bytes too short to contain valid header
    let short_bytes = vec![0u8; 5];
    let result = Proof::from_bytes(&short_bytes);

    assert!(
        result.is_err(),
        "Truncated header should fail deserialization"
    );
}

#[test]
fn test_proof_from_bytes_wrong_magic_fails() {
    // Wrong magic bytes
    let mut wrong_magic = vec![0u8; 20];
    wrong_magic[0..4].copy_from_slice(b"XXXX"); // Wrong magic

    let result = Proof::from_bytes(&wrong_magic);

    assert!(result.is_err(), "Wrong magic bytes should fail");
}
