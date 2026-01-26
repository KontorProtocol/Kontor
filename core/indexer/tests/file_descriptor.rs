use indexer::runtime::wit::FileDescriptor;
use indexer::test_utils::valid_seed_field;

#[test]
fn test_build_challenge_success() {
    let metadata = create_fake_file_metadata("file1", "test.txt", 800000);
    let descriptor = FileDescriptor::from_row(metadata);

    let seed = valid_seed_field(1);
    let result = descriptor.build_challenge(800000, 100, &seed.bytes, "prover1".to_string());

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

    let seed = valid_seed_field(1);
    let result = descriptor.compute_challenge_id(800000, 100, &seed.bytes, "prover1".to_string());

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
    let seed = valid_seed_field(1);

    let challenge = descriptor
        .build_challenge(800000, 100, &seed.bytes, "prover1".to_string())
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
