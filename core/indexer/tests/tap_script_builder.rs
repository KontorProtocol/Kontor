use anyhow::Result;
use bitcoin::key::{Keypair, Secp256k1, XOnlyPublicKey, rand};
use bitcoin::opcodes::all::OP_ENDIF;
use bitcoin::script::Instruction;

use indexer::api::compose::build_tap_script_and_script_address;
use indexer::logging;
use tracing::info;

// Generate a random XOnlyPublicKey for testing
fn generate_test_key() -> XOnlyPublicKey {
    let secp = Secp256k1::new();
    let keypair = Keypair::new(&secp, &mut rand::thread_rng());
    keypair.x_only_public_key().0
}

#[tokio::test]
async fn test_build_tap_script_and_script_address_empty() -> Result<()> {
    let key = generate_test_key();
    let data = vec![];
    let result = build_tap_script_and_script_address(key, data.clone());
    assert!(result.is_err(), "Data cannot be empty");

    Ok(())
}

#[tokio::test]
async fn test_build_tap_script_and_script_address_519_bytes() -> Result<()> {
    let key = generate_test_key();
    let data = vec![0xFF; 519];
    let (script, _, _, _) = build_tap_script_and_script_address(key, data.clone())?;

    let script_instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;

    assert_eq!(
        script_instructions.len(),
        8,
        "Expected script to have 9 elements"
    );

    let push_bytes_instructions = script
        .instructions()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .skip(6) // the first six are OPs
        .collect::<Vec<_>>();

    if let [Instruction::PushBytes(data), Instruction::Op(op_endif)] =
        push_bytes_instructions.as_slice()
    {
        assert_eq!(data.len(), 519, "Expected data to be 520 bytes");
        assert_eq!(*op_endif, OP_ENDIF, "Expected OP_ENDIF");
    } else {
        panic!("Script structure doesn't match expected pattern");
    }

    Ok(())
}

#[tokio::test]
async fn test_build_tap_script_and_script_address_521_bytes() -> Result<()> {
    let key = generate_test_key();
    let data = vec![0xFF; 521];
    let (script, _, _, _) = build_tap_script_and_script_address(key, data.clone())?;

    let script_instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;

    assert_eq!(
        script_instructions.len(),
        9,
        "Expected script to have 9 elements"
    );

    let push_bytes_instructions = script
        .instructions()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .skip(6) // the first six are OPs
        .collect::<Vec<_>>();

    if let [
        Instruction::PushBytes(data_part_1),
        Instruction::PushBytes(data_part_2),
        Instruction::Op(op_endif),
    ] = push_bytes_instructions.as_slice()
    {
        assert_eq!(data_part_1.len(), 520, "Expected data to be 520 bytes");
        assert_eq!(data_part_2.len(), 1, "Expected data to be 1 bytes");
        assert_eq!(*op_endif, OP_ENDIF, "Expected OP_ENDIF");
    } else {
        panic!("Script structure doesn't match expected pattern");
    }

    Ok(())
}

#[tokio::test]
async fn test_build_tap_script_and_script_address_520_bytes() -> Result<()> {
    let key = generate_test_key();
    let data = vec![0xFF; 520];
    let (script, _, _, _) = build_tap_script_and_script_address(key, data.clone())?;

    let script_instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;

    assert_eq!(
        script_instructions.len(),
        8,
        "Expected script to have 9 elements"
    );

    let push_bytes_instructions = script
        .instructions()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .skip(6) // the first six are OPs
        .collect::<Vec<_>>();

    if let [Instruction::PushBytes(data), Instruction::Op(op_endif)] =
        push_bytes_instructions.as_slice()
    {
        assert_eq!(data.len(), 520, "Expected data to be 520 bytes");
        assert_eq!(*op_endif, OP_ENDIF, "Expected OP_ENDIF");
    } else {
        panic!("Script structure doesn't match expected pattern");
    }

    Ok(())
}

#[tokio::test]
async fn test_build_tap_script_and_script_address_small_chunking() -> Result<()> {
    let key = generate_test_key();
    let data = vec![0xFF; 1000];
    let (script, _, _, _) = build_tap_script_and_script_address(key, data.clone())?;

    let script_instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;

    assert_eq!(
        script_instructions.len(),
        9,
        "Expected script to have 9 elements"
    );

    let push_bytes_instructions = script
        .instructions()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .skip(6) // the first six are OPs
        .collect::<Vec<_>>();

    if let [
        Instruction::PushBytes(data_part_1),
        Instruction::PushBytes(data_part_2),
        Instruction::Op(op_endif),
    ] = push_bytes_instructions.as_slice()
    {
        assert_eq!(data_part_1.len(), 520, "Expected data to be 520 bytes");
        assert_eq!(data_part_2.len(), 480, "Expected data to be 480 bytes");
        assert_eq!(*op_endif, OP_ENDIF, "Expected OP_ENDIF");
    } else {
        panic!("Script structure doesn't match expected pattern");
    }

    let final_instructions = script
        .instructions()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .skip(6)
        .collect::<Vec<_>>();
    if let [
        Instruction::PushBytes(data_part_1),
        Instruction::PushBytes(data_part_2),
        Instruction::Op(op_endif),
    ] = final_instructions.as_slice()
    {
        assert_eq!(*op_endif, OP_ENDIF, "Expected OP_ENDIF");
        assert_eq!(data_part_1.len(), 520, "Expected data parts to be equal");
        assert_eq!(data_part_2.len(), 480, "Expected data parts to be equal");
    } else {
        panic!("Script structure doesn't match expected pattern");
    }

    Ok(())
}

#[tokio::test]
async fn test_build_tap_script_and_script_address_large_chunking() -> Result<()> {
    let key = generate_test_key();
    let data = vec![0xFF; 2700];
    let (script, _, _, _) = build_tap_script_and_script_address(key, data.clone())?;

    let script_instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;

    assert_eq!(
        script_instructions.len(),
        13,
        "Expected script to be 110 bytes"
    );

    let push_bytes_instructions = script
        .instructions()
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .skip(6)
        .collect::<Vec<_>>();
    if let [
        Instruction::PushBytes(data_part_1),
        Instruction::PushBytes(data_part_2),
        Instruction::PushBytes(data_part_3),
        Instruction::PushBytes(data_part_4),
        Instruction::PushBytes(data_part_5),
        Instruction::PushBytes(data_part_6),
        _,
    ] = push_bytes_instructions.as_slice()
    {
        assert_eq!(data_part_1.len(), 520, "Expected data parts to be equal");
        assert_eq!(data_part_2.len(), 520, "Expected data parts to be equal");
        assert_eq!(data_part_3.len(), 520, "Expected data parts to be equal");
        assert_eq!(data_part_4.len(), 520, "Expected data parts to be equal");
        assert_eq!(data_part_5.len(), 520, "Expected data parts to be equal");
        assert_eq!(data_part_6.len(), 100, "Expected data parts to be equal");
    } else {
        panic!("Script structure doesn't match expected pattern");
    }

    Ok(())
}

#[tokio::test]
async fn test_build_tap_script_progressive_size_limit() -> Result<()> {
    let key = generate_test_key();
    logging::setup();

    // Test progressive sizes: 500KB -> 600KB -> ... -> 5.5MB
    let mut current_size = 500_000; // Start with 500KB
    let increment = 100_000; // Increase by 100KB each iteration
    let max_size = 5_500_000; // Test up to 5.5MB

    while current_size <= max_size {
        let data = vec![0xFF; current_size];

        // Should succeed - let any errors propagate
        let (script, _, _, _) = build_tap_script_and_script_address(key, data.clone())?;

        // Verify basic script structure
        let instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;
        assert!(
            instructions.len() > 6,
            "Script should have basic structure for size {}",
            current_size
        );

        // Verify chunking worked correctly
        let expected_chunks = current_size.div_ceil(520); // Ceiling division: how many 520-byte chunks needed
        let actual_chunks = instructions.len() - 7; // Total instructions minus fixed structure
        info!(
            "expected_chunks: {}, actual_chunks: {}",
            expected_chunks, actual_chunks,
        );
        assert_eq!(
            actual_chunks, expected_chunks,
            "Chunk count mismatch for size {}",
            current_size
        );

        // Verify script contains the data
        assert!(
            script.len() > current_size,
            "Script should be larger than input data for size {}",
            current_size
        );

        current_size += increment;
    }

    // Test that we successfully handled large data sizes
    assert!(
        current_size > 5_000_000,
        "Should have tested sizes over 5MB"
    );

    Ok(())
}
