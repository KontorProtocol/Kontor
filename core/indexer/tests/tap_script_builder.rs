use anyhow::Result;
use bitcoin::key::{Keypair, Secp256k1, XOnlyPublicKey, rand};
use bitcoin::opcodes::all::OP_ENDIF;
use bitcoin::script::Instruction;

use indexer::api::compose::build_tap_script_and_script_address;

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
    let (script, _, _) = build_tap_script_and_script_address(key, data.clone())?;

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
    let (script, _, _) = build_tap_script_and_script_address(key, data.clone())?;

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
    let (script, _, _) = build_tap_script_and_script_address(key, data.clone())?;

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
    let (script, _, _) = build_tap_script_and_script_address(key, data.clone())?;

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
    let (script, _, _) = build_tap_script_and_script_address(key, data.clone())?;

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

    // Start with a larger size and use bigger increments
    let mut current_size = 500_000; // Start with 500KB (where previous test left off)
    let increment = 100_000; // Increase by 100KB each iteration
    let max_attempts = 50; // Test up to ~5.5MB

    let mut last_successful_size = 0;
    let mut attempts = 0;

    println!("Testing progressive data size limits...");

    while attempts < max_attempts {
        let data = vec![0xFF; current_size];

        match build_tap_script_and_script_address(key, data.clone()) {
            Ok((script, _, _)) => {
                last_successful_size = current_size;
                let script_size = script.len();
                let num_chunks = (current_size + 519) / 520; // Round up division

                println!(
                    "✓ Success: {} bytes data ({} KB) -> {} bytes script, {} chunks",
                    current_size,
                    current_size / 1024,
                    script_size,
                    num_chunks
                );

                // Verify the script can be parsed
                let instructions = script.instructions().collect::<Result<Vec<_>, _>>()?;
                assert!(instructions.len() > 6, "Script should have basic structure");

                current_size += increment;
                attempts += 1;
            }
            Err(e) => {
                println!(
                    "✗ Failed at {} bytes ({} KB): {}",
                    current_size,
                    current_size / 1024,
                    e
                );
                break;
            }
        }
    }

    if attempts >= max_attempts {
        println!(
            "⚠ Reached maximum attempts ({}) without failure",
            max_attempts
        );
        println!(
            "Last tested size: {} bytes ({} KB)",
            current_size - increment,
            (current_size - increment) / 1024
        );
    }

    println!(
        "Maximum successful data size: {} bytes ({} KB)",
        last_successful_size,
        last_successful_size / 1024
    );

    // Ensure we successfully tested at least some sizes
    assert!(
        last_successful_size > 0,
        "Should have at least one successful size"
    );

    Ok(())
}
