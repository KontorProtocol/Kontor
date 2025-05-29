use anyhow::Result;
use bitcoin::key::{Keypair, Secp256k1, XOnlyPublicKey, rand};
use bitcoin::opcodes::all::OP_ENDIF;
use bitcoin::script::Instruction;

use kontor::api::compose::build_tap_script_and_script_address;

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
