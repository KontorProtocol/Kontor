use anyhow::Result;
use bitcoin::FeeRate;
use indexer::api::compose::{CommitInputs, ComposeInputs, InstructionInputs, compose_commit};
use testlib::RegTester;
use tracing::info;

pub async fn test_compose_commit_unique_vout_mapping_even_with_identical_chunks(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_compose_commit_unique_vout_mapping_even_with_identical_chunks");
    let identity = reg_tester.identity().await?;
    let keypair = identity.keypair;
    let addr = identity.address.clone();
    let (internal_key, _parity) = keypair.x_only_public_key();
    let utxos = reg_tester.fund_address(&addr, 2).await?;
    let utxo1 = utxos[0].clone();
    let utxo2 = utxos[1].clone();

    // Two participants with identical script data to force identical tapscripts
    let data = b"same".to_vec();

    let inputs = ComposeInputs::builder()
        .instructions(vec![
            InstructionInputs::builder()
                .address(addr.clone())
                .x_only_public_key(internal_key)
                .funding_utxos(vec![utxo1])
                .instruction(data.clone())
                .build(),
            InstructionInputs::builder()
                .address(addr.clone())
                .x_only_public_key(internal_key)
                .funding_utxos(vec![utxo2])
                .instruction(data.clone())
                .build(),
        ])
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .envelope(546)
        .build();
    let commit = compose_commit(CommitInputs::from(inputs)).expect("commit");
    // Ensure outpoints in reveal_inputs are unique
    let vouts: std::collections::HashSet<u32> = commit
        .reveal_inputs
        .participants
        .iter()
        .map(|p| p.commit_outpoint.vout)
        .collect();
    assert_eq!(
        vouts.len(),
        2,
        "each participant should map to a unique vout"
    );
    Ok(())
}

pub async fn test_compose_commit_psbt_inputs_have_metadata(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_compose_commit_psbt_inputs_have_metadata");
    let identity = reg_tester.identity().await?;
    let addr = identity.address.clone();
    let keypair = identity.keypair;
    let (internal_key, _parity) = keypair.x_only_public_key();
    let next_funding_utxo = identity.next_funding_utxo;

    let inputs = ComposeInputs::builder()
        .instructions(vec![
            InstructionInputs::builder()
                .address(addr.clone())
                .x_only_public_key(internal_key)
                .funding_utxos(vec![next_funding_utxo])
                .instruction(b"x".to_vec())
                .build(),
        ])
        .fee_rate(FeeRate::from_sat_per_vb(2).unwrap())
        .envelope(546)
        .build();
    let commit = compose_commit(CommitInputs::from(inputs)).expect("commit");
    let psbt_hex = commit.commit_psbt_hex;
    let psbt_bytes = hex::decode(&psbt_hex).expect("hex decode");
    let psbt: bitcoin::psbt::Psbt =
        bitcoin::psbt::Psbt::deserialize(&psbt_bytes).expect("psbt decode");
    assert!(!psbt.inputs.is_empty());
    for inp in psbt.inputs.iter() {
        assert!(inp.witness_utxo.is_some());
        assert!(inp.tap_internal_key.is_some());
    }
    Ok(())
}
