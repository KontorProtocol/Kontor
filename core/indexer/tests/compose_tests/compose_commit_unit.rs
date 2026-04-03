use anyhow::Result;
use bitcoin::FeeRate;
use indexer::api::compose::{CommitInputs, ComposeInputs, InstructionInputs, compose_commit};
use testlib::RegTester;
use tracing::info;

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
