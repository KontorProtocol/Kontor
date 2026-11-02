use anyhow::Result;
use indexer_types::{CommitSource, Inst, InstKind, Insts, Reveal, RevealParticipant};
use testlib::{RegTester, sample_provenance};
use tracing::info;

pub async fn test_compose_commit_psbt_inputs_have_metadata(
    reg_tester: &mut RegTester,
) -> Result<()> {
    info!("test_compose_commit_psbt_inputs_have_metadata");
    let identity = reg_tester.identity().await?;
    let addr = identity.address.clone();
    let keypair = identity.keypair;
    let (internal_key, _parity) = keypair.x_only_public_key();
    let (out_point, _) = identity.next_funding_utxo;

    let inst = Inst {
        gas_limit: 50_000,
        kind: InstKind::Publish {
            name: "psbt-metadata".to_string(),
            bytes: b"x".to_vec(),
            provenance: sample_provenance(),
        },
    };
    let reveal = Reveal::builder()
        .sat_per_vbyte(2)
        .participants(vec![
            RevealParticipant::builder()
                .x_only_public_key(internal_key.to_string())
                .commit_insts(Insts::single(inst))
                .commit_source(CommitSource::build(&addr, [out_point]))
                .build(),
        ])
        .build();

    let commit_outputs = reg_tester.compose_commit(reveal).await?;
    let commit = &commit_outputs.commits[0];
    let psbt_bytes = hex::decode(&commit.psbt_hex).expect("hex decode");
    let psbt = bitcoin::psbt::Psbt::deserialize(&psbt_bytes).expect("psbt decode");
    assert!(!psbt.inputs.is_empty());
    for inp in psbt.inputs.iter() {
        assert!(inp.witness_utxo.is_some());
        assert!(inp.tap_internal_key.is_some());
    }
    Ok(())
}
