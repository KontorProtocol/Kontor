//! End-to-end proof verification: a single aggregated PoR proof covering two
//! files for one prover, verified through the contract against the host
//! challenge ledger. Runs locally (it seeds the ledger via `storage_conn`); the
//! proof is generated live, so it tracks the signer-derived prover and the
//! per-network challenge count — no precomputed fixtures.

use indexer::database::queries::{
    append_challenge_status, insert_challenge, latest_challenge_status,
};
use indexer::database::types::{ChallengeRow, ChallengeStatus};
use indexer::test_utils::{
    metadata_to_descriptor, por_aggregated_proof, prepare_por_file, valid_seed_field,
};
use testlib::*;

import!(
    name = "filestorage",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/filestorage/wit",
);

/// Two agreements, one common prover, and a single aggregated proof over both
/// files that the contract verifies in one call — marking both challenges proven.
async fn e2e_cross_file_aggregation(runtime: &mut Runtime) -> Result<()> {
    let prover_signer = runtime.identity().await?;

    let (prepared_a, metadata_a) = prepare_por_file(b"Content of file A", "agg_a.txt");
    let (prepared_b, metadata_b) = prepare_por_file(b"Content of file B", "agg_b.txt");

    let created_a =
        filestorage::create_agreement(runtime, &prover_signer, metadata_to_descriptor(&metadata_a))
            .await??;
    let created_b =
        filestorage::create_agreement(runtime, &prover_signer, metadata_to_descriptor(&metadata_b))
            .await??;

    // The prover joins both agreements; the join result is its node identity.
    let prover = filestorage::join_agreement(runtime, &prover_signer, &created_a.agreement_id)
        .await??
        .node_id;
    filestorage::join_agreement(runtime, &prover_signer, &created_b.agreement_id).await??;
    let prover_id: u64 = prover.parse().expect("prover is a signer_id");

    // Generate one aggregated proof over both files; seed a matching ledger
    // challenge per file. (regtest s_chal = 8; issue at genesis so the `active`
    // rows precede the `proven` rows verify-proof writes.)
    let s_chal = 8usize;
    let block_height = 0u64;
    let seed_a = valid_seed_field(200);
    let seed_b = valid_seed_field(201);
    let (proof_bytes, challenge_ids) = por_aggregated_proof(
        vec![
            (prepared_a, metadata_a, seed_a.field),
            (prepared_b, metadata_b, seed_b.field),
        ],
        block_height,
        s_chal,
        &prover,
    )?;

    let conn = runtime.storage_conn();
    for (cid, agreement_id, seed) in [
        (&challenge_ids[0], &created_a.agreement_id, &seed_a),
        (&challenge_ids[1], &created_b.agreement_id, &seed_b),
    ] {
        let row = ChallengeRow::builder()
            .challenge_id(cid.clone())
            .prover_id(prover_id)
            .agreement_id(agreement_id.clone())
            .num_challenges(s_chal as u64)
            .seed(seed.bytes.to_vec())
            .deadline_height(block_height + 2016)
            .height(block_height)
            .build();
        insert_challenge(&conn, &row).await?;
        append_challenge_status(&conn, cid, ChallengeStatus::Active, block_height).await?;
    }

    let result = filestorage::verify_proof(runtime, &prover_signer, proof_bytes).await??;
    assert_eq!(result.verified_count, 2, "both challenges should verify");

    for cid in &challenge_ids {
        assert_eq!(
            latest_challenge_status(&conn, cid).await?,
            Some(ChallengeStatus::Proven),
            "challenge {cid} should be Proven"
        );
    }

    Ok(())
}

/// A well-formed but invalid aggregated proof is rejected (one byte flipped, so
/// it deserializes but fails verification).
async fn e2e_invalid_proof_rejected(runtime: &mut Runtime) -> Result<()> {
    let prover_signer = runtime.identity().await?;
    let (prepared, metadata) = prepare_por_file(b"Content of file C", "agg_c.txt");
    let created =
        filestorage::create_agreement(runtime, &prover_signer, metadata_to_descriptor(&metadata))
            .await??;
    let prover = filestorage::join_agreement(runtime, &prover_signer, &created.agreement_id)
        .await??
        .node_id;
    let prover_id: u64 = prover.parse().expect("prover is a signer_id");

    let s_chal = 8usize;
    let block_height = 0u64;
    let seed = valid_seed_field(202);
    // A valid proof over the file, then flip a byte to make it invalid; seed the
    // matching challenge so verify-proof gets past the lookup and actually fails
    // verification.
    let (mut proof_bytes, challenge_ids) = por_aggregated_proof(
        vec![(prepared, metadata, seed.field)],
        block_height,
        s_chal,
        &prover,
    )?;
    if let Some(last) = proof_bytes.last_mut() {
        *last ^= 0x01;
    }

    let conn = runtime.storage_conn();
    let row = ChallengeRow::builder()
        .challenge_id(challenge_ids[0].clone())
        .prover_id(prover_id)
        .agreement_id(created.agreement_id.clone())
        .num_challenges(s_chal as u64)
        .seed(seed.bytes.to_vec())
        .deadline_height(block_height + 2016)
        .height(block_height)
        .build();
    insert_challenge(&conn, &row).await?;
    append_challenge_status(
        &conn,
        &challenge_ids[0],
        ChallengeStatus::Active,
        block_height,
    )
    .await?;

    // An invalid proof must never mark the challenge proven. If it deserializes,
    // verification rejects it and the status becomes failed/invalid; if it fails
    // to deserialize, the status stays active. Either way: not Proven.
    let _ = filestorage::verify_proof(runtime, &prover_signer, proof_bytes).await?;
    let status = latest_challenge_status(&conn, &challenge_ids[0]).await?;
    assert_ne!(
        status,
        Some(ChallengeStatus::Proven),
        "invalid proof must not mark the challenge proven"
    );

    Ok(())
}

pub async fn run(runtime: &mut Runtime) -> Result<()> {
    e2e_cross_file_aggregation(runtime).await?;
    e2e_invalid_proof_rejected(runtime).await?;
    Ok(())
}
