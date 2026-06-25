use anyhow::Result;
use indexer::runtime::ContractAddress;
use indexer_types::{Inst, InstKind};
use testlib::*;

/// Publish seeds the provenance log; the owner can append; a non-owner can't.
#[testlib::test(contracts_dir = "../../test-contracts", regtest_only)]
async fn provenance_log_append_and_owner_authz_regtest() -> Result<()> {
    let mut rt = runtime.reg_tester().unwrap();

    let contracts = ContractReader::new("../../test-contracts").await?;
    let counter_bytes = contracts
        .read("counter")
        .await?
        .expect("counter contract not found");

    // Owner funds itself, then publishes in a separate instruction so the
    // Publish is op 0 and `result.contract` is the published contract.
    let mut owner = rt.unregistered_identity().await?;
    rt.instruction(
        &mut owner,
        Inst {
            gas_limit: 10_000,
            kind: InstKind::Issuance,
        },
    )
    .await?;
    let published = rt
        .instruction(
            &mut owner,
            Inst {
                gas_limit: 50_000,
                kind: InstKind::Publish {
                    name: "counter".to_string(),
                    bytes: counter_bytes,
                    provenance: sample_provenance(),
                },
            },
        )
        .await?;
    let address: ContractAddress = published
        .result
        .contract
        .parse()
        .map_err(|e: String| anyhow::anyhow!(e))?;

    // Publish seeds exactly one entry, authored by the publisher.
    let log = rt.get_contract_provenance(&address).await?;
    assert_eq!(log.len(), 1, "publish should seed one provenance entry");
    assert_eq!(log[0].provenance, sample_provenance());

    // The owner appends a second claim (e.g. the repo moved).
    let mut updated = sample_provenance();
    updated.source.repo = "renamed".to_string();
    rt.instruction(
        &mut owner,
        Inst {
            gas_limit: 50_000,
            kind: InstKind::UpdateProvenance {
                contract: address.clone().into(),
                provenance: updated.clone(),
            },
        },
    )
    .await?;

    let log = rt.get_contract_provenance(&address).await?;
    assert_eq!(log.len(), 2, "owner update should append");
    assert_eq!(log[1].provenance, updated, "latest entry is the update");

    // A different identity cannot update the contract's provenance.
    let mut stranger = rt.unregistered_identity().await?;
    rt.instruction(
        &mut stranger,
        Inst {
            gas_limit: 10_000,
            kind: InstKind::Issuance,
        },
    )
    .await?;
    let mut malicious = sample_provenance();
    malicious.source.owner = "attacker".to_string();
    // Rejected by the owner-authz check; ignore the failure.
    let _ = rt
        .instruction(
            &mut stranger,
            Inst {
                gas_limit: 50_000,
                kind: InstKind::UpdateProvenance {
                    contract: address.clone().into(),
                    provenance: malicious,
                },
            },
        )
        .await;

    // The log is unchanged — the non-owner attempt appended nothing.
    let log = rt.get_contract_provenance(&address).await?;
    assert_eq!(log.len(), 2, "non-owner update must be rejected");
    assert_eq!(log[1].provenance, updated, "latest still the owner's update");

    Ok(())
}
