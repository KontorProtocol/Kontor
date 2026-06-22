use indexer::test_utils::make_descriptor;
use testlib::*;

import!(
    name = "nft",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/nft/wit",
);

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/token/wit",
);

/// End-to-end proof that a user op writing non-exempt contract storage LOCKS a
/// storage deposit into the VAULT (debited from the payer), and that token flow
/// is CONSERVED: everything the payer loses lands in either the VAULT (deposit)
/// or the BURNER (execution burn) — nothing is unaccounted. Conservation is the
/// foundation of the result-row-as-delta model: a 3rd party summing the token
/// movements emitted in result rows (settle → list<transfer>, release → burn)
/// can rebuild every balance. NFT mint writes fresh keys (no overwrite-netting),
/// so the lock is unambiguous.
#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_storage_deposit_locks_into_vault() -> Result<()> {
    let alice = runtime.identity().await?;
    let alice_ref: HolderRef = (&alice).into();

    let vault_before = token::balance(runtime, HolderRef::Vault)
        .await?
        .unwrap_or_default();
    let burner_before = token::balance(runtime, HolderRef::Burner)
        .await?
        .unwrap_or_default();
    let alice_before = token::balance(runtime, alice_ref.clone())
        .await?
        .unwrap_or_default();

    let descriptor = make_descriptor(
        "dep_file_1".to_string(),
        vec![1u8; 32],
        16,
        10,
        "dep_file_1.txt".to_string(),
    );
    nft::mint(runtime, &alice, "dep-nft-1", vec![], descriptor).await??;

    let vault_after = token::balance(runtime, HolderRef::Vault)
        .await?
        .unwrap_or_default();
    let burner_after = token::balance(runtime, HolderRef::Burner)
        .await?
        .unwrap_or_default();
    let alice_after = token::balance(runtime, alice_ref.clone())
        .await?
        .unwrap_or_default();

    let vault_gain = vault_after.sub(vault_before)?;
    let burner_gain = burner_after.sub(burner_before)?;
    let alice_loss = alice_before.sub(alice_after)?;

    // A deposit was actually locked (fresh storage written).
    assert!(
        vault_gain > Decimal::try_from(0u64)?,
        "vault must grow by the locked deposit: {vault_before} -> {vault_after}"
    );
    // CONSERVATION: every token alice lost went to the vault (deposit) or the
    // burner (execution burn) — none vanished, none appeared. CORE (the gas
    // escrow) nets to zero and never surfaces.
    assert_eq!(
        alice_loss,
        vault_gain.add(burner_gain)?,
        "payer loss ({alice_loss}) must equal vault deposit ({vault_gain}) + burn ({burner_gain})"
    );

    Ok(())
}
