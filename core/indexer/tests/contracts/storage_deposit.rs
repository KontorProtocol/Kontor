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
/// storage deposit into the VAULT (paid out of the payer's gas escrow), and that
/// the vault is funded — the invariant the per-row `deposited_amount` columns
/// reconcile against. NFT mint writes fresh keys (no overwrite-netting), so the
/// lock is unambiguous.
#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_storage_deposit_locks_into_vault() -> Result<()> {
    let alice = runtime.identity().await?;
    let alice_ref: HolderRef = (&alice).into();

    let vault_before = token::balance(runtime, HolderRef::Vault)
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
    let alice_after = token::balance(runtime, alice_ref.clone())
        .await?
        .unwrap_or_default();

    // The deposit moved INTO the vault, funded by alice's escrow (she pays gas +
    // the locked deposit), so her balance strictly drops and the vault strictly
    // grows.
    assert!(
        vault_after > vault_before,
        "vault must grow by the locked deposit: {vault_before} -> {vault_after}"
    );
    assert!(
        alice_after < alice_before,
        "payer must fund gas + deposit: {alice_before} -> {alice_after}"
    );

    Ok(())
}
