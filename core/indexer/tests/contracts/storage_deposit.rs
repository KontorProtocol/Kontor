use indexer::runtime::ExecutionError;
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

interface!(name = "counter", path = "../../test-contracts/counter/wit");

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

/// The DECISIVE property: a deposit is refunded to the original SETTER, not to
/// whoever overwrites the slot. counter's `value` is a single shared slot; alice
/// sets it, then bob overwrites it — and alice (who didn't sign bob's op) gets
/// her deposit back. This is what stops the overwrite-siphon (a different payer
/// overwriting a mutable slot for free, funded by the original setter).
#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_deposit_refunds_to_setter_not_overwriter() -> Result<()> {
    let admin = runtime.identity().await?;
    let alice = runtime.identity().await?;
    let bob = runtime.identity().await?;
    let alice_ref: HolderRef = (&alice).into();
    let contract = runtime.publish(&admin, "counter").await?;

    // alice writes the shared slot → her deposit is locked, depositor = alice.
    let mut submit = runtime.submit();
    submit.push(&alice, counter::increment_call(&contract));
    submit.execute().await?;

    let alice_before = token::balance(runtime, alice_ref.clone())
        .await?
        .unwrap_or_default();
    let vault_before = token::balance(runtime, HolderRef::Vault)
        .await?
        .unwrap_or_default();

    // bob OVERWRITES the same slot → bob is charged a new deposit and alice (the
    // displaced setter) is refunded hers, despite not signing this op.
    let mut submit = runtime.submit();
    submit.push(&bob, counter::increment_call(&contract));
    submit.execute().await?;

    let alice_after = token::balance(runtime, alice_ref.clone())
        .await?
        .unwrap_or_default();
    let vault_after = token::balance(runtime, HolderRef::Vault)
        .await?
        .unwrap_or_default();

    assert!(
        alice_after > alice_before,
        "the SETTER (alice) must be refunded when bob overwrites her slot: {alice_before} -> {alice_after}"
    );
    // Same-sized u64 value: bob's new deposit exactly replaces alice's refunded
    // one, so the vault is flat across the overwrite.
    assert_eq!(
        vault_after, vault_before,
        "vault flat across overwrite (bob's deposit replaced alice's)"
    );

    Ok(())
}

/// An op whose storage deposit exceeds its gas budget must revert DETERMINISTICALLY
/// (the deposit is metered as fuel, so it trips the out-of-gas path) — never as a
/// node-halting NonDeterministic error. Local-only: it needs a >100k-gas-budget
/// write (~150 KB), which is trivial as a direct call but would blow regtest's tx
/// size. The classification is host-side and mode-independent, so local proves it.
#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_deposit_over_budget_reverts_deterministically() -> Result<()> {
    let admin = runtime.identity().await?;
    let contract = runtime.publish(&admin, "counter").await?;
    let vault_before = token::balance(runtime, HolderRef::Vault)
        .await?
        .unwrap_or_default();

    // Deposit = 1 gas/byte, so ~150k bytes needs ~150k deposit-gas > the 100k
    // budget. Built guest-side from a small arg so the op expr stays tiny.
    let result = counter::fill_blob(runtime, &contract, &admin, 150_000).await;
    let err = result.expect_err("over-budget deposit must fail");
    assert!(
        err.downcast_ref::<ExecutionError>()
            .is_some_and(|e| matches!(e, ExecutionError::Deterministic(_))),
        "over-budget deposit must be a DETERMINISTIC revert, got: {err:#}"
    );

    // Nothing was locked, and the node is still alive — a normal op still works.
    let vault_after = token::balance(runtime, HolderRef::Vault)
        .await?
        .unwrap_or_default();
    assert_eq!(
        vault_after, vault_before,
        "an over-budget op must lock no deposit"
    );
    let mut submit = runtime.submit();
    submit.push(&admin, counter::increment_call(&contract));
    submit.execute().await?;

    Ok(())
}

/// A failed op locks NO deposit: the write lands, the op then fails, the savepoint
/// rolls the write back and the deposit-accumulator frame is discarded. Asserts the
/// EFFECTS (vault unchanged + write reverted), which hold regardless of how the
/// failure surfaces — so it runs in both local and regtest.
#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_failed_op_locks_no_deposit() -> Result<()> {
    let admin = runtime.identity().await?;
    let contract = runtime.publish(&admin, "counter").await?;
    let vault_before = token::balance(runtime, HolderRef::Vault)
        .await?
        .unwrap_or_default();

    // Writes the blob, then returns Err → the whole op reverts. The failure
    // surfaces differently in local vs regtest, so ignore it and check effects.
    let mut submit = runtime.submit();
    let blob = "z".repeat(500);
    submit.push(&admin, counter::set_blob_then_fail_call(&contract, &blob));
    let _ = submit.execute().await;

    let vault_after = token::balance(runtime, HolderRef::Vault)
        .await?
        .unwrap_or_default();
    assert_eq!(
        vault_after, vault_before,
        "a rolled-back write must lock no deposit"
    );
    assert!(
        counter::get_blob(runtime, &contract).await?.is_empty(),
        "the write must have rolled back with the failed op"
    );

    Ok(())
}
