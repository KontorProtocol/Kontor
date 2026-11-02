use indexer::runtime::ExecutionError;
use testlib::*;

import!(
    name = "token",
    height = 0,
    tx_index = 0,
    path = "../../native-contracts/token/wit",
);

interface!(name = "counter", path = "../../test-contracts/counter/wit");

/// The DECISIVE floor-model property: freeing a row moves NO token. Under the old
/// vault model, deleting a row refunded its setter's deposit; under the floor model
/// the setter's collateral was never moved out of their balance in the first place
/// — the deletion just shrinks their footprint, so their balance is untouched. alice
/// sets a map entry; admin removes it; alice (who didn't sign the removal) is
/// neither charged nor refunded.
///
/// SHARED-INSTANCE RULE: regtest tests share ONE published "counter" (a publish
/// costs a block confirmation), so each test owns its keys/slots and never runs
/// whole-map ops — another test's row freed mid-flight was the floor-view flake.
#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_delete_moves_no_token() -> Result<()> {
    let admin = runtime.identity().await?;
    let alice = runtime.identity().await?;
    let alice_ref: HolderRef = (&alice).into();
    let contract = runtime.publish(&admin, "counter").await?;

    // alice sets an entry under this test's own key (depositor = alice).
    let mut submit = runtime.submit();
    submit.push(&alice, counter::set_entry_call(&contract, "delete-k", "v"));
    submit.execute().await?;

    let alice_before = token::balance(runtime, alice_ref.clone())
        .await?
        .unwrap_or_default();

    // admin removes the entry → alice's row is freed. No refund, no charge to alice.
    let mut submit = runtime.submit();
    submit.push(&admin, counter::remove_entry_call(&contract, "delete-k"));
    submit.execute().await?;

    let alice_after = token::balance(runtime, alice_ref.clone())
        .await?
        .unwrap_or_default();
    assert_eq!(
        alice_after, alice_before,
        "freeing a row must move no token to/from its setter (floor model): {alice_before} -> {alice_after}"
    );

    Ok(())
}

/// An overwrite also moves no token. alice writes a key, then bob overwrites the
/// same key. Under the vault model alice would be refunded her displaced deposit;
/// under the floor model nothing moves — alice's footprint just transfers to bob
/// (the new depositor), and her balance is untouched. Uses this test's own key
/// (not the `value` slot: `test_counter_batching` owns that on the shared
/// instance — see the shared-instance rule on `test_delete_moves_no_token`).
#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_overwrite_moves_no_token() -> Result<()> {
    let admin = runtime.identity().await?;
    let alice = runtime.identity().await?;
    let bob = runtime.identity().await?;
    let alice_ref: HolderRef = (&alice).into();
    let contract = runtime.publish(&admin, "counter").await?;

    // alice writes the row (depositor = alice).
    let mut submit = runtime.submit();
    submit.push(
        &alice,
        counter::set_entry_call(&contract, "overwrite-k", "a"),
    );
    submit.execute().await?;

    let alice_before = token::balance(runtime, alice_ref.clone())
        .await?
        .unwrap_or_default();

    // bob overwrites the same row (depositor → bob). alice gets nothing.
    let mut submit = runtime.submit();
    submit.push(&bob, counter::set_entry_call(&contract, "overwrite-k", "b"));
    submit.execute().await?;

    let alice_after = token::balance(runtime, alice_ref.clone())
        .await?
        .unwrap_or_default();
    assert_eq!(
        alice_after, alice_before,
        "an overwrite must not refund the displaced setter (floor model): {alice_before} -> {alice_after}"
    );

    Ok(())
}

/// An op whose storage growth exceeds its gas budget reverts DETERMINISTICALLY (the
/// deposit is metered as fuel, so it trips the out-of-gas path) — never as a
/// node-halting NonDeterministic error. This is the per-op growth cap = the gas the
/// payer authorized. Local-only: it needs a >100k-gas write (~150 KB), trivial as a
/// direct call but past regtest's tx size. The classification is host-side and
/// mode-independent, so local proves it.
#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_growth_over_budget_reverts_deterministically() -> Result<()> {
    let admin = runtime.identity().await?;
    let contract = runtime.publish(&admin, "counter").await?;

    let result = counter::fill_blob(runtime, &contract, &admin, 150_000).await;
    let err = result.expect_err("over-budget growth must fail");
    assert!(
        err.downcast_ref::<ExecutionError>()
            .is_some_and(|e| matches!(e, ExecutionError::Deterministic(_))),
        "over-budget growth must be a DETERMINISTIC revert, got: {err:#}"
    );

    // The node is unharmed — a normal op still works.
    let mut submit = runtime.submit();
    submit.push(&admin, counter::increment_call(&contract));
    submit.execute().await?;

    Ok(())
}

/// A failed op leaves no storage and moves no token beyond its gas. The write lands,
/// the op fails, the savepoint rolls the write back so it never enters the footprint.
/// Asserts the effects (write reverted), which hold regardless of how the failure
/// surfaces — so it runs in both local and regtest.
#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_failed_op_leaves_no_storage() -> Result<()> {
    let admin = runtime.identity().await?;
    let contract = runtime.publish(&admin, "counter").await?;

    // Writes the blob, then returns Err → the whole op reverts. The failure surfaces
    // differently in local vs regtest, so ignore it and check effects.
    let mut submit = runtime.submit();
    let blob = "z".repeat(500);
    submit.push(&admin, counter::set_blob_then_fail_call(&contract, &blob));
    let _ = submit.execute().await;

    assert!(
        counter::get_blob(runtime, &contract).await?.is_empty(),
        "the write must have rolled back with the failed op"
    );

    Ok(())
}

/// The storage-deposit FLOOR is enforced as a spendable reserve: every token debit
/// must leave `balance - footprint x D >= 0`. alice accumulates a large footprint
/// (several big keyed values), then tries to spend down past it — the token's debit
/// check rejects the transfer; a spend that respects the floor still succeeds.
/// Local-only: the floor only bites at a footprint many times the per-op gas budget
/// (D is tiny today), which needs several >100 KB direct writes, past regtest's tx
/// size.
#[testlib::test(contracts_dir = "../../test-contracts", local_only = true)]
async fn test_floor_blocks_overcommitted_spend() -> Result<()> {
    let admin = runtime.identity().await?;
    let alice = runtime.identity().await?;
    let bob = runtime.identity().await?;
    let alice_ref: HolderRef = (&alice).into();
    let bob_ref: HolderRef = (&bob).into();
    let contract = runtime.publish(&admin, "counter").await?;

    // alice accumulates footprint across distinct keys (each ~90 KB, under the
    // per-op gas cap). Eight writes push `footprint x D` (~7.2e-4 token) well above
    // one op's gas hold (~1e-4), so the escrow refund alone can no longer cover the
    // floor when she tries to spend down.
    for i in 0..8u32 {
        let key = format!("k{i}");
        counter::fill_entry(runtime, &contract, &alice, &key, 90_000).await?;
    }

    let alice_balance = token::balance(runtime, alice_ref.clone())
        .await?
        .unwrap_or_default();

    // Draining to ~0.0005 token would leave alice below her ~7.2e-4 floor → the
    // token's debit check (spendable = balance - floor) rejects the transfer. The
    // amount is affordable as a plain transfer, so the rejection is the FLOOR, not
    // insufficient funds.
    let drain_amt = alice_balance.sub(Decimal::from("0.0005"))?;
    let drain = token::transfer(runtime, &alice, bob_ref.clone(), drain_amt).await;
    let msg = match drain {
        Ok(Ok(_)) => panic!("draining below the floor must fail, but the transfer succeeded"),
        Ok(Err(e)) => format!("{e:?}"),
        Err(e) => format!("{e:#}"),
    };
    assert!(
        msg.contains("floor"),
        "expected a storage-deposit floor rejection, got: {msg}"
    );

    // The drain rolled back — alice keeps (all but the gas burned on the attempt) her
    // balance, NOT drained to ~0.0005 — and a floor-respecting tiny spend still works.
    let alice_after = token::balance(runtime, alice_ref.clone())
        .await?
        .unwrap_or_default();
    assert!(
        alice_balance.sub(alice_after)? < Decimal::from("0.01"),
        "the floor-violating transfer must roll back (only gas burned): {alice_balance} -> {alice_after}"
    );
    token::transfer(runtime, &alice, bob_ref, Decimal::from("0.0001")).await??;

    Ok(())
}

/// The `token.floor` view exposes a holder's storage-deposit floor — the public,
/// cross-contract-callable surface over the native-only `deposit.storage-floor` host
/// fn. A holder with no deposited rows reads 0; after a keyed write the floor is
/// positive (the same value the debit check reads). Proves the native token mediates
/// floor reads now that the host fn is native-only. Runs in regtest too: this is the
/// regression guard for `storage_floor` resolving an x-only-PUBKEY holder to its
/// signer-id — in a live cluster `(&identity).into()` is a pubkey (its signer-id is
/// assigned lazily on first write), and an unresolved-pubkey floor used to read 0.
#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_token_floor_view_reports_deposit() -> Result<()> {
    let admin = runtime.identity().await?;
    let alice = runtime.identity().await?;
    let alice_ref: HolderRef = (&alice).into();
    let contract = runtime.publish(&admin, "counter").await?;

    let zero = Decimal::from("0");
    assert_eq!(
        token::floor(runtime, alice_ref.clone()).await?,
        zero,
        "a holder with no deposited rows must read floor 0"
    );

    // alice writes a keyed entry (depositor = alice) → her floor becomes positive.
    // Own key, per the shared-instance rule (see `test_delete_moves_no_token`):
    // the assertion requires alice to still be the depositor of this row at read
    // time, so no other test may overwrite or remove it.
    let mut submit = runtime.submit();
    submit.push(&alice, counter::set_entry_call(&contract, "floor-k", "v"));
    submit.execute().await?;

    let floor = token::floor(runtime, alice_ref.clone()).await?;
    if floor <= zero {
        // On-failure discriminator (NOT polling — the assertion has already failed on
        // this first read; re-reading only enriches the panic so a CI flake finally
        // names its cause). A regtest `floor` read that comes back 0 right after a
        // deposited write has two very different explanations:
        //   * re-read POSITIVE  → a transient read-after-write VISIBILITY lag on the
        //     `/view` path (pool/snapshot/timing) — the deposit is there, the first
        //     read just didn't see it.
        //   * re-read STILL 0    → a PERSISTENT accounting bug (the resolved signer-id
        //     ≠ the id the deposit was recorded under, or the deposit wasn't recorded),
        //     NOT a snapshot/timing issue. (The historical cause of this branch —
        //     another test overwriting/clearing this row on the shared counter —
        //     is designed out by the per-test key + no-whole-map-ops rule.)
        // Capturing this only on failure keeps prod untouched and doesn't mask the flake.
        let reread = token::floor(runtime, alice_ref.clone()).await;
        // Forensics resolve alice (and admin, in case the deposit landed under the
        // wrong signer) from both the pubkey and the captured id, with footprints —
        // naming which id actually holds the deposit, or that none does.
        let alice_forensics = runtime.signer_forensics(&alice).await;
        let admin_forensics = runtime.signer_forensics(&admin).await;
        panic!(
            "floor must be positive after a deposited write, got {floor}; \
             re-read = {reread:?} — POSITIVE ⇒ transient /view visibility lag; \
             still 0 ⇒ persistent accounting bug (signer-id mismatch or deposit not recorded)\n\
             alice {alice_forensics}\nadmin {admin_forensics}"
        );
    }

    Ok(())
}
