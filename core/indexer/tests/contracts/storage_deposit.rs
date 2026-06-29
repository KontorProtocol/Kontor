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
/// sets a map entry; admin clears it; alice (who didn't sign the clear) is neither
/// charged nor refunded.
#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_delete_moves_no_token() -> Result<()> {
    let admin = runtime.identity().await?;
    let alice = runtime.identity().await?;
    let alice_ref: HolderRef = (&alice).into();
    let contract = runtime.publish(&admin, "counter").await?;

    // alice sets an entry (depositor = alice).
    let mut submit = runtime.submit();
    submit.push(&alice, counter::set_entry_call(&contract, "k", "v"));
    submit.execute().await?;

    let alice_before = token::balance(runtime, alice_ref.clone())
        .await?
        .unwrap_or_default();

    // admin clears the map → alice's row is freed. No refund, no charge to alice.
    let mut submit = runtime.submit();
    submit.push(&admin, counter::clear_all_call(&contract));
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

/// An overwrite also moves no token. counter's `value` is a single shared slot;
/// alice sets it, then bob overwrites it. Under the vault model alice would be
/// refunded her displaced deposit; under the floor model nothing moves — alice's
/// footprint just transfers to bob (the new depositor), and her balance is untouched.
#[testlib::test(contracts_dir = "../../test-contracts")]
async fn test_overwrite_moves_no_token() -> Result<()> {
    let admin = runtime.identity().await?;
    let alice = runtime.identity().await?;
    let bob = runtime.identity().await?;
    let alice_ref: HolderRef = (&alice).into();
    let contract = runtime.publish(&admin, "counter").await?;

    // alice writes the shared slot (depositor = alice).
    let mut submit = runtime.submit();
    submit.push(&alice, counter::increment_call(&contract));
    submit.execute().await?;

    let alice_before = token::balance(runtime, alice_ref.clone())
        .await?
        .unwrap_or_default();

    // bob overwrites the same slot (depositor → bob). alice gets nothing.
    let mut submit = runtime.submit();
    submit.push(&bob, counter::increment_call(&contract));
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
    let contract = runtime.publish(&admin, "counter").await?;
    let zero = Decimal::from("0");

    // AMPLIFIED (investigation): repeat the 0→positive transition with a FRESH
    // identity each iteration to provoke the floor-view flake. Modest count to
    // avoid the cluster-collapse load failures larger counts trigger. Revert to a
    // single iteration once root-caused.
    for i in 0..20u32 {
        let alice = runtime.identity().await?;
        let alice_ref: HolderRef = (&alice).into();
        // alice's signer-id as resolved at identity() time (via the signers API).
        let alice_sid = alice.signer_id();
        assert_eq!(
            token::floor(runtime, alice_ref.clone()).await?,
            zero,
            "iter {i}: a holder with no deposited rows must read floor 0"
        );

        let mut submit = runtime.submit();
        submit.push(
            &alice,
            counter::set_entry_call(&contract, &format!("k{i}"), "v"),
        );
        submit.execute().await?;

        // Retry-discriminator: characterize the flake. If floor is 0 right after the
        // write, retry (up to ~20s, matching the original poll that worked) and record
        // how long until it flips positive — the host FLOOR_ZERO_DIAG logs
        // live_sum/max_height on each 0-read, so we see whether the write lands late
        // (live_sum/height advance) vs a persistent miss. On failure we also capture
        // alice's balance: if balance resolves correctly while floor stays 0, x-only→
        // signer-id resolution works and only the footprint is missing.
        let mut floor = token::floor(runtime, alice_ref.clone()).await?;
        let mut tries = 0u32;
        while floor == zero && tries < 100 {
            tries += 1;
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
            floor = token::floor(runtime, alice_ref.clone()).await?;
        }
        if tries > 0 {
            let bal = token::balance(runtime, alice_ref.clone()).await;
            eprintln!(
                "FLOOR_RETRY_DIAG: iter {i} alice_sid={alice_sid:?} balance={bal:?} floor 0→{floor} after {tries} retries (~{}ms)",
                tries * 200
            );
        }
        assert!(
            floor > zero,
            "iter {i}: floor still 0 after {tries} retries (~{}ms), alice_sid={alice_sid:?}",
            tries * 200
        );
    }

    Ok(())
}
