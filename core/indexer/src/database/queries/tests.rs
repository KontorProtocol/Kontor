use std::collections::HashSet;

use anyhow::Result;
use bitcoin::hashes::Hash;
use futures_util::{StreamExt, TryStreamExt};
use indexer_types::{BlockRow, ContractListRow, TransactionRow};
use libsql::{Connection, params};
use sha2::{Digest, Sha256};

use super::*;
use crate::database::types::{
    BlockQuery, ContractQuery, ContractResultRow, ContractRow, ContractStateRow, OpResultId,
    OrderDirection, ResultQuery, TransactionQuery,
};
use crate::runtime::ContractAddress;
use crate::test_utils::{new_mock_block_hash, new_mock_transaction, new_test_db};

fn calculate_row_hash(state: &ContractStateRow) -> String {
    let value_part = hex::encode(&state.value).to_uppercase();
    let path_part = hex::encode(&state.path).to_uppercase();
    // Mirrors `checkpoint_trigger.sql`: fields joined by `|` (impossible in any
    // field's charset) so the digest is unambiguous. A NULL depositor renders as
    // empty (SQLite `concat` treats NULL as '').
    let depositor_part = state.depositor.map(|d| d.to_string()).unwrap_or_default();
    let amount_part = state
        .deposited_gas
        .map(|g| g.to_string())
        .unwrap_or_default();
    let input = format!(
        "{}|{}|{}|{}|{}|{}",
        state.contract_id,
        path_part,
        value_part,
        if state.deleted { "1" } else { "0" },
        depositor_part,
        amount_part,
    );
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    hex::encode(hasher.finalize()).to_uppercase()
}

fn calculate_combined_hash(state: &ContractStateRow, prev_hash: &str) -> String {
    let row_hash = calculate_row_hash(state);
    let combined = format!("{}{}", row_hash, prev_hash);
    let mut hasher = Sha256::new();
    hasher.update(combined.as_bytes());
    hex::encode(hasher.finalize()).to_uppercase()
}

/// Build a `contract_state` codec path from string segments — enough to exercise
/// the byte-range / `next_element` query logic, which is element-type-agnostic.
/// (Real guest paths mix int/string/etc. elements; the queries don't care.)
fn cs_path(segments: &[&str]) -> Vec<u8> {
    let mut path = Vec::new();
    for s in segments {
        stdlib::KeyElement::encode_to(&s.to_string(), &mut path);
    }
    path
}

/// Same, but from a legacy dotted path string (`"m.k.field1"`) — splitting on `.`
/// reproduces the segment structure, so parent/child byte-prefix relationships
/// match the old text paths.
fn cs_path_dotted(path: &str) -> Vec<u8> {
    cs_path(&path.split('.').collect::<Vec<_>>())
}

/// Candidate discriminant elements for `matching_path`/`hard_delete_matching_paths`,
/// from string variant names — these host tests use string-element discriminants
/// (the byte-compare is encoding-agnostic, so a string element is a fine stand-in).
fn cands(names: &[&str]) -> Vec<Vec<u8>> {
    names.iter().map(|n| stdlib::string_element(n)).collect()
}

async fn setup_test_data(conn: &libsql::Connection) -> Result<()> {
    // Insert blocks
    for height in [800000, 800001, 800002] {
        let hash = format!(
            "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba{:02}",
            height % 100
        )
        .parse()?;
        let block = BlockRow::builder().height(height).hash(hash).build();
        insert_block(conn, block).await?;
    }

    insert_contract(
        conn,
        ContractRow::builder()
            .name("token".to_string())
            .height(800000)
            .tx_index(1)
            .bytes(vec![])
            .build(),
    )
    .await?;

    // Insert transactions across multiple heights
    // Height 800000: 5 transactions (tx_index 0-4)
    let mut tx_ids_800000 = Vec::new();
    for i in 0..5 {
        let tx = TransactionRow::builder()
            .height(800000)
            .txid(format!(
                "tx800000_{:02}_abcdef1234567890abcdef1234567890abcdef1234567890abcdef123456",
                i
            ))
            .tx_index(i)
            .build();
        tx_ids_800000.push(insert_transaction(conn, tx).await?);
    }

    // tx_index=0 modifies the token contract
    insert_contract_state(
        conn,
        ContractStateRow::builder()
            .contract_id(1)
            .tx_id(tx_ids_800000[0])
            .height(800000)
            .path(cs_path_dotted("foo"))
            .build(),
    )
    .await?;

    // Height 800001: 3 transactions (tx_index 0-2)
    let mut tx_ids_800001 = Vec::new();
    for i in 0..3 {
        let tx = TransactionRow::builder()
            .height(800001)
            .txid(format!(
                "tx800001_{:02}_fedcba0987654321fedcba0987654321fedcba0987654321fedcba098765",
                i
            ))
            .tx_index(i)
            .build();
        tx_ids_800001.push(insert_transaction(conn, tx).await?);
    }

    // tx_index=1 modifies the token contract (two state changes — tests DISTINCT)
    insert_contract_state(
        conn,
        ContractStateRow::builder()
            .contract_id(1)
            .tx_id(tx_ids_800001[1])
            .height(800001)
            .path(cs_path_dotted("bar"))
            .build(),
    )
    .await?;
    insert_contract_state(
        conn,
        ContractStateRow::builder()
            .contract_id(1)
            .tx_id(tx_ids_800001[1])
            .height(800001)
            .path(cs_path_dotted("biz"))
            .build(),
    )
    .await?;

    // Height 800002: 2 transactions (tx_index 0-1)
    let mut tx_ids_800002 = Vec::new();
    for i in 0..2 {
        let tx = TransactionRow::builder()
            .height(800002)
            .txid(format!(
                "tx800002_{:02}_123456789abcdef0123456789abcdef0123456789abcdef0123456789abcd",
                i
            ))
            .tx_index(i)
            .build();
        tx_ids_800002.push(insert_transaction(conn, tx).await?);
    }

    // tx_index=0 modifies the token contract
    insert_contract_state(
        conn,
        ContractStateRow::builder()
            .contract_id(1)
            .tx_id(tx_ids_800002[0])
            .height(800002)
            .path(cs_path_dotted("baz"))
            .build(),
    )
    .await?;

    Ok(())
}

async fn count_checkpoints(conn: &Connection) -> i64 {
    let stmt = conn
        .prepare("SELECT COUNT(*) FROM checkpoints")
        .await
        .unwrap();
    let mut rows = stmt.query(libsql::params![]).await.unwrap();
    rows.next()
        .await
        .unwrap()
        .map(|r| r.get(0).unwrap())
        .unwrap_or(0)
}

#[tokio::test]
async fn test_checkpoint_trigger() {
    let (_reader, writer, _temp) = new_test_db().await.unwrap();
    let conn = writer.connection();

    for height in 1..=200 {
        let block = BlockRow::builder()
            .height(height)
            .hash(bitcoin::BlockHash::from_byte_array([height as u8; 32]))
            .build();
        insert_block(&conn, block).await.unwrap();
    }

    let cs1 = ContractStateRow::builder()
        .contract_id(1)
        .height(10)
        .path(cs_path_dotted("/test/path1"))
        .value(b"test value 1".to_vec())
        .build();
    insert_contract_state(&conn, cs1.clone()).await.unwrap();
    let cp1 = get_checkpoint_by_height(&conn, 10).await.unwrap().unwrap();
    assert_eq!(cp1.height, 10);
    assert_eq!(
        cp1.hash.to_lowercase(),
        calculate_row_hash(&cs1).to_lowercase()
    );
    assert_eq!(count_checkpoints(&conn).await, 1);

    let cs2 = ContractStateRow::builder()
        .contract_id(1)
        .height(20)
        .path(cs_path_dotted("/test/path2"))
        .build();
    insert_contract_state(&conn, cs2.clone()).await.unwrap();
    let cp2 = get_checkpoint_by_height(&conn, 20).await.unwrap().unwrap();
    assert_eq!(cp2.height, 20);
    assert_eq!(
        cp2.hash.to_lowercase(),
        calculate_combined_hash(&cs2, &cp1.hash).to_lowercase()
    );
    assert_eq!(count_checkpoints(&conn).await, 2);

    let cs3 = ContractStateRow::builder()
        .contract_id(2)
        .height(60)
        .path(cs_path_dotted("/test/path3"))
        .value(b"test value 3".to_vec())
        .build();
    insert_contract_state(&conn, cs3.clone()).await.unwrap();
    let cp3 = get_checkpoint_by_height(&conn, 60).await.unwrap().unwrap();
    assert_eq!(
        cp3.hash.to_lowercase(),
        calculate_combined_hash(&cs3, &cp2.hash).to_lowercase()
    );
    assert_eq!(count_checkpoints(&conn).await, 3);

    let cs4 = ContractStateRow::builder()
        .contract_id(2)
        .height(75)
        .path(cs_path_dotted("/test/path4"))
        .value(b"test value 4".to_vec())
        .build();
    insert_contract_state(&conn, cs4.clone()).await.unwrap();
    let cp4 = get_checkpoint_by_height(&conn, 75).await.unwrap().unwrap();
    assert_eq!(
        cp4.hash.to_lowercase(),
        calculate_combined_hash(&cs4, &cp3.hash).to_lowercase()
    );
    assert_eq!(count_checkpoints(&conn).await, 4);

    let cs5 = ContractStateRow::builder()
        .contract_id(3)
        .height(120)
        .path(cs_path_dotted("/test/path5"))
        .value(b"test value 5".to_vec())
        .build();
    insert_contract_state(&conn, cs5.clone()).await.unwrap();
    let cp5 = get_checkpoint_by_height(&conn, 120).await.unwrap().unwrap();
    assert_eq!(
        cp5.hash.to_lowercase(),
        calculate_combined_hash(&cs5, &cp4.hash).to_lowercase()
    );
    assert_eq!(count_checkpoints(&conn).await, 5);

    let cs6 = ContractStateRow::builder()
        .contract_id(4)
        .height(190)
        .path(cs_path_dotted("/test/path6"))
        .build();
    insert_contract_state(&conn, cs6.clone()).await.unwrap();
    let cp6 = get_checkpoint_by_height(&conn, 190).await.unwrap().unwrap();
    assert_eq!(
        cp6.hash.to_lowercase(),
        calculate_combined_hash(&cs6, &cp5.hash).to_lowercase()
    );
    assert_eq!(count_checkpoints(&conn).await, 6);

    let cs7 = ContractStateRow::builder()
        .contract_id(4)
        .height(199)
        .path(cs_path_dotted("/test/path7"))
        .value(b"test value 7".to_vec())
        .build();
    insert_contract_state(&conn, cs7.clone()).await.unwrap();
    let cp7 = get_checkpoint_by_height(&conn, 199).await.unwrap().unwrap();
    assert_eq!(
        cp7.hash.to_lowercase(),
        calculate_combined_hash(&cs7, &cp6.hash).to_lowercase()
    );
    assert_eq!(count_checkpoints(&conn).await, 7);

    let cp_latest = get_checkpoint_latest(&conn).await.unwrap().unwrap();
    assert_eq!(cp7, cp_latest);

    // Same height insertion updates checkpoint
    let cs8 = ContractStateRow::builder()
        .contract_id(4)
        .height(199)
        .path(cs_path_dotted("/test/path7"))
        .value(b"test value 7".to_vec())
        .build();
    insert_contract_state(&conn, cs8.clone()).await.unwrap();
    assert_eq!(count_checkpoints(&conn).await, 7);
    assert_eq!(
        calculate_combined_hash(&cs8, &cp7.hash).to_lowercase(),
        get_checkpoint_latest(&conn)
            .await
            .unwrap()
            .unwrap()
            .hash
            .to_lowercase()
    );
}

#[tokio::test]
async fn test_database() -> Result<()> {
    let height: u64 = 800000;
    let hash = new_mock_block_hash(height as u32);
    let block = BlockRow::builder().height(height).hash(hash).build();

    let (reader, writer, _temp_dir) = new_test_db().await?;

    insert_block(&writer.connection(), block).await?;
    let block_at_height = select_block_at_height(&*reader.connection().await?, height)
        .await?
        .unwrap();
    assert_eq!(block_at_height.height, height);
    assert_eq!(block_at_height.hash, hash);
    let last_block = select_block_latest(&*reader.connection().await?)
        .await?
        .unwrap();
    assert_eq!(last_block.height, height);
    assert_eq!(last_block.hash, hash);

    Ok(())
}

#[tokio::test]
async fn test_transaction() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let tx = writer.connection().transaction().await?;
    let height = 800000;
    let hash = new_mock_block_hash(height as u32);
    let block = BlockRow::builder().height(height).hash(hash).build();
    insert_block(&tx, block).await?;
    assert!(select_block_latest(&tx).await?.is_some());
    tx.commit().await?;
    Ok(())
}

#[tokio::test]
async fn test_crypto_extension() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let mut rows = conn
        .query("SELECT hex(crypto_sha256('abc'))", params![])
        .await?;
    let row = rows.next().await?.unwrap();
    let hash = row.get_str(0)?;
    assert_eq!(
        hash,
        "BA7816BF8F01CFEA414140DE5DAE2223B00361A396177A9CB410FF61F20015AD"
    );
    Ok(())
}

#[tokio::test]
async fn test_contract_state_operations() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    // First insert a block to satisfy foreign key constraints
    let height = 800000;
    let hash = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?;
    let block = BlockRow::builder().height(height).hash(hash).build();
    insert_block(&conn, block).await?;

    // Insert a transaction for the contract state
    let tx = TransactionRow::builder()
        .height(height)
        .txid("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string())
        .tx_index(0)
        .confirmed_height(height)
        .build();
    let tx_id = insert_transaction(&conn, tx.clone()).await?;

    // Test contract state insertion and retrieval
    let contract_id = 123;
    let path = cs_path(&["test", "path"]);
    let base = cs_path(&["test"]);
    let value = vec![1, 2, 3, 4];

    assert!(!contract_has_state(&conn, contract_id).await?);

    let contract_state = ContractStateRow::builder()
        .contract_id(contract_id)
        .tx_id(tx_id)
        .height(height)
        .path(path.clone())
        .value(value.clone())
        .build();

    // Insert contract state
    let id = insert_contract_state(&conn, contract_state.clone()).await?;
    assert!(id > 0, "Contract state insertion should succeed");

    // check existence
    assert!(contract_has_state(&conn, contract_id).await?);
    assert!(exists_contract_state(&conn, contract_id, &base).await?);

    // "path" is candidate index 0.
    assert_eq!(
        matching_path(&conn, contract_id, &base, &cands(&["path", "foo", "bar"]))
            .await?
            .unwrap(),
        0
    );

    // Get latest contract state
    let retrieved_state = get_latest_contract_state(&conn, contract_id, &path).await?;
    assert!(
        retrieved_state.is_some(),
        "Contract state should be retrieved"
    );

    // Get latest contract state value
    let fuel = 1000;
    let retrieved_value = get_latest_contract_state_value(&conn, 1000, contract_id, &path).await?;
    assert!(
        retrieved_value.is_some(),
        "Contract state value should be retrieved"
    );

    let retrieved_state = retrieved_state.unwrap();
    assert_eq!(retrieved_state.contract_id, contract_id);
    assert_eq!(retrieved_state.path, path);
    assert_eq!(retrieved_state.value, value);
    assert_eq!(retrieved_value.unwrap(), value);
    assert!(!retrieved_state.deleted);
    assert_eq!(retrieved_state.height, height);
    assert_eq!(retrieved_state.tx_id, contract_state.tx_id);

    // Test with a newer version of the same contract state
    let height2 = 800001;
    let hash2 = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05".parse()?;
    let block2 = BlockRow::builder().height(height2).hash(hash2).build();
    insert_block(&conn, block2).await?;

    let txid2 = "fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321";
    let tx2 = TransactionRow::builder()
        .height(height2)
        .txid(txid2.to_string())
        .tx_index(2)
        .confirmed_height(height2)
        .build();
    let tx_id2 = insert_transaction(&conn, tx2.clone()).await?;

    let updated_value = vec![5, 6, 7, 8];
    let updated_contract_state = ContractStateRow::builder()
        .contract_id(contract_id)
        .tx_id(tx_id2)
        .height(height2)
        .path(path.clone())
        .value(updated_value.clone())
        .build();
    insert_contract_state(&conn, updated_contract_state).await?;

    // Verify we get the latest version
    let latest_state = get_latest_contract_state(&conn, contract_id, &path)
        .await?
        .unwrap();
    let latest_value = get_latest_contract_state_value(&conn, fuel, contract_id, &path)
        .await?
        .unwrap();
    assert_eq!(latest_state.height, height2);
    assert_eq!(latest_state.value, updated_value);
    assert_eq!(latest_value, updated_value);

    // Delete the contract state
    let (deleted, _) =
        delete_contract_state(&conn, height2, Some(tx_id2), contract_id, &path).await?;
    assert!(deleted);

    let count = conn
        .query(
            "SELECT COUNT(*) FROM contract_state WHERE contract_id = :contract_id AND path = :path",
            (
                (":contract_id", contract_id),
                (":path", libsql::Value::Blob(path.clone())),
            ),
        )
        .await?
        .next()
        .await?
        .unwrap()
        .get::<u64>(0)
        .unwrap();
    assert_eq!(count, 2);

    // Verify the contract state is deleted
    let latest_state = get_latest_contract_state(&conn, contract_id, &path).await?;
    assert!(latest_state.is_none());

    Ok(())
}

// `live_deposit_gas_sum` returns the FROZEN per-row deposit GAS a depositor holds
// live across ALL contracts (the floor = their sum). Each row keeps the gas it was
// charged (so an evolving D never re-prices it); overwrites replace the row's gas,
// deletes drop it, and another depositor's rows are excluded.
#[tokio::test]
async fn test_live_deposit_gas_sum() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let height = 800000u64;
    insert_block(
        &conn,
        BlockRow::builder()
            .height(height)
            .hash(new_mock_block_hash(height as u32))
            .build(),
    )
    .await?;
    let tx = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(height)
            .txid(format!("bbbb{:060}", 0))
            .tx_index(0)
            .confirmed_height(height)
            .build(),
    )
    .await?;
    let alice = create_contract_signer(&conn, height).await?;
    let bob = create_contract_signer(&conn, height).await?;
    let put = async |cid: u64, key: &str, gas: u64, who: u64| -> Result<()> {
        insert_contract_state(
            &conn,
            ContractStateRow::builder()
                .contract_id(cid)
                .tx_id(tx)
                .height(height)
                .path(cs_path(&[key]))
                .value(vec![1])
                .depositor(who)
                .deposited_gas(gas)
                .build(),
        )
        .await?;
        Ok(())
    };
    let p_bb = cs_path(&["bb"]);
    let sum = async |who: u64| -> Result<u64> { Ok(live_deposit_gas_sum(&conn, who).await?) };

    // Empty → no rows.
    assert_eq!(sum(alice).await?, 0);

    // alice's frozen deposits in two contracts; bob's row is excluded from alice's.
    put(1, "a", 10, alice).await?;
    put(2, "bb", 25, alice).await?;
    put(1, "z", 99, bob).await?;
    assert_eq!(sum(alice).await?, 35);

    // Overwrite alice's contract-1 row (same height replaces) with a new frozen
    // amount → the old amount drops, the new one counts.
    put(1, "a", 40, alice).await?;
    assert_eq!(sum(alice).await?, 65);

    // Tombstone alice's contract-2 row → its deposit drops from the floor.
    delete_contract_state(&conn, height, Some(tx), 2, &p_bb).await?;
    assert_eq!(sum(alice).await?, 40);

    // bob's floor is just his own row.
    assert_eq!(sum(bob).await?, 99);
    Ok(())
}

// A row's `depositor` (the storage-deposit floor basis) round-trips through
// insert → `get_latest_contract_state`; a tombstone carries NO depositor.
#[tokio::test]
async fn test_depositor_roundtrips_and_tombstone_clears_it() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let cid = 55;
    let height = 800000u64;
    insert_block(
        &conn,
        BlockRow::builder()
            .height(height)
            .hash(new_mock_block_hash(height as u32))
            .build(),
    )
    .await?;
    let tx = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(height)
            .txid(format!("cccc{:060}", 0))
            .tx_index(0)
            .confirmed_height(height)
            .build(),
    )
    .await?;
    // A real signer to satisfy the depositor FK.
    let sid = create_contract_signer(&conn, height).await?;
    let path = cs_path(&["k"]);

    insert_contract_state(
        &conn,
        ContractStateRow::builder()
            .contract_id(cid)
            .tx_id(tx)
            .height(height)
            .path(path.clone())
            .value(vec![1, 2, 3])
            .depositor(sid)
            .deposited_gas(42)
            .build(),
    )
    .await?;

    // The depositor + deposited_amount round-trip through the latest-state read
    // (the columns that back the storage-deposit floor).
    let row = get_latest_contract_state(&conn, cid, &path).await?.unwrap();
    assert_eq!(row.depositor, Some(sid));
    assert_eq!(row.deposited_gas, Some(42));
    // …and the delete find surfaces the live row (path + size, value-less).
    let found = find_live_subtree(&conn, cid, &path).await?;
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].size, 3);

    // Tombstone (same height → replaces the live row) carries no depositor.
    delete_contract_state(&conn, height, Some(tx), cid, &path).await?;
    let mut tomb = conn
        .query(
            "SELECT depositor, deleted FROM contract_state WHERE contract_id = ? AND path = ?",
            params![cid, libsql::Value::Blob(path.clone())],
        )
        .await?;
    let r = tomb.next().await?.unwrap();
    assert!(r.get::<bool>(1)?, "row is a tombstone");
    assert_eq!(
        r.get::<Option<u64>>(0)?,
        None,
        "a tombstone has no depositor"
    );
    Ok(())
}

// The eager `depositor_footprint` cache plumbing: set/get/delete round-trip
// (absence ⇔ zero), live-depositor discovery (reconstruct source), and the
// load-bearing `depositors_affected_by_reorg` predicate that bounds the reorg
// reversal (a rollback past a depositor's row must flag them; one that leaves
// nothing above the target must not).
#[tokio::test]
async fn test_footprint_cache_and_reorg_affected() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let cid = 77;
    for h in [10u64, 12u64] {
        insert_block(
            &conn,
            BlockRow::builder()
                .height(h)
                .hash(new_mock_block_hash(h as u32))
                .build(),
        )
        .await?;
    }
    let sid = create_contract_signer(&conn, 10).await?;
    // sid deposits path `a` at height 10 ("100") and path `b` at height 12 ("50").
    for (h, key, gas) in [(10u64, "a", 100u64), (12u64, "b", 50u64)] {
        let tx = insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(h)
                .txid(format!("d{:063}", h))
                .tx_index(0)
                .confirmed_height(h)
                .build(),
        )
        .await?;
        insert_contract_state(
            &conn,
            ContractStateRow::builder()
                .contract_id(cid)
                .tx_id(tx)
                .height(h)
                .path(cs_path(&[key]))
                .value(vec![1])
                .depositor(sid)
                .deposited_gas(gas)
                .build(),
        )
        .await?;
    }

    // set/get/delete round-trip + atomic add.
    assert_eq!(footprint_cache_get(&conn, sid).await?, None);
    footprint_cache_set(&conn, sid, Some(150)).await?;
    assert_eq!(footprint_cache_get(&conn, sid).await?, Some(150));
    footprint_cache_add(&conn, sid, -50).await?;
    assert_eq!(footprint_cache_get(&conn, sid).await?, Some(100));
    footprint_cache_add(&conn, sid, -100).await?; // → 0 prunes the row
    assert_eq!(footprint_cache_get(&conn, sid).await?, None);

    // Over-subtract (would underflow) clamps to 0 and prunes — never a negative row
    // (which the zero-prune would miss and the fail-loud read would reject).
    footprint_cache_set(&conn, sid, Some(30)).await?;
    footprint_cache_add(&conn, sid, -100).await?; // 30 - 100 → max(0, …) = 0 → pruned
    assert_eq!(footprint_cache_get(&conn, sid).await?, None);
    // Subtract against a non-existent row also clamps (inserts max(0, -5) = 0 → pruned).
    footprint_cache_add(&conn, sid, -5).await?;
    assert_eq!(footprint_cache_get(&conn, sid).await?, None);

    // reconstruct source: sid's live floor sums to 150.
    assert_eq!(live_deposit_gas_sum(&conn, sid).await?, 150);

    // reorg reversal predicate (tip = MAX(height) = 12, derived in-query): rollback to 11
    // drops the height-12 row → sid affected; rollback to 12 leaves nothing above → not.
    assert!(
        depositors_affected_by_reorg(&conn, 11)
            .await?
            .contains(&sid)
    );
    assert!(
        !depositors_affected_by_reorg(&conn, 12)
            .await?
            .contains(&sid)
    );
    Ok(())
}

// The per-signer footprint query: returns a depositor's LIVE rows across all
// contracts, excluding other depositors' rows and any row superseded by a newer
// version (overwritten/deleted → it drops from their floor). Exercises the
// depositor filter, the cross-contract JOIN, and the NOT EXISTS liveness.
#[tokio::test]
async fn test_find_footprint_by_depositor() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let h1 = 800000u64;
    let h2 = h1 + 1;
    for h in [h1, h2] {
        insert_block(
            &conn,
            BlockRow::builder()
                .height(h)
                .hash(new_mock_block_hash(h as u32))
                .build(),
        )
        .await?;
    }
    let tx1 = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(h1)
            .txid(format!("aaaa{:060}", 0))
            .tx_index(0)
            .confirmed_height(h1)
            .build(),
    )
    .await?;
    let tx2 = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(h2)
            .txid(format!("bbbb{:060}", 0))
            .tx_index(0)
            .confirmed_height(h2)
            .build(),
    )
    .await?;

    // Two contracts → exercise the cross-contract breakdown + name JOIN.
    let alpha = insert_contract(
        &conn,
        ContractRow::builder()
            .name("alpha".to_string())
            .height(h1)
            .tx_index(0)
            .bytes(vec![])
            .build(),
    )
    .await?;
    let beta = insert_contract(
        &conn,
        ContractRow::builder()
            .name("beta".to_string())
            .height(h1)
            .tx_index(1)
            .bytes(vec![])
            .build(),
    )
    .await?;
    let alice = create_contract_signer(&conn, h1).await?;
    let bob = create_contract_signer(&conn, h1).await?;

    let set = async |cid: u64, seg: &str, who: u64, gas: u64, h: u64, tx: u64| -> Result<()> {
        insert_contract_state(
            &conn,
            ContractStateRow::builder()
                .contract_id(cid)
                .tx_id(tx)
                .height(h)
                .path(cs_path(&[seg]))
                .value(vec![1, 2, 3])
                .depositor(who)
                .deposited_gas(gas)
                .build(),
        )
        .await?;
        Ok(())
    };

    // alice: two live rows in alpha, one in beta.
    set(alpha, "a1", alice, 10, h1, tx1).await?;
    set(alpha, "a2", alice, 5, h1, tx1).await?;
    set(beta, "b1", alice, 30, h1, tx1).await?;
    // bob's row → excluded by the depositor filter.
    set(beta, "b2", bob, 99, h1, tx1).await?;
    // alice set a3, then it was overwritten by bob at a newer height → alice's a3
    // is superseded (drops from alice's floor, moves to bob's) and must NOT appear.
    set(alpha, "a3", alice, 1000, h1, tx1).await?;
    set(alpha, "a3", bob, 7, h2, tx2).await?;

    let rows = find_footprint_by_depositor(&conn, alice).await?;
    assert_eq!(
        rows.len(),
        3,
        "alice's live rows: a1, a2 (alpha) + b1 (beta)"
    );

    let alpha_total: u64 = rows
        .iter()
        .filter(|r| r.contract_id == alpha)
        .map(|r| r.deposited_gas)
        .sum();
    let beta_total: u64 = rows
        .iter()
        .filter(|r| r.contract_id == beta)
        .map(|r| r.deposited_gas)
        .sum();
    assert_eq!(alpha_total, 15, "10 + 5; a3 superseded, excluded");
    assert_eq!(beta_total, 30, "b1 only; b2 is bob's");
    assert!(rows.iter().any(|r| r.contract_name == "alpha"));
    assert!(rows.iter().any(|r| r.contract_name == "beta"));
    assert!(
        rows.iter().all(|r| r.footprint_bytes > 0),
        "path + value bytes"
    );

    // A signer with no deposits gets an empty footprint.
    assert!(
        find_footprint_by_depositor(&conn, bob + 999)
            .await?
            .is_empty()
    );
    Ok(())
}

// `delete_contract_state` must tombstone the WHOLE subtree of an entry, not just
// the exact path: a struct/map value persists under child paths (`key.field`),
// so removing it has to clear every live descendant — else `Map`/`IndexedMap`
// `remove` leaves live primary rows behind after clearing the index. Sibling
// entries (boundaried at `.`) must be untouched. Regression for "remove skips
// nested stored fields".
#[tokio::test]
async fn test_delete_tombstones_whole_subtree() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let cid = 123;
    let height = 800000u64;
    insert_block(
        &conn,
        BlockRow::builder()
            .height(height)
            .hash(new_mock_block_hash(height as u32))
            .build(),
    )
    .await?;
    let tx = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(height)
            .txid(format!("aaaa{:060}", 0))
            .tx_index(0)
            .confirmed_height(height)
            .build(),
    )
    .await?;
    let insert = async |segments: &[&str]| -> Result<()> {
        insert_contract_state(
            &conn,
            ContractStateRow::builder()
                .contract_id(cid)
                .tx_id(tx)
                .height(height)
                .path(cs_path(segments))
                .value(vec![1])
                .build(),
        )
        .await?;
        Ok(())
    };

    // Struct value `m/k` lives under child field paths (incl. a nested struct);
    // `m/k2` is a sibling entry that must survive — the codec's element
    // terminators make `m/k` NOT a byte-prefix of `m/k2`.
    insert(&["m", "k", "field1"]).await?;
    insert(&["m", "k", "field2"]).await?;
    insert(&["m", "k", "nested", "inner"]).await?;
    insert(&["m", "k2", "field1"]).await?;

    let (removed, freed) =
        delete_contract_state(&conn, height, Some(tx), cid, &cs_path(&["m", "k"])).await?;
    assert!(removed, "the subtree had live rows to tombstone");
    // Freed bytes = path + value (1 byte each) of every tombstoned row in the
    // subtree — the three `m/k/*` rows, not the surviving `m/k2` sibling.
    let expected_freed: u64 = [
        cs_path(&["m", "k", "field1"]),
        cs_path(&["m", "k", "field2"]),
        cs_path(&["m", "k", "nested", "inner"]),
    ]
    .iter()
    .map(|p| (p.len() + 1) as u64)
    .sum();
    assert_eq!(freed, expected_freed);

    // Tombstones are VALUE-LESS: the deleted row stores an empty value (not the
    // original 1-byte value), even though `freed` still counts the original size.
    let mut tomb = conn
        .query(
            "SELECT value, deleted FROM contract_state WHERE contract_id = ? AND path = ?",
            params![cid, libsql::Value::Blob(cs_path(&["m", "k", "field1"]))],
        )
        .await?;
    let row = tomb.next().await?.unwrap();
    assert!(row.get::<bool>(1)?, "row is a tombstone");
    assert!(
        row.get::<Vec<u8>>(0)?.is_empty(),
        "tombstone value must be empty"
    );

    // Every descendant of `m/k` is gone (not just the exact path).
    assert!(!exists_contract_state(&conn, cid, &cs_path(&["m", "k"])).await?);
    assert!(
        get_latest_contract_state(&conn, cid, &cs_path(&["m", "k", "field1"]))
            .await?
            .is_none()
    );
    assert!(
        get_latest_contract_state(&conn, cid, &cs_path(&["m", "k", "nested", "inner"]))
            .await?
            .is_none()
    );

    // The boundaried sibling `m/k2` is untouched.
    assert!(exists_contract_state(&conn, cid, &cs_path(&["m", "k2"])).await?);
    assert!(
        get_latest_contract_state(&conn, cid, &cs_path(&["m", "k2", "field1"]))
            .await?
            .is_some()
    );

    // A second remove finds nothing live → no-op, returns false.
    assert!(
        !delete_contract_state(&conn, height, Some(tx), cid, &cs_path(&["m", "k"]))
            .await?
            .0
    );

    Ok(())
}

#[tokio::test]
async fn test_transaction_operations() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    // Insert a block first
    let height = 800000;
    let hash = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?;
    let block = BlockRow::builder().height(height).hash(hash).build();
    insert_block(&conn, block).await?;

    let tx1 = TransactionRow::builder()
        .height(height)
        .txid("abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890".to_string())
        .tx_index(0)
        .confirmed_height(height)
        .build();
    let tx2 = TransactionRow::builder()
        .height(height)
        .txid("123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef0".to_string())
        .tx_index(1)
        .confirmed_height(height)
        .build();
    let tx3 = TransactionRow::builder()
        .height(height)
        .txid("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321".to_string())
        .tx_index(2)
        .confirmed_height(height)
        .build();

    // Insert multiple transactions at the same height

    insert_transaction(&conn, tx1.clone()).await?;
    insert_transaction(&conn, tx2.clone()).await?;
    insert_transaction(&conn, tx3.clone()).await?;

    // Test get_transaction_by_txid
    let result = get_transaction_by_txid(&conn, tx2.txid.as_str())
        .await?
        .unwrap();
    assert_eq!(tx2.txid, result.txid);
    assert_eq!(tx2.height, result.height);
    assert_eq!(tx2.tx_index, result.tx_index);

    // Test get_transactions_at_height
    let txs_at_height = get_transactions_at_height(&conn, height).await?;
    assert_eq!(txs_at_height.len(), 3);

    // Verify all transactions are included - now using TransactionRow objects
    let txids = txs_at_height
        .iter()
        .map(|tx| tx.txid.clone())
        .collect::<HashSet<_>>();

    assert!(txids.contains(&tx1.txid));
    assert!(txids.contains(&tx2.txid));
    assert!(txids.contains(&tx3.txid));

    // Insert transactions at a different height
    let height2 = 800001;
    let hash2 = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05".parse()?;
    let block2 = BlockRow::builder().height(height2).hash(hash2).build();
    insert_block(&conn, block2).await?;

    let tx4_txid = "aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899".to_string();
    let tx4 = TransactionRow::builder()
        .height(height2)
        .txid(tx4_txid.clone())
        .tx_index(0)
        .build();

    insert_transaction(&conn, tx4).await?;

    // Verify get_transactions_at_height returns only transactions at the specified height
    let txs_at_height1 = get_transactions_at_height(&conn, height).await?;
    assert_eq!(txs_at_height1.len(), 3);

    let txs_at_height2 = get_transactions_at_height(&conn, height2).await?;
    assert_eq!(txs_at_height2.len(), 1);

    // Check the transaction details
    let tx4 = &txs_at_height2[0];
    assert_eq!(tx4.tx_index, Some(0));
    assert_eq!(tx4.txid, tx4_txid);
    assert_eq!(tx4.height, height2);

    Ok(())
}

#[tokio::test]
async fn test_select_block_by_height_or_hash() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    // Insert test blocks
    let block1 = BlockRow::builder()
        .height(800000)
        .hash("000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?)
        .build();
    let block2 = BlockRow::builder()
        .height(800001)
        .hash("000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05".parse()?)
        .build();
    let block3 = BlockRow::builder()
        .height(123456)
        .hash("abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".parse()?)
        .build();

    insert_block(&conn, block1.clone()).await?;
    insert_block(&conn, block2.clone()).await?;
    insert_block(&conn, block3.clone()).await?;

    // Test 1: Find by height (as string)
    let result = select_block_by_height_or_hash(&conn, "800000").await?;
    assert!(result.is_some());
    let found_block = result.unwrap();
    assert_eq!(found_block.height, 800000);
    assert_eq!(found_block.hash, block1.hash);

    // Test 2: Find by hash
    let result = select_block_by_height_or_hash(
        &conn,
        "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba05",
    )
    .await?;
    assert!(result.is_some());
    let found_block = result.unwrap();
    assert_eq!(found_block.height, 800001);
    assert_eq!(found_block.hash, block2.hash);

    // Test 3: Find by different height
    let result = select_block_by_height_or_hash(&conn, "123456").await?;
    assert!(result.is_some());
    let found_block = result.unwrap();
    assert_eq!(found_block.height, 123456);
    assert_eq!(found_block.hash, block3.hash);

    // Test 4: Find by different hash
    let result = select_block_by_height_or_hash(
        &conn,
        "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789",
    )
    .await?;
    assert!(result.is_some());
    let found_block = result.unwrap();
    assert_eq!(found_block.height, 123456);
    assert_eq!(found_block.hash, block3.hash);

    // Test 5: Non-existent height
    let result = select_block_by_height_or_hash(&conn, "999999").await?;
    assert!(result.is_none());

    // Test 6: Non-existent hash
    let result = select_block_by_height_or_hash(&conn, "nonexistenthash123456789").await?;
    assert!(result.is_none());

    // Test 7: Invalid height format (non-numeric string that's not a hash)
    let result = select_block_by_height_or_hash(&conn, "invalid_height").await?;
    assert!(result.is_none());

    // Test 8: Empty string
    let result = select_block_by_height_or_hash(&conn, "").await?;
    assert!(result.is_none());

    // Test 9: Height 0 (edge case)
    let block_zero = BlockRow::builder()
        .height(0)
        .hash("0000000000000000000000000000000000000000000000000000000000000000".parse()?)
        .build();
    insert_block(&conn, block_zero.clone()).await?;

    let result = select_block_by_height_or_hash(&conn, "0").await?;
    assert!(result.is_some());
    let found_block = result.unwrap();
    assert_eq!(found_block.height, 0);
    assert_eq!(found_block.hash, block_zero.hash);

    // Test 10: Very large height
    let large_height = u64::MAX;
    let result = select_block_by_height_or_hash(&conn, &large_height.to_string()).await?;
    assert!(result.is_none());

    // Test 11: Partial hash match (should not match)
    let result = select_block_by_height_or_hash(&conn, "000000000000000000015d76").await?;
    assert!(result.is_none());

    Ok(())
}

#[tokio::test]
async fn test_contracts() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    insert_block(
        &conn,
        BlockRow::builder()
            .hash(new_mock_block_hash(0))
            .height(0)
            .build(),
    )
    .await?;
    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(0)
            .tx_index(1)
            .txid(new_mock_transaction(1).txid.to_string())
            .build(),
    )
    .await?;
    let row = ContractRow::builder()
        .bytes("value".as_bytes().to_vec())
        .height(0)
        .tx_index(1)
        .name("test".to_string())
        .build();
    insert_contract(&conn, row.clone()).await?;
    let address = ContractAddress {
        height: 0,
        tx_index: 1,
        name: "test".to_string(),
    };
    let bytes = get_contract_bytes_by_address(&conn, &address)
        .await?
        .unwrap();
    assert_eq!(bytes, row.bytes);
    let id = get_contract_id_from_address(&conn, &address)
        .await?
        .unwrap();
    let bytes = get_contract_bytes_by_id(&conn, id).await?.unwrap();
    assert_eq!(bytes, row.bytes);
    let (rows, _) = get_contracts_paginated(&conn, ContractQuery::builder().build()).await?;
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0], ContractListRow { id, ..row.into() });
    Ok(())
}

#[tokio::test]
async fn test_contracts_gapless() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let insert = async |conn: &Connection, i: u64| {
        insert_block(
            conn,
            BlockRow::builder()
                .hash(new_mock_block_hash(i as u32))
                .height(i)
                .build(),
        )
        .await
        .unwrap();
        let row = ContractRow::builder()
            .bytes("value".as_bytes().to_vec())
            .height(i)
            .tx_index(1)
            .name("test".to_string())
            .build();
        insert_contract(conn, row.clone()).await.unwrap();
    };
    for i in 1u64..=5 {
        insert(&conn, i).await;
    }
    let query = "SELECT id FROM contracts ORDER BY height ASC";
    let get_ids = async |conn: &Connection| {
        conn.query(query, params![])
            .await
            .unwrap()
            .into_stream()
            .map(|row| row.unwrap().get::<i64>(0).unwrap())
            .collect::<Vec<_>>()
            .await
    };
    assert_eq!(get_ids(&conn).await, vec![1, 2, 3, 4, 5]);
    rollback_to_height(&conn, 3).await?;
    assert_eq!(get_ids(&conn).await, vec![1, 2, 3]);
    for i in 4u64..=5 {
        insert(&conn, i).await;
    }
    assert_eq!(get_ids(&conn).await, vec![1, 2, 3, 4, 5]);
    Ok(())
}

#[tokio::test]
async fn test_get_contracts_paginated() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    insert_block(
        &conn,
        BlockRow::builder()
            .hash(new_mock_block_hash(1))
            .height(1)
            .build(),
    )
    .await?;

    let mut ids = Vec::new();
    for i in 0u32..5 {
        let id = insert_contract(
            &conn,
            ContractRow::builder()
                .name(format!("c{}", i))
                .height(1)
                .tx_index(i)
                .bytes(vec![])
                .build(),
        )
        .await?;
        ids.push(id);
    }

    // Default order is DESC — page 1 returns the latest 2.
    let (page1, meta1) =
        get_contracts_paginated(&conn, ContractQuery::builder().limit(2).build()).await?;
    assert_eq!(page1.len(), 2);
    assert_eq!(page1[0].id, ids[4]);
    assert_eq!(page1[1].id, ids[3]);
    assert!(meta1.has_more);
    assert_eq!(meta1.total_count, 5);

    // Cursor follows: next page picks up below the cursor id.
    let (page2, meta2) = get_contracts_paginated(
        &conn,
        ContractQuery::builder()
            .limit(2)
            .cursor(meta1.next_cursor.unwrap())
            .build(),
    )
    .await?;
    assert_eq!(page2.len(), 2);
    assert_eq!(page2[0].id, ids[2]);
    assert_eq!(page2[1].id, ids[1]);
    assert!(meta2.has_more);

    Ok(())
}

#[tokio::test]
async fn test_get_contracts_signer_id_filter() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    insert_block(
        &conn,
        BlockRow::builder()
            .hash(new_mock_block_hash(1))
            .height(1)
            .build(),
    )
    .await?;

    let signer_a = ensure_identity(
        &conn,
        "1111111111111111111111111111111111111111111111111111111111111111",
        1,
    )
    .await?
    .signer_id();
    let signer_b = ensure_identity(
        &conn,
        "2222222222222222222222222222222222222222222222222222222222222222",
        1,
    )
    .await?
    .signer_id();

    // 2 contracts for signer_a, 1 for signer_b, 1 with no signer (publish without signer).
    let id_a1 = insert_contract(
        &conn,
        ContractRow::builder()
            .name("a1".to_string())
            .height(1)
            .tx_index(0)
            .bytes(vec![])
            .signer_id(signer_a)
            .build(),
    )
    .await?;
    let id_a2 = insert_contract(
        &conn,
        ContractRow::builder()
            .name("a2".to_string())
            .height(1)
            .tx_index(1)
            .bytes(vec![])
            .signer_id(signer_a)
            .build(),
    )
    .await?;
    let _id_b = insert_contract(
        &conn,
        ContractRow::builder()
            .name("b".to_string())
            .height(1)
            .tx_index(2)
            .bytes(vec![])
            .signer_id(signer_b)
            .build(),
    )
    .await?;
    insert_contract(
        &conn,
        ContractRow::builder()
            .name("anon".to_string())
            .height(1)
            .tx_index(3)
            .bytes(vec![])
            .build(),
    )
    .await?;

    let (rows, meta) =
        get_contracts_paginated(&conn, ContractQuery::builder().signer_id(signer_a).build())
            .await?;
    assert_eq!(meta.total_count, 2);
    let returned: Vec<u64> = rows.iter().map(|r| r.id).collect();
    assert_eq!(returned, vec![id_a2, id_a1]);
    assert!(rows.iter().all(|r| r.signer_id == Some(signer_a)));

    Ok(())
}

#[tokio::test]
async fn test_map_keys() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    let height = 800000;
    let block1 = BlockRow::builder()
        .height(height)
        .hash("000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?)
        .build();

    insert_block(&conn, block1.clone()).await?;

    // Insert transactions to satisfy FK constraints
    let tx_id1 = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(height)
            .txid("aaaa000000000000000000000000000000000000000000000000000000000001".to_string())
            .tx_index(0)
            .confirmed_height(height)
            .build(),
    )
    .await?;
    let tx_id2 = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(height)
            .txid("aaaa000000000000000000000000000000000000000000000000000000000002".to_string())
            .tx_index(1)
            .confirmed_height(height)
            .build(),
    )
    .await?;
    let tx_id3 = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(height)
            .txid("aaaa000000000000000000000000000000000000000000000000000000000003".to_string())
            .tx_index(2)
            .confirmed_height(height)
            .build(),
    )
    .await?;

    let contract_id = 123;
    let path = "test.path";
    let value = vec![1, 2, 3, 4];

    let contract_state = ContractStateRow::builder()
        .contract_id(contract_id)
        .tx_id(tx_id1)
        .height(height)
        .path(cs_path_dotted(&format!("{}.key0.foo", path)))
        .value(value.clone())
        .build();

    insert_contract_state(&conn, contract_state).await?;

    let contract_state = ContractStateRow::builder()
        .contract_id(contract_id)
        .tx_id(tx_id1)
        .height(height)
        .path(cs_path_dotted(&format!("{}.key0.bar", path)))
        .value(value.clone())
        .build();

    insert_contract_state(&conn, contract_state).await?;

    let contract_state = ContractStateRow::builder()
        .contract_id(contract_id)
        .tx_id(tx_id2)
        .height(height)
        .path(cs_path_dotted(&format!("{}.key2", path)))
        .value(value.clone())
        .build();
    insert_contract_state(&conn, contract_state).await?;

    let contract_state = ContractStateRow::builder()
        .contract_id(contract_id)
        .tx_id(tx_id3)
        .height(height)
        .path(cs_path_dotted(&format!("{}.key1", path)))
        .value(value.clone())
        .build();
    insert_contract_state(&conn, contract_state).await?;

    let stream = path_prefix_filter_contract_state(
        &conn,
        contract_id,
        cs_path_dotted("test.path"),
        None,
        None,
    )
    .await?;
    let paths = stream.try_collect::<Vec<Vec<u8>>>().await?;
    // Each item is the child key's codec element (one segment), deduped + ordered.
    assert_eq!(paths.len(), 3);
    assert_eq!(paths[0], cs_path(&["key0"]));
    assert_eq!(paths[1], cs_path(&["key1"]));
    assert_eq!(paths[2], cs_path(&["key2"]));

    // The read half returns the rows the delete will remove (for metering)…
    let rows = find_matching_paths(
        &conn,
        contract_id,
        height,
        &cs_path_dotted("test.path"),
        &cands(&["key0"]),
    )
    .await?;
    assert_eq!(rows.len(), 2);
    // …and the write half removes exactly those rows.
    let deleted = hard_delete_matching_paths(
        &conn,
        contract_id,
        height,
        &cs_path_dotted("test.path"),
        &cands(&["key0"]),
    )
    .await?;
    assert_eq!(deleted, 2);

    Ok(())
}

// Reproduces the filestorage `get_agreement_nodes` failure after a member
// leaves: an IndexedMap whose struct value has a sub-field, plus a sibling
// `#idx` index that churns on update (tombstone + re-add). `keys(m)` must return
// the primary keys regardless of the index churn or the value update, AND a scan
// of an index bucket (`by_index`) must drop a member whose entry was tombstoned —
// not fall back to its older live row.
#[tokio::test]
async fn test_keys_with_idx_sibling_after_update() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let cid = 123;

    let mut txs = Vec::new();
    for (i, height) in [800000u64, 800001].into_iter().enumerate() {
        insert_block(
            &conn,
            BlockRow::builder()
                .height(height)
                .hash(new_mock_block_hash(height as u32))
                .build(),
        )
        .await?;
        txs.push(
            insert_transaction(
                &conn,
                TransactionRow::builder()
                    .height(height)
                    .txid(format!("bbbb{:060}", i))
                    .tx_index(0)
                    .confirmed_height(height)
                    .build(),
            )
            .await?,
        );
    }
    let insert = async |tx_id, height, path: &str| -> Result<()> {
        insert_contract_state(
            &conn,
            ContractStateRow::builder()
                .contract_id(cid)
                .tx_id(tx_id)
                .height(height)
                .path(cs_path_dotted(path))
                .value(vec![1])
                .build(),
        )
        .await?;
        Ok(())
    };

    // H1: two members active. Exact filestorage nesting/underscores — primary
    // `<m>.<id>.active`, index sibling `<m>#idx...` string-extends `<m>`.
    let m = "agreement_nodes.leave_test.nodes";
    insert(txs[0], 800000, &format!("{m}.44.active")).await?;
    insert(txs[0], 800000, &format!("{m}.45.active")).await?;
    insert(txs[0], 800000, &format!("{m}#idx.active.true.44")).await?;
    insert(txs[0], 800000, &format!("{m}#idx.active.true.45")).await?;

    // H2: member 44 leaves (active=false). Index churns: tombstone the old
    // bucket entry, write the new one.
    insert(txs[1], 800001, &format!("{m}.44.active")).await?;
    delete_contract_state(
        &conn,
        800001,
        Some(txs[1]),
        cid,
        &cs_path_dotted(&format!("{m}#idx.active.true.44")),
    )
    .await?;
    insert(txs[1], 800001, &format!("{m}#idx.active.false.44")).await?;

    // `keys(m)` — both members are still in the primary map (44's value row was
    // updated, not removed), regardless of index churn.
    let stream =
        path_prefix_filter_contract_state(&conn, cid, cs_path_dotted(m), None, None).await?;
    let mut keys = stream.try_collect::<Vec<Vec<u8>>>().await?;
    keys.sort();
    assert_eq!(keys, vec![cs_path(&["44"]), cs_path(&["45"])]);

    // `by_index("active","true")` = a scan of the `active.true` bucket. 44 left,
    // so `<m>#idx.active.true.44` was tombstoned at H2; only 45 remains. The
    // departed member must NOT reappear via its older (H1) live row — that was
    // the pre-rank `deleted = false` bug, which let a tombstoned entry fall back.
    let active = path_prefix_filter_contract_state(
        &conn,
        cid,
        cs_path_dotted(&format!("{m}#idx.active.true")),
        None,
        None,
    )
    .await?
    .try_collect::<Vec<Vec<u8>>>()
    .await?;
    assert_eq!(active, vec![cs_path(&["45"])]);

    Ok(())
}

// A live value under a prefix must make `exists` true even when the
// latest-height row under that prefix is a tombstone (e.g. an IndexedMap index
// Regression: a guest can pass an empty `list<u8>` (or any degenerate path).
// `strinc(empty)` is `None` (no exclusive upper bound), so the subtree-bound
// builder must treat it as the whole keyspace — NOT panic via `expect`. Covers
// exists / keys / matching / delete on an empty path.
#[tokio::test]
async fn test_empty_path_is_whole_keyspace_not_panic() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    let height = 900000;
    for h in [height, height + 1] {
        insert_block(
            &conn,
            BlockRow::builder()
                .height(h)
                .hash(bitcoin::BlockHash::from_byte_array([h as u8; 32]))
                .build(),
        )
        .await?;
    }
    let tx = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(height)
            .txid("bbbb000000000000000000000000000000000000000000000000000000000001".to_string())
            .tx_index(0)
            .confirmed_height(height)
            .build(),
    )
    .await?;

    let cid = 1;
    for k in ["k1", "k2"] {
        insert_contract_state(
            &conn,
            ContractStateRow::builder()
                .contract_id(cid)
                .tx_id(tx)
                .height(height)
                .path(cs_path(&["m", k]))
                .value(vec![1])
                .build(),
        )
        .await?;
    }

    // Empty path = whole keyspace: any live row makes `exists` true.
    assert!(exists_contract_state(&conn, cid, &[]).await?);
    // `keys()` of the root yields the single distinct top-level element ("m").
    let top: Vec<Vec<u8>> = path_prefix_filter_contract_state(&conn, cid, Vec::new(), None, None)
        .await?
        .try_collect()
        .await?;
    assert_eq!(top, vec![cs_path(&["m"])]);
    // `matching_path` at the root must not panic.
    let _ = matching_path(&conn, cid, &[], &cands(&["none", "some"])).await?;
    // Deleting the empty subtree tombstones the whole keyspace.
    assert!(
        delete_contract_state(&conn, height + 1, Some(tx), cid, &[])
            .await?
            .0
    );
    assert!(!exists_contract_state(&conn, cid, &[]).await?);

    Ok(())
}

// delete). Regression: `exists` ranked rows globally (no per-path partition),
// so it saw only the single newest row — if that was a tombstone it wrongly
// reported the whole subtree gone.
#[tokio::test]
async fn test_exists_with_tombstone_as_latest_row() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let cid = 123;

    let mut txs = Vec::new();
    for (i, height) in [800000u64, 800001].into_iter().enumerate() {
        insert_block(
            &conn,
            BlockRow::builder()
                .height(height)
                .hash(new_mock_block_hash(height as u32))
                .build(),
        )
        .await?;
        txs.push(
            insert_transaction(
                &conn,
                TransactionRow::builder()
                    .height(height)
                    .txid(format!("cccc{:060}", i))
                    .tx_index(0)
                    .confirmed_height(height)
                    .build(),
            )
            .await?,
        );
    }

    // A live value under `a` at H1.
    insert_contract_state(
        &conn,
        ContractStateRow::builder()
            .contract_id(cid)
            .tx_id(txs[0])
            .height(800000)
            .path(cs_path_dotted("a.live"))
            .value(vec![1])
            .build(),
    )
    .await?;
    // A tombstone under `a` at a strictly higher height (the newest row).
    insert_contract_state(
        &conn,
        ContractStateRow::builder()
            .contract_id(cid)
            .tx_id(txs[1])
            .height(800001)
            .path(cs_path_dotted("a.gone"))
            .value(vec![1])
            .build(),
    )
    .await?;
    delete_contract_state(&conn, 800001, Some(txs[1]), cid, &cs_path_dotted("a.gone")).await?;

    assert!(
        exists_contract_state(&conn, cid, &cs_path_dotted("a")).await?,
        "`a.live` is still live, so `a` must exist despite the newer tombstone"
    );

    Ok(())
}

// `matching_path` resolves an enum's live variant. After a re-set (old variant
// tombstoned, new variant written at the same height), it must return the NEW
// variant — the per-path ranking must not let the old tombstone win.
#[tokio::test]
async fn test_matching_path_after_enum_reset() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let cid = 123;

    let mut txs = Vec::new();
    for (i, height) in [800000u64, 800001].into_iter().enumerate() {
        insert_block(
            &conn,
            BlockRow::builder()
                .height(height)
                .hash(new_mock_block_hash(height as u32))
                .build(),
        )
        .await?;
        txs.push(
            insert_transaction(
                &conn,
                TransactionRow::builder()
                    .height(height)
                    .txid(format!("dddd{:060}", i))
                    .tx_index(0)
                    .confirmed_height(height)
                    .build(),
            )
            .await?,
        );
    }

    // H1: status = active.
    insert_contract_state(
        &conn,
        ContractStateRow::builder()
            .contract_id(cid)
            .tx_id(txs[0])
            .height(800000)
            .path(cs_path_dotted("c.status.active"))
            .value(vec![])
            .build(),
    )
    .await?;
    // H2: re-set to proven — tombstone `active`, write `proven` (same height).
    delete_contract_state(
        &conn,
        800001,
        Some(txs[1]),
        cid,
        &cs_path_dotted("c.status.active"),
    )
    .await?;
    insert_contract_state(
        &conn,
        ContractStateRow::builder()
            .contract_id(cid)
            .tx_id(txs[1])
            .height(800001)
            .path(cs_path_dotted("c.status.proven"))
            .value(vec![])
            .build(),
    )
    .await?;

    let found = matching_path(
        &conn,
        cid,
        &cs_path_dotted("c.status"),
        &cands(&["active", "proven"]),
    )
    .await?;
    assert_eq!(found, Some(1)); // "proven" is candidate index 1

    Ok(())
}

// `matching_path` must return the NEWEST live variant when a stale one lingers
// live at a lower height (an old variant whose tombstone never landed). This is
// the `Op` enum case — `id` written earlier, `sum` later, both live — where the
// resolver must pick `sum`, not arbitrarily `id`.
#[tokio::test]
async fn test_matching_path_newest_of_multiple_live() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let cid = 123;

    let mut txs = Vec::new();
    for (i, height) in [800000u64, 800001].into_iter().enumerate() {
        insert_block(
            &conn,
            BlockRow::builder()
                .height(height)
                .hash(new_mock_block_hash(height as u32))
                .build(),
        )
        .await?;
        txs.push(
            insert_transaction(
                &conn,
                TransactionRow::builder()
                    .height(height)
                    .txid(format!("eeee{:060}", i))
                    .tx_index(0)
                    .confirmed_height(height)
                    .build(),
            )
            .await?,
        );
    }

    // Old variant `id` at H1, new variant `sum` at H2 — both live.
    for (tx, height, path) in [
        (txs[0], 800000u64, "c.op.id"),
        (txs[1], 800001, "c.op.sum.y"),
    ] {
        insert_contract_state(
            &conn,
            ContractStateRow::builder()
                .contract_id(cid)
                .tx_id(tx)
                .height(height)
                .path(cs_path_dotted(path))
                .value(vec![1])
                .build(),
        )
        .await?;
    }

    let found = matching_path(&conn, cid, &cs_path_dotted("c.op"), &cands(&["id", "sum"])).await?;
    assert_eq!(found, Some(1)); // "sum" is candidate index 1

    Ok(())
}

// The `Option` resolver asks only "does `<field>.none` exist?". A stale `none`
// lingering live at a lower height (from an earlier value) must be outranked by
// the newer `some` write, so the none-check finds nothing → the field reads as
// Some. (Regression: a per-path resolver would have surfaced the stale `none`.)
#[tokio::test]
async fn test_matching_path_stale_none_outranked_by_some() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let cid = 123;

    let mut txs = Vec::new();
    for (i, height) in [800000u64, 800001].into_iter().enumerate() {
        insert_block(
            &conn,
            BlockRow::builder()
                .height(height)
                .hash(new_mock_block_hash(height as u32))
                .build(),
        )
        .await?;
        txs.push(
            insert_transaction(
                &conn,
                TransactionRow::builder()
                    .height(height)
                    .txid(format!("ffff{:060}", i))
                    .tx_index(0)
                    .confirmed_height(height)
                    .build(),
            )
            .await?,
        );
    }

    // Stale `none` at H1, then a `some` value at H2 — both live.
    for (tx, height, path) in [
        (txs[0], 800000u64, "c.opt.none"),
        (txs[1], 800001, "c.opt.some"),
    ] {
        insert_contract_state(
            &conn,
            ContractStateRow::builder()
                .contract_id(cid)
                .tx_id(tx)
                .height(height)
                .path(cs_path_dotted(path))
                .value(vec![1])
                .build(),
        )
        .await?;
    }

    // The none-check (only `none` in the alternation) must NOT match the newer
    // `some`, so it returns None and the field resolves to Some.
    let found = matching_path(&conn, cid, &cs_path_dotted("c.opt"), &cands(&["none"])).await?;
    assert_eq!(found, None);

    Ok(())
}

// Regression: the newest live row under `base_path` can be `base_path` ITSELF — a
// value stored at the path with no variant segment after it. `matching_path` must
// report no match (Ok(None)), not a codec error from decoding the empty suffix.
#[tokio::test]
async fn test_matching_path_on_bare_base_row() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    let cid = 123;
    let height = 800000;
    insert_block(
        &conn,
        BlockRow::builder()
            .height(height)
            .hash(new_mock_block_hash(height as u32))
            .build(),
    )
    .await?;
    let tx = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(height)
            .txid(format!("eeee{:060}", 0))
            .tx_index(0)
            .confirmed_height(height)
            .build(),
    )
    .await?;

    // A value stored AT `c.opt` exactly — no variant child under it.
    insert_contract_state(
        &conn,
        ContractStateRow::builder()
            .contract_id(cid)
            .tx_id(tx)
            .height(height)
            .path(cs_path_dotted("c.opt"))
            .value(vec![1])
            .build(),
    )
    .await?;

    // No variant segment after base_path → no match, and crucially no error.
    let found = matching_path(
        &conn,
        cid,
        &cs_path_dotted("c.opt"),
        &cands(&["none", "some"]),
    )
    .await?;
    assert_eq!(found, None);

    Ok(())
}

// Fuzz the contract_state query layer: ARBITRARY guest path bytes (empty,
// malformed, all-0xFF, base-equal, random) must never panic any of exists / keys /
// matching / delete — the class behind the three boundary bugs (empty subtree
// bound, malformed parse, bare-base suffix). The host ALSO rejects malformed paths
// at ingress (`validate_path`); this guards the query layer directly so a future
// caller can't reintroduce a panic.
mod proptest_paths {
    use super::*;
    use proptest::prelude::*;

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(24))]
        #[test]
        fn query_layer_no_panic_on_arbitrary_path(
            path in proptest::collection::vec(any::<u8>(), 0..40),
        ) {
            let rt = tokio::runtime::Runtime::new().unwrap();
            rt.block_on(async {
                let (_reader, writer, _temp) = new_test_db().await.unwrap();
                let conn = writer.connection();
                let h = 700000u64;
                for height in [h, h + 1] {
                    insert_block(
                        &conn,
                        BlockRow::builder()
                            .height(height)
                            .hash(new_mock_block_hash(height as u32))
                            .build(),
                    )
                    .await
                    .unwrap();
                }
                let tx = insert_transaction(
                    &conn,
                    TransactionRow::builder()
                        .height(h)
                        .txid(format!("dddd{:060}", 0))
                        .tx_index(0)
                        .confirmed_height(h)
                        .build(),
                )
                .await
                .unwrap();
                for k in ["a", "b"] {
                    insert_contract_state(
                        &conn,
                        ContractStateRow::builder()
                            .contract_id(1)
                            .tx_id(tx)
                            .height(h)
                            .path(cs_path(&["m", k]))
                            .value(vec![1])
                            .build(),
                    )
                    .await
                    .unwrap();
                }
                let cid = 1;
                // None of these may panic on arbitrary `path` bytes.
                let _ = exists_contract_state(&conn, cid, &path).await;
                let _ = matching_path(&conn, cid, &path, &cands(&["none", "some"])).await;
                if let Ok(stream) =
                    path_prefix_filter_contract_state(&conn, cid, path.clone(), None, None).await
                {
                    let _ = stream.collect::<Vec<_>>().await;
                }
                let _ = delete_contract_state(&conn, h + 1, Some(tx), cid, &path).await;
            });
        }
    }
}

// Cross-call pagination via the `after` cursor: a caller resumes a keys scan
// strictly past the last full path it saw. Within a call the lazy stream is what
// bounds work (the guest stops iterating); across calls `after` is the resume
// point, so two cursor-resumed reads reconstruct the full scan with no overlap.
#[tokio::test]
async fn test_path_prefix_filter_after_cursor_resumes() -> Result<()> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    let h = 600000;
    insert_block(
        &conn,
        BlockRow::builder()
            .height(h)
            .hash(new_mock_block_hash(h as u32))
            .build(),
    )
    .await?;
    let tx = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(h)
            .txid(format!("cccc{:060}", 0))
            .tx_index(0)
            .confirmed_height(h)
            .build(),
    )
    .await?;
    let cid = 1;
    // Five single-row "members" under bucket `m` (the index-scan shape).
    for k in ["k1", "k2", "k3", "k4", "k5"] {
        insert_contract_state(
            &conn,
            ContractStateRow::builder()
                .contract_id(cid)
                .tx_id(tx)
                .height(h)
                .path(cs_path(&["m", k]))
                .value(vec![1])
                .build(),
        )
        .await?;
    }

    // Full scan, no cursor: every member in path order.
    let all: Vec<Vec<u8>> =
        path_prefix_filter_contract_state(&conn, cid, cs_path(&["m"]), None, None)
            .await?
            .try_collect()
            .await?;
    assert_eq!(
        all,
        vec![
            cs_path(&["k1"]),
            cs_path(&["k2"]),
            cs_path(&["k3"]),
            cs_path(&["k4"]),
            cs_path(&["k5"]),
        ]
    );

    // Resume after child `k2` (cursor = its child-node path `m/k2`): the remaining
    // members, no overlap with the first two.
    let rest: Vec<Vec<u8>> = path_prefix_filter_contract_state(
        &conn,
        cid,
        cs_path(&["m"]),
        Some(cs_path(&["m", "k2"])),
        None,
    )
    .await?
    .try_collect()
    .await?;
    assert_eq!(
        rest,
        vec![cs_path(&["k3"]), cs_path(&["k4"]), cs_path(&["k5"])]
    );

    Ok(())
}

// The `from_key` seek: a sorted-index range query's inclusive lower bound. Members
// are `(sort, pk)` tuple elements under a bucket; seeking to `sort_lower_bound(lo)`
// starts the scan at the first `sort >= lo` member host-side (a plain `>=` against
// `bucket ++ from_key`), so members below `lo` are never emitted — the pull-side
// `skip_while` the guest would otherwise pay per key is avoided.
#[tokio::test]
async fn test_path_prefix_filter_from_key_seeks_lower_bound() -> Result<()> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    let h = 600001;
    insert_block(
        &conn,
        BlockRow::builder()
            .height(h)
            .hash(new_mock_block_hash(h as u32))
            .build(),
    )
    .await?;
    let tx = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(h)
            .txid(format!("dddd{:060}", 0))
            .tx_index(0)
            .confirmed_height(h)
            .build(),
    )
    .await?;
    let cid = 1;
    let bucket = cs_path(&["m"]);
    // A sorted member: the child element is the `(sort_height, pk)` tuple; its full
    // row path is `bucket ++ that element`. Insert out of order.
    let member = |sort: u64, pk: &str| -> (Vec<u8>, Vec<u8>) {
        let elem = stdlib::tuple_from_elements(&[
            stdlib::KeyElement::encode(&sort).as_slice(),
            stdlib::KeyElement::encode(&pk.to_string()).as_slice(),
        ]);
        let mut path = bucket.clone();
        path.extend_from_slice(&elem);
        (path, elem)
    };
    let members = [member(30, "c"), member(10, "a"), member(20, "b")];
    for (path, _) in &members {
        insert_contract_state(
            &conn,
            ContractStateRow::builder()
                .contract_id(cid)
                .tx_id(tx)
                .height(h)
                .path(path.clone())
                .value(vec![1])
                .build(),
        )
        .await?;
    }
    // Elements in ascending sort order (a=10, b=20, c=30), which is the scan order.
    let (elem_a, elem_b, elem_c) = (
        members[1].1.clone(),
        members[2].1.clone(),
        members[0].1.clone(),
    );

    let scan_from = async |lo: u64| -> Result<Vec<Vec<u8>>> {
        Ok(path_prefix_filter_contract_state(
            &conn,
            cid,
            bucket.clone(),
            None,
            Some(stdlib::sort_lower_bound(&lo)),
        )
        .await?
        .try_collect()
        .await?)
    };

    // Seek to an exact member (>= 20): skips a, yields b, c.
    assert_eq!(scan_from(20).await?, vec![elem_b.clone(), elem_c.clone()]);
    // Seek between members (>= 25): only c (30) qualifies.
    assert_eq!(scan_from(25).await?, vec![elem_c.clone()]);
    // Seek below everything (>= 5): the whole bucket, in order.
    assert_eq!(
        scan_from(5).await?,
        vec![elem_a.clone(), elem_b.clone(), elem_c.clone()]
    );
    // Seek above everything (>= 40): empty.
    assert!(scan_from(40).await?.is_empty());

    // An EMPTY `from_key` (untrusted-boundary edge — the real guest never sends one)
    // means "no lower bound", NOT `>= path`: it must return the full bucket child-only
    // and NOT trap on the row at the bucket prefix. Same result as `None`.
    let empty_seek: Vec<Vec<u8>> =
        path_prefix_filter_contract_state(&conn, cid, bucket.clone(), None, Some(Vec::new()))
            .await?
            .try_collect()
            .await?;
    assert_eq!(empty_seek, vec![elem_a, elem_b, elem_c]);
    Ok(())
}

// Regression: a cursor resume must skip the last child's ENTIRE subtree, not just
// the bare child-node path. Here each child owns several deeper rows (a struct/map
// value), so resuming with `after = m/a` must NOT re-read `m/a/*` and re-emit `a`.
// The old `cs.path > after` bound did exactly that (`m/a` sorts before `m/a/f1`);
// `cs.path >= strinc(after)` fixes it.
#[tokio::test]
async fn test_after_cursor_skips_whole_child_subtree() -> Result<()> {
    let (_reader, writer, _temp) = new_test_db().await?;
    let conn = writer.connection();
    let h = 600000;
    insert_block(
        &conn,
        BlockRow::builder()
            .height(h)
            .hash(new_mock_block_hash(h as u32))
            .build(),
    )
    .await?;
    let tx = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(h)
            .txid(format!("dddd{:060}", 0))
            .tx_index(0)
            .confirmed_height(h)
            .build(),
    )
    .await?;
    let cid = 1;
    // Map `m` of multi-field struct values: each child owns several deeper rows.
    for (child, field) in [
        ("a", "f1"),
        ("a", "f2"),
        ("b", "f1"),
        ("b", "f2"),
        ("c", "f1"),
    ] {
        insert_contract_state(
            &conn,
            ContractStateRow::builder()
                .contract_id(cid)
                .tx_id(tx)
                .height(h)
                .path(cs_path(&["m", child, field]))
                .value(vec![1])
                .build(),
        )
        .await?;
    }

    // No cursor: the three distinct child keys, deduped across their subtrees.
    let all: Vec<Vec<u8>> =
        path_prefix_filter_contract_state(&conn, cid, cs_path(&["m"]), None, None)
            .await?
            .try_collect()
            .await?;
    assert_eq!(all, vec![cs_path(&["a"]), cs_path(&["b"]), cs_path(&["c"])]);

    // Resume after child `a` (cursor = its child-node path `m/a`): must skip ALL of
    // a's deeper rows and not re-emit `a`.
    let rest: Vec<Vec<u8>> = path_prefix_filter_contract_state(
        &conn,
        cid,
        cs_path(&["m"]),
        Some(cs_path(&["m", "a"])),
        None,
    )
    .await?
    .try_collect()
    .await?;
    assert_eq!(rest, vec![cs_path(&["b"]), cs_path(&["c"])]);

    Ok(())
}

#[tokio::test]
async fn test_contract_result_operations() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    // Insert a block first
    let height = 800000;
    let hash = "000000000000000000015d76e1b13f62d0edc4593ed326528c37b5af3c3fba04".parse()?;
    let block = BlockRow::builder().height(height).hash(hash).build();
    insert_block(&conn, block).await?;

    let contract_id = insert_contract(
        &conn,
        ContractRow::builder()
            .name("token".to_string())
            .height(height)
            .tx_index(1)
            .bytes(vec![])
            .build(),
    )
    .await?;

    let txid = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";
    let tx1 = TransactionRow::builder()
        .height(height)
        .txid(txid.to_string())
        .tx_index(0)
        .confirmed_height(height)
        .build();

    let tx_id = insert_transaction(&conn, tx1.clone()).await?;

    let signer_id = ensure_identity(
        &conn,
        "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233",
        height,
    )
    .await?
    .signer_id();
    let result = ContractResultRow::builder()
        .id(1)
        .tx_id(tx_id)
        .input_index(0)
        .op_index(0)
        .height(height)
        .contract_id(contract_id)
        .value("".to_string())
        .gas(100)
        .signer_id(signer_id)
        .build();

    insert_contract_result(&conn, result.clone()).await?;

    let row = get_contract_result(
        &conn,
        result.tx_id,
        result.input_index,
        result.op_index,
        result.result_index,
    )
    .await?;
    assert_eq!(Some(result.clone()), row);

    let row = get_op_result(&conn, &OpResultId::builder().txid(txid.to_string()).build()).await?;
    assert!(row.is_some());
    assert_eq!(result.id, row.unwrap().id);

    Ok(())
}

#[tokio::test]
async fn test_insert_and_select_batch() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    let height: u64 = 100;
    let hash = new_mock_block_hash(height as u32);
    insert_block(&conn, BlockRow::builder().height(height).hash(hash).build()).await?;

    insert_batch(&conn, 1, height, &hash.to_string(), b"cert1", false).await?;

    // Insert two batch transactions
    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(height)
            .batch_height(1)
            .txid("aa".repeat(32))
            .build(),
    )
    .await?;
    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(height)
            .batch_height(1)
            .txid("bb".repeat(32))
            .build(),
    )
    .await?;

    let result = select_batch(&conn, 1).await?;
    assert!(result.is_some());
    let batch = result.unwrap();
    assert_eq!(batch.anchor_height, height);
    assert_eq!(batch.anchor_hash, hash.to_string());
    assert_eq!(batch.certificate, b"cert1");
    assert_eq!(batch.txids.len(), 2);
    assert_eq!(batch.txids[0], "aa".repeat(32));
    assert_eq!(batch.txids[1], "bb".repeat(32));

    // Non-existent batch
    assert!(select_batch(&conn, 999).await?.is_none());

    Ok(())
}

#[tokio::test]
async fn test_select_min_batch_height() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    assert!(select_min_batch_height(&conn).await?.is_none());

    let height: u64 = 100;
    let hash = new_mock_block_hash(height as u32);
    insert_block(&conn, BlockRow::builder().height(height).hash(hash).build()).await?;

    insert_batch(&conn, 5, height, &hash.to_string(), b"cert5", false).await?;
    insert_batch(&conn, 3, height, &hash.to_string(), b"cert3", false).await?;
    insert_batch(&conn, 8, height, &hash.to_string(), b"cert8", false).await?;

    assert_eq!(select_min_batch_height(&conn).await?, Some(3));

    Ok(())
}

#[tokio::test]
async fn test_select_batches_from_anchor() -> Result<()> {
    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    // Create blocks at heights 100 and 200
    for h in [100u64, 200] {
        let hash = new_mock_block_hash(h as u32);
        insert_block(&conn, BlockRow::builder().height(h).hash(hash).build()).await?;
    }

    let hash100 = new_mock_block_hash(100);
    let hash200 = new_mock_block_hash(200);

    // Batch at anchor 100
    insert_batch(&conn, 1, 100, &hash100.to_string(), b"cert1", false).await?;
    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(100)
            .batch_height(1)
            .txid("aa".repeat(32))
            .build(),
    )
    .await?;

    // Batch at anchor 200
    insert_batch(&conn, 2, 200, &hash200.to_string(), b"cert2", false).await?;
    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(200)
            .batch_height(2)
            .txid("bb".repeat(32))
            .build(),
    )
    .await?;
    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(200)
            .batch_height(2)
            .txid("cc".repeat(32))
            .build(),
    )
    .await?;

    // Query from anchor 200 — should only return the second batch
    let results = select_batches_from_anchor(&conn, 200).await?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].consensus_height, 2);
    assert_eq!(results[0].anchor_height, 200);
    assert_eq!(results[0].txids.len(), 2);

    // Query from anchor 100 — should return both
    let results = select_batches_from_anchor(&conn, 100).await?;
    assert_eq!(results.len(), 2);
    assert_eq!(results[0].consensus_height, 1);
    assert_eq!(results[0].txids.len(), 1);
    assert_eq!(results[1].consensus_height, 2);
    assert_eq!(results[1].txids.len(), 2);

    Ok(())
}

#[tokio::test]
async fn test_select_existing_txids() -> Result<()> {
    use crate::database::queries::select_existing_txids;

    let (_reader, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    // Create a block
    insert_block(
        &conn,
        BlockRow::builder()
            .height(100)
            .hash(new_mock_block_hash(100))
            .build(),
    )
    .await?;

    // Insert some transactions
    let txid_a = "aa".repeat(32);
    let txid_b = "bb".repeat(32);
    let txid_c = "cc".repeat(32);

    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(100)
            .confirmed_height(100)
            .tx_index(0)
            .txid(txid_a.clone())
            .build(),
    )
    .await?;
    insert_batch(
        &conn,
        1,
        100,
        &new_mock_block_hash(100).to_string(),
        b"cert",
        false,
    )
    .await?;
    insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(100)
            .batch_height(1)
            .txid(txid_b.clone())
            .build(),
    )
    .await?;

    // Query with mix of existing and non-existing txids
    let result =
        select_existing_txids(&conn, &[txid_a.clone(), txid_b.clone(), txid_c.clone()]).await?;

    assert!(result.contains(&txid_a), "confirmed tx should be found");
    assert!(result.contains(&txid_b), "batched tx should be found");
    assert!(!result.contains(&txid_c), "unknown tx should not be found");
    assert_eq!(result.len(), 2);

    // Empty input returns empty result
    let empty = select_existing_txids(&conn, &[]).await?;
    assert!(empty.is_empty());

    Ok(())
}

#[tokio::test]
async fn test_get_blocks_query() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    insert_block(
        &conn,
        BlockRow::builder()
            .height(100)
            .hash(new_mock_block_hash(100))
            .build(),
    )
    .await?;

    insert_block(
        &conn,
        BlockRow::builder()
            .height(101)
            .hash(new_mock_block_hash(101))
            .build(),
    )
    .await?;

    insert_block(
        &conn,
        BlockRow::builder()
            .height(102)
            .hash(new_mock_block_hash(102))
            .build(),
    )
    .await?;

    let (blocks, meta) =
        get_blocks_paginated(&conn, BlockQuery::builder().limit(1).build()).await?;

    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].height, 102);
    assert!(meta.has_more);
    assert_eq!(meta.next_cursor, Some(blocks[0].height));
    assert_eq!(meta.total_count, 3);

    let (blocks, meta) = get_blocks_paginated(
        &conn,
        BlockQuery::builder()
            .maybe_cursor(meta.next_cursor)
            .limit(1)
            .build(),
    )
    .await?;

    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].height, 101);
    assert!(meta.has_more);
    assert_eq!(meta.next_cursor, Some(blocks[0].height));

    let (blocks, meta) = get_blocks_paginated(
        &conn,
        BlockQuery::builder()
            .maybe_cursor(meta.next_cursor)
            .limit(1)
            .build(),
    )
    .await?;

    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].height, 100);
    assert!(!meta.has_more);
    assert_eq!(meta.next_cursor, Some(blocks[0].height));

    Ok(())
}

#[tokio::test]
async fn test_get_blocks_query_relevant() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    insert_block(
        &conn,
        BlockRow::builder()
            .height(100)
            .hash(new_mock_block_hash(100))
            .relevant(true)
            .build(),
    )
    .await?;

    insert_block(
        &conn,
        BlockRow::builder()
            .height(101)
            .hash(new_mock_block_hash(101))
            .build(),
    )
    .await?;

    let (blocks, meta) =
        get_blocks_paginated(&conn, BlockQuery::builder().relevant(true).build()).await?;

    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].height, 100);
    assert!(!meta.has_more);
    assert_eq!(meta.next_cursor, Some(blocks[0].height));
    assert_eq!(meta.total_count, 1);

    let (blocks, meta) =
        get_blocks_paginated(&conn, BlockQuery::builder().relevant(false).build()).await?;

    assert_eq!(blocks.len(), 1);
    assert_eq!(blocks[0].height, 101);
    assert!(!meta.has_more);
    assert_eq!(meta.next_cursor, Some(blocks[0].height));
    assert_eq!(meta.total_count, 1);

    Ok(())
}

#[tokio::test]
async fn test_get_results_query() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    insert_block(
        &conn,
        BlockRow::builder()
            .height(1)
            .hash(new_mock_block_hash(1))
            .build(),
    )
    .await?;

    let signer_id = ensure_identity(
        &conn,
        "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233",
        1,
    )
    .await?
    .signer_id();

    let contract_1_id = insert_contract(
        &conn,
        ContractRow::builder()
            .name("token".to_string())
            .height(1)
            .tx_index(1)
            .bytes(vec![])
            .build(),
    )
    .await?;

    let contract_2_id = insert_contract(
        &conn,
        ContractRow::builder()
            .name("storage".to_string())
            .height(1)
            .tx_index(2)
            .bytes(vec![])
            .build(),
    )
    .await?;

    let tx_id_1_3 = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(1)
            .txid(new_mock_transaction(1003).txid.to_string())
            .tx_index(3)
            .build(),
    )
    .await?;

    let tx_id_1_4 = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(1)
            .txid(new_mock_transaction(1004).txid.to_string())
            .tx_index(4)
            .build(),
    )
    .await?;

    insert_contract_result(
        &conn,
        ContractResultRow::builder()
            .contract_id(contract_1_id)
            .height(1)
            .tx_id(tx_id_1_3)
            .input_index(0)
            .op_index(0)
            .gas(100)
            .signer_id(signer_id)
            .build(),
    )
    .await?;

    insert_contract_result(
        &conn,
        ContractResultRow::builder()
            .contract_id(contract_2_id)
            .func("foo".to_string())
            .height(1)
            .tx_id(tx_id_1_4)
            .input_index(0)
            .op_index(0)
            .gas(100)
            .signer_id(signer_id)
            .build(),
    )
    .await?;

    insert_block(
        &conn,
        BlockRow::builder()
            .height(2)
            .hash(new_mock_block_hash(2))
            .build(),
    )
    .await?;

    let tx_id_2_1 = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(2)
            .txid(new_mock_transaction(2001).txid.to_string())
            .tx_index(1)
            .build(),
    )
    .await?;

    let tx_id_2_2 = insert_transaction(
        &conn,
        TransactionRow::builder()
            .height(2)
            .txid(new_mock_transaction(2002).txid.to_string())
            .tx_index(2)
            .build(),
    )
    .await?;

    insert_contract_result(
        &conn,
        ContractResultRow::builder()
            .contract_id(contract_1_id)
            .height(2)
            .tx_id(tx_id_2_1)
            .input_index(0)
            .op_index(0)
            .gas(100)
            .signer_id(signer_id)
            .build(),
    )
    .await?;

    insert_contract_result(
        &conn,
        ContractResultRow::builder()
            .contract_id(contract_2_id)
            .height(2)
            .tx_id(tx_id_2_2)
            .input_index(0)
            .op_index(0)
            .gas(100)
            .signer_id(signer_id)
            .build(),
    )
    .await?;

    // contract result with NULL tx_id (no associated transaction)
    insert_contract_result(
        &conn,
        ContractResultRow::builder()
            .contract_id(contract_2_id)
            .height(2)
            .result_index(1)
            .gas(100)
            .signer_id(signer_id)
            .build(),
    )
    .await?;

    // Second signer with a single result at height 1 — exercises the
    // signer_id filter narrowing without affecting the height-filtered
    // assertion below (which counts only height=2 rows).
    let signer_id_2 = ensure_identity(
        &conn,
        "ffeeddcc99887766ffeeddcc99887766ffeeddcc99887766ffeeddcc99887766",
        1,
    )
    .await?
    .signer_id();
    insert_contract_result(
        &conn,
        ContractResultRow::builder()
            .contract_id(contract_1_id)
            .height(1)
            .tx_id(tx_id_1_3)
            .input_index(0)
            .op_index(0)
            .result_index(1)
            .gas(100)
            .signer_id(signer_id_2)
            .build(),
    )
    .await?;

    let (_, meta) = get_results_paginated(
        &conn,
        ResultQuery::builder()
            .order(OrderDirection::Asc)
            .limit(1)
            .build(),
    )
    .await?;
    assert_eq!(meta.total_count, 6);

    // NULL tx_id result is included with txid: None
    let (results, _) = get_results_paginated(
        &conn,
        ResultQuery::builder()
            .height(2)
            .order(OrderDirection::Asc)
            .limit(10)
            .build(),
    )
    .await?;
    assert_eq!(results.len(), 3);

    // contract filtering
    let (results, meta) = get_results_paginated(
        &conn,
        ResultQuery::builder()
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 1,
                tx_index: 1,
            })
            .order(OrderDirection::Asc)
            .limit(1)
            .build(),
    )
    .await?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].contract_name, "token");
    assert_eq!(results[0].contract_height, 1);
    assert_eq!(results[0].contract_tx_index, 1);
    // signer_id_2 also has a result on the "token" contract at height=1.
    assert_eq!(meta.total_count, 3);

    // func filtering
    let (results, meta) = get_results_paginated(
        &conn,
        ResultQuery::builder()
            .contract(ContractAddress {
                name: "storage".to_string(),
                height: 1,
                tx_index: 2,
            })
            .func("foo".to_string())
            .order(OrderDirection::Asc)
            .limit(1)
            .build(),
    )
    .await?;
    assert_eq!(results.len(), 1);
    assert_eq!(results[0].func, "foo".to_string());
    assert_eq!(results[0].contract_name, "storage");
    assert_eq!(results[0].contract_height, 1);
    assert_eq!(results[0].contract_tx_index, 2);
    assert_eq!(meta.total_count, 1);
    assert_eq!(meta.next_cursor, Some(results[0].id));

    // height filtering
    let (results, meta) = get_results_paginated(
        &conn,
        ResultQuery::builder()
            .height(2)
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 1,
                tx_index: 1,
            })
            .order(OrderDirection::Asc)
            .limit(1)
            .build(),
    )
    .await?;
    assert_eq!(results[0].height, 2);
    assert_eq!(meta.total_count, 1);

    // start height
    let (results, meta) = get_results_paginated(
        &conn,
        ResultQuery::builder()
            .start_height(2)
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 1,
                tx_index: 1,
            })
            .order(OrderDirection::Asc)
            .limit(1)
            .build(),
    )
    .await?;
    assert_eq!(results[0].height, 2);
    assert_eq!(meta.total_count, 1);
    assert!(!meta.has_more);

    // signer_id filter — first signer has 5 results, second has 1.
    let (results, meta) = get_results_paginated(
        &conn,
        ResultQuery::builder()
            .signer_id(signer_id)
            .order(OrderDirection::Asc)
            .limit(10)
            .build(),
    )
    .await?;
    assert_eq!(results.len(), 5);
    assert_eq!(meta.total_count, 5);
    assert!(results.iter().all(|r| r.signer_id == signer_id));

    let (results, meta) = get_results_paginated(
        &conn,
        ResultQuery::builder()
            .signer_id(signer_id_2)
            .order(OrderDirection::Asc)
            .limit(10)
            .build(),
    )
    .await?;
    assert_eq!(results.len(), 1);
    assert_eq!(meta.total_count, 1);
    assert_eq!(results[0].signer_id, signer_id_2);

    Ok(())
}

#[tokio::test]
async fn test_transaction_query_contract_address() -> Result<()> {
    let x = serde_json::from_str::<TransactionQuery>(r#"{"contract": "token_1_0"}"#).unwrap();
    assert_eq!(
        x,
        TransactionQuery::builder()
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 1,
                tx_index: 0
            })
            .build()
    );
    Ok(())
}

#[tokio::test]
async fn test_basic_pagination_no_filters() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    // Test first page with limit 3
    let (transactions, meta) =
        get_transactions_paginated(&conn, TransactionQuery::builder().limit(3).build()).await?;

    assert_eq!(transactions.len(), 3);
    assert!(meta.has_more);
    assert_eq!(meta.total_count, 10); // 5 + 3 + 2 = 10 total
    assert!(meta.next_offset.is_some());
    assert_eq!(meta.next_offset, Some(3));
    assert!(meta.next_cursor.is_some());
    let cursor = meta.next_cursor.unwrap();
    assert_eq!(cursor, 8);

    // Verify ordering (DESC by height, then DESC by tx_index)
    assert_eq!(transactions[0].height, 800002);
    assert_eq!(transactions[0].tx_index, Some(1));
    assert_eq!(transactions[1].height, 800002);
    assert_eq!(transactions[1].tx_index, Some(0));
    assert_eq!(transactions[2].height, 800001);
    assert_eq!(transactions[2].tx_index, Some(2));

    Ok(())
}

#[tokio::test]
async fn test_offset_pagination() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;
    // First page
    let (page1, meta1) =
        get_transactions_paginated(&conn, TransactionQuery::builder().limit(3).build()).await?;
    assert_eq!(page1.len(), 3);
    assert_eq!(meta1.next_offset, Some(3));
    assert!(meta1.has_more);
    assert!(meta1.next_cursor.is_some());

    // Second page using offset
    let (page2, meta2) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder().offset(3).limit(3).build(),
    )
    .await?;
    assert_eq!(page2.len(), 3);
    assert_eq!(meta2.next_offset, Some(6));
    assert!(meta2.has_more);
    assert!(meta2.next_cursor.is_none()); // offset pagination

    // Third page
    let (page3, meta3) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder().offset(6).limit(3).build(),
    )
    .await?;
    assert_eq!(page3.len(), 3);
    assert_eq!(meta3.next_offset, Some(9));
    assert!(meta3.has_more);

    // Fourth page (last page)
    let (page4, meta4) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder().offset(9).limit(3).build(),
    )
    .await?;
    assert_eq!(page4.len(), 1); // Only 1 transaction left
    assert_eq!(meta4.next_offset, Some(10)); // For polling - points past last item
    assert!(!meta4.has_more);

    // Verify no overlap between pages
    let all_txids: Vec<String> = [&page1, &page2, &page3, &page4]
        .iter()
        .flat_map(|page| page.iter().map(|tx| tx.txid.clone()))
        .collect();
    let unique_txids: std::collections::HashSet<String> = all_txids.iter().cloned().collect();
    assert_eq!(all_txids.len(), unique_txids.len()); // No duplicates

    Ok(())
}

#[tokio::test]
async fn test_cursor_pagination() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    // First page with cursor pagination
    let (page1, meta1) =
        get_transactions_paginated(&conn, TransactionQuery::builder().limit(3).build()).await?;

    assert_eq!(page1.len(), 3);
    assert!(meta1.has_more);
    assert!(meta1.next_cursor.is_some());
    assert!(meta1.next_offset.is_some());

    let cursor = meta1.next_cursor.unwrap();
    assert_eq!(cursor, 8);

    let (page2, meta2) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .maybe_cursor(meta1.next_cursor)
            .limit(3)
            .build(),
    )
    .await?;

    assert_eq!(page2.len(), 3);
    assert!(meta2.has_more);
    assert!(meta2.next_cursor.is_some());
    assert!(meta2.next_offset.is_none());

    let cursor = meta2.next_cursor.unwrap();
    assert_eq!(cursor, 5);

    let (page3, meta3) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .maybe_cursor(meta2.next_cursor)
            .limit(3)
            .build(),
    )
    .await?;

    assert_eq!(page3.len(), 3);
    assert!(meta3.has_more);
    assert!(meta3.next_cursor.is_some());

    let cursor = meta3.next_cursor.unwrap();
    assert_eq!(cursor, 2);

    let (page4, meta4) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .maybe_cursor(meta3.next_cursor)
            .limit(3)
            .build(),
    )
    .await?;

    assert_eq!(page4.len(), 1);
    assert!(!meta4.has_more);
    assert_eq!(meta4.next_cursor, Some(page4[0].id));

    // Verify no overlap
    let all_txids: Vec<String> = [&page1, &page2, &page3, &page4]
        .iter()
        .flat_map(|page| page.iter().map(|tx| tx.txid.clone()))
        .collect();
    let unique_txids: std::collections::HashSet<String> = all_txids.iter().cloned().collect();
    assert_eq!(all_txids.len(), unique_txids.len());

    Ok(())
}

#[tokio::test]
async fn test_height_filter() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;
    // Filter by height 800001 (should have 3 transactions)
    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder().height(800001).limit(10).build(),
    )
    .await?;

    assert_eq!(transactions.len(), 3);
    assert_eq!(meta.total_count, 3);
    assert!(!meta.has_more);
    assert_eq!(meta.next_offset, Some(3));

    // Verify all transactions are from height 800001
    for tx in &transactions {
        assert_eq!(tx.height, 800001);
    }

    // Verify ordering within height (DESC by tx_index)
    assert_eq!(transactions[0].tx_index, Some(2));
    assert_eq!(transactions[1].tx_index, Some(1));
    assert_eq!(transactions[2].tx_index, Some(0));

    Ok(())
}

#[tokio::test]
async fn test_height_filter_with_pagination() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    // Filter by height 800000 with limit 2 (should have 5 total, return 2)
    let (page1, meta1) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder().height(800000).limit(2).build(),
    )
    .await?;

    assert_eq!(page1.len(), 2);
    assert_eq!(meta1.total_count, 5);
    assert!(meta1.has_more);
    assert_eq!(meta1.next_offset, Some(2));

    // Get second page
    let (page2, meta2) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .height(800000)
            .offset(2)
            .limit(2)
            .build(),
    )
    .await?;

    assert_eq!(page2.len(), 2);
    assert!(meta2.has_more);
    assert_eq!(meta2.next_offset, Some(4));

    // Get final page
    let (page3, meta3) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .height(800000)
            .offset(4)
            .limit(2)
            .build(),
    )
    .await?;

    assert_eq!(page3.len(), 1); // Last transaction
    assert!(!meta3.has_more);
    assert_eq!(meta3.next_offset, Some(5));

    Ok(())
}

#[tokio::test]
async fn test_cursor_and_offset_conflict() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    // When both cursor and offset are provided, cursor takes precedence
    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .cursor(9)
            .offset(5)
            .limit(3)
            .build(),
    )
    .await?;

    // Should use cursor pagination (ignore offset)
    assert!(meta.next_cursor.is_none());
    assert!(meta.next_offset.is_none());

    // Should return transactions with (height, tx_index) < (800001, 1)
    for tx in &transactions {
        assert!(tx.height == 800001);
    }

    Ok(())
}

#[tokio::test]
async fn test_empty_result_set() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    // Query for non-existent height
    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder().height(999999).limit(10).build(),
    )
    .await?;

    assert_eq!(transactions.len(), 0);
    assert_eq!(meta.total_count, 0);
    assert!(!meta.has_more);
    assert_eq!(meta.next_offset, Some(0));
    assert!(meta.next_cursor.is_none());

    Ok(())
}

#[tokio::test]
async fn test_large_limit() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    // Request more than available
    let (transactions, meta) =
        get_transactions_paginated(&conn, TransactionQuery::builder().limit(100).build()).await?;

    assert_eq!(transactions.len(), 10); // All available transactions
    assert!(!meta.has_more);
    assert_eq!(meta.next_offset, Some(10));
    assert_eq!(meta.total_count, 10);

    Ok(())
}

#[tokio::test]
async fn test_zero_limit() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    let (transactions, meta) =
        get_transactions_paginated(&conn, TransactionQuery::builder().limit(0).build()).await?;

    assert_eq!(transactions.len(), 0);
    assert!(meta.has_more); // There are transactions available
    assert_eq!(meta.next_offset, Some(0)); // Next offset should be 0
    assert_eq!(meta.total_count, 10);

    Ok(())
}

#[tokio::test]
async fn test_cursor_boundary_conditions() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    // Cursor pointing to the very first transaction
    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder().cursor(10).limit(10).build(),
    )
    .await?;

    assert_eq!(transactions.len(), 9);
    assert!(!meta.has_more);

    // Cursor pointing beyond all transactions
    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder().cursor(11).limit(10).build(),
    )
    .await?;

    assert_eq!(transactions.len(), 10);
    assert!(!meta.has_more);

    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder().cursor(0).limit(10).build(),
    )
    .await?;

    assert_eq!(transactions.len(), 0);
    assert!(!meta.has_more);

    Ok(())
}

#[tokio::test]
async fn test_cursor_contract_address_querying() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 800000,
                tx_index: 1,
            })
            .limit(1)
            .build(),
    )
    .await?;

    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].height, 800002);
    assert_eq!(transactions[0].tx_index, Some(0));
    assert!(meta.has_more);
    assert_eq!(meta.next_cursor, Some(transactions[0].id));
    assert_eq!(meta.total_count, 3);

    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .maybe_cursor(meta.next_cursor)
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 800000,
                tx_index: 1,
            })
            .limit(1)
            .build(),
    )
    .await?;

    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].height, 800001);
    assert_eq!(transactions[0].tx_index, Some(1));
    assert!(meta.has_more);
    assert_eq!(meta.next_cursor, Some(transactions[0].id));

    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .maybe_cursor(meta.next_cursor)
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 800000,
                tx_index: 1,
            })
            .limit(1)
            .build(),
    )
    .await?;

    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].height, 800000);
    assert_eq!(transactions[0].tx_index, Some(0));
    assert!(!meta.has_more);
    assert_eq!(meta.next_cursor, Some(transactions[0].id));

    Ok(())
}

#[tokio::test]
async fn test_cursor_contract_address_querying_asc() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_test_data(&conn).await?;

    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 800000,
                tx_index: 1,
            })
            .limit(1)
            .order(OrderDirection::Asc)
            .build(),
    )
    .await?;

    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].height, 800000);
    assert_eq!(transactions[0].tx_index, Some(0));
    assert!(meta.has_more);
    assert_eq!(meta.next_cursor, Some(transactions[0].id));
    assert_eq!(meta.total_count, 3);

    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .maybe_cursor(meta.next_cursor)
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 800000,
                tx_index: 1,
            })
            .limit(1)
            .order(OrderDirection::Asc)
            .build(),
    )
    .await?;

    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].height, 800001);
    assert_eq!(transactions[0].tx_index, Some(1));
    assert!(meta.has_more);
    assert_eq!(meta.next_cursor, Some(transactions[0].id));

    let (transactions, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .maybe_cursor(meta.next_cursor)
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 800000,
                tx_index: 1,
            })
            .limit(1)
            .order(OrderDirection::Asc)
            .build(),
    )
    .await?;

    assert_eq!(transactions.len(), 1);
    assert_eq!(transactions[0].height, 800002);
    assert_eq!(transactions[0].tx_index, Some(0));
    assert!(!meta.has_more);
    assert_eq!(meta.next_cursor, Some(transactions[0].id));

    Ok(())
}

#[tokio::test]
async fn test_transaction_signer_id_querying() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();

    // Self-contained fixture rather than setup_test_data — keeps the
    // signer_id assertions independent of changes to the shared bed.
    insert_block(
        &conn,
        BlockRow::builder()
            .height(1)
            .hash(new_mock_block_hash(1))
            .build(),
    )
    .await?;

    let signer_a = ensure_identity(
        &conn,
        "1111111111111111111111111111111111111111111111111111111111111111",
        1,
    )
    .await?
    .signer_id();
    let signer_b = ensure_identity(
        &conn,
        "2222222222222222222222222222222222222222222222222222222222222222",
        1,
    )
    .await?
    .signer_id();

    let token_id = insert_contract(
        &conn,
        ContractRow::builder()
            .name("token".to_string())
            .height(1)
            .tx_index(0)
            .bytes(vec![])
            .build(),
    )
    .await?;

    // Insert 5 txs and capture their ids.
    let mut tx_ids = Vec::new();
    for i in 0u32..5 {
        let id = insert_transaction(
            &conn,
            TransactionRow::builder()
                .height(1)
                .txid(new_mock_transaction(i + 1).txid.to_string())
                .tx_index(i)
                .build(),
        )
        .await?;
        tx_ids.push(id);
    }

    // Result distribution:
    // tx 0: signer_a, 1 result
    // tx 1: signer_a, 2 results (exercises DISTINCT in the JOIN)
    // tx 2: signer_b, 1 result
    // tx 3: signer_a, 1 result + a contract_state row on `token`
    //       (covers signer_id + contract combined — two joins)
    // tx 4: no results (control — must not appear in any signer query)
    let insert_result = async |tx_id: u64, signer_id: u64, result_index: u32| {
        insert_contract_result(
            &conn,
            ContractResultRow::builder()
                .contract_id(token_id)
                .height(1)
                .tx_id(tx_id)
                .input_index(0)
                .op_index(0)
                .result_index(result_index)
                .gas(100)
                .signer_id(signer_id)
                .build(),
        )
        .await
    };
    insert_result(tx_ids[0], signer_a, 0).await?;
    insert_result(tx_ids[1], signer_a, 0).await?;
    insert_result(tx_ids[1], signer_a, 1).await?;
    insert_result(tx_ids[2], signer_b, 0).await?;
    insert_result(tx_ids[3], signer_a, 0).await?;
    insert_contract_state(
        &conn,
        ContractStateRow::builder()
            .contract_id(token_id)
            .tx_id(tx_ids[3])
            .height(1)
            .path(cs_path_dotted("foo"))
            .build(),
    )
    .await?;

    // 1) signer filter narrows correctly. signer_a → 3 distinct txs
    //    (tx 0, 1, 3). DISTINCT must collapse tx 1's two results.
    let (txs, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .signer_id(signer_a)
            .order(OrderDirection::Asc)
            .limit(10)
            .build(),
    )
    .await?;
    assert_eq!(txs.len(), 3);
    assert_eq!(meta.total_count, 3);
    let ids: Vec<u64> = txs.iter().map(|t| t.id).collect();
    assert_eq!(ids, vec![tx_ids[0], tx_ids[1], tx_ids[3]]);

    // 2) signer_b → 1 tx
    let (txs, _) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .signer_id(signer_b)
            .order(OrderDirection::Asc)
            .limit(10)
            .build(),
    )
    .await?;
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0].id, tx_ids[2]);

    // 3) signer_id + cursor pagination still works.
    let (txs, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .signer_id(signer_a)
            .order(OrderDirection::Asc)
            .limit(2)
            .build(),
    )
    .await?;
    assert_eq!(txs.len(), 2);
    assert!(meta.has_more);
    assert_eq!(meta.next_cursor, Some(txs[1].id));
    let (txs, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .signer_id(signer_a)
            .maybe_cursor(meta.next_cursor)
            .order(OrderDirection::Asc)
            .limit(2)
            .build(),
    )
    .await?;
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0].id, tx_ids[3]);
    assert!(!meta.has_more);

    // 4) signer_id + height combined.
    let (txs, _) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .signer_id(signer_a)
            .height(1)
            .limit(10)
            .build(),
    )
    .await?;
    assert_eq!(txs.len(), 3);

    // 5) signer_id + contract combined — two joins (contract_results +
    //    contract_state). Only tx 3 has a state row on `token`.
    let (txs, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .signer_id(signer_a)
            .contract(ContractAddress {
                name: "token".to_string(),
                height: 1,
                tx_index: 0,
            })
            .order(OrderDirection::Asc)
            .limit(10)
            .build(),
    )
    .await?;
    assert_eq!(txs.len(), 1);
    assert_eq!(txs[0].id, tx_ids[3]);
    assert_eq!(meta.total_count, 1);

    // 6) Empty result set — bogus signer_id.
    let (txs, meta) = get_transactions_paginated(
        &conn,
        TransactionQuery::builder()
            .signer_id(9999)
            .limit(10)
            .build(),
    )
    .await?;
    assert!(txs.is_empty());
    assert_eq!(meta.total_count, 0);
    assert!(!meta.has_more);

    Ok(())
}

async fn setup_block(conn: &Connection, height: u64) -> Result<()> {
    insert_block(
        conn,
        BlockRow {
            height,
            hash: new_mock_block_hash(height as u32),
            relevant: true,
        },
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn test_ensure_identity_creates_new() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_block(&conn, 1).await?;

    let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
    let identity = ensure_identity(&conn, pubkey, 1).await?;
    assert!(identity.signer_id() > 0);
    assert_eq!(identity.x_only_pubkey(&conn).await?, pubkey);

    Ok(())
}

#[tokio::test]
async fn test_ensure_identity_returns_existing() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_block(&conn, 1).await?;
    setup_block(&conn, 2).await?;

    let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
    let id1 = ensure_identity(&conn, pubkey, 1).await?;
    let id2 = ensure_identity(&conn, pubkey, 2).await?;
    assert_eq!(id1.signer_id(), id2.signer_id());

    Ok(())
}

#[tokio::test]
async fn test_create_core_signer_idempotent() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_block(&conn, 0).await?;

    let id1 = create_core_signer(&conn).await?;
    let id2 = create_core_signer(&conn).await?;
    assert_eq!(id1, id2);

    Ok(())
}

#[tokio::test]
async fn test_create_contract_signer_assigns_unique_ids() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_block(&conn, 1).await?;

    let id1 = create_contract_signer(&conn, 1).await?;
    let id2 = create_contract_signer(&conn, 1).await?;
    assert_ne!(id1, id2);

    Ok(())
}

#[tokio::test]
async fn test_advance_nonce() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_block(&conn, 1).await?;
    setup_block(&conn, 2).await?;

    let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
    let row = ensure_identity(&conn, pubkey, 1).await?;

    let next = row.advance_nonce(&conn, 0, 1).await?;
    assert_eq!(next, 1);

    let next = row.advance_nonce(&conn, 1, 2).await?;
    assert_eq!(next, 2);

    Ok(())
}

#[tokio::test]
async fn test_advance_nonce_gap() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_block(&conn, 1).await?;

    let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
    let row = ensure_identity(&conn, pubkey, 1).await?;

    let next = row.advance_nonce(&conn, 5, 1).await?;
    assert_eq!(next, 6);

    // Gap beyond MAX_NONCE_GAP is rejected
    let result = row.advance_nonce(&conn, 20_000, 1).await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_advance_nonce_replay_rejected() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_block(&conn, 1).await?;
    setup_block(&conn, 2).await?;

    let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
    let row = ensure_identity(&conn, pubkey, 1).await?;

    row.advance_nonce(&conn, 0, 1).await?;
    let result = row.advance_nonce(&conn, 0, 2).await;
    assert!(result.is_err());

    Ok(())
}

#[tokio::test]
async fn test_register_bls_key() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_block(&conn, 1).await?;

    let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
    let row = ensure_identity(&conn, pubkey, 1).await?;

    let bls_key = vec![1u8; 48];
    row.register_bls_key(&conn, &bls_key, 1).await?;

    let entry = get_signer_entry_by_x_only_pubkey(&conn, pubkey)
        .await?
        .unwrap();
    assert_eq!(entry.bls_pubkey, Some(bls_key));

    Ok(())
}

#[tokio::test]
async fn test_get_signer_entry_by_x_only_pubkey() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_block(&conn, 1).await?;

    let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
    let row = ensure_identity(&conn, pubkey, 1).await?;

    let entry = get_signer_entry_by_x_only_pubkey(&conn, pubkey)
        .await?
        .unwrap();
    assert_eq!(entry.signer_id, row.signer_id());
    assert_eq!(entry.x_only_pubkey.as_deref(), Some(pubkey));
    assert_eq!(entry.bls_pubkey, None);
    assert_eq!(entry.next_nonce, Some(0));

    Ok(())
}

#[tokio::test]
async fn test_get_signer_entry_by_id() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_block(&conn, 1).await?;

    let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
    let row = ensure_identity(&conn, pubkey, 1).await?;

    let entry = get_signer_entry_by_id(&conn, row.signer_id())
        .await?
        .unwrap();
    assert_eq!(entry.x_only_pubkey.as_deref(), Some(pubkey));
    assert_eq!(entry.next_nonce, Some(0));

    Ok(())
}

#[tokio::test]
async fn test_get_signer_entry_by_bls_pubkey() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_block(&conn, 1).await?;

    let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
    let row = ensure_identity(&conn, pubkey, 1).await?;
    let bls_key = vec![7u8; 48];
    row.register_bls_key(&conn, &bls_key, 1).await?;

    let entry = get_signer_entry_by_bls_pubkey(&conn, &bls_key)
        .await?
        .unwrap();
    assert_eq!(entry.signer_id, row.signer_id());
    assert_eq!(entry.bls_pubkey, Some(bls_key));

    let missing = get_signer_entry_by_bls_pubkey(&conn, &[0u8; 48]).await?;
    assert!(missing.is_none());

    Ok(())
}

#[tokio::test]
async fn test_get_signer_entry_core_and_contract() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_block(&conn, 0).await?;
    setup_block(&conn, 1).await?;

    let core_id = create_core_signer(&conn).await?;
    let core = get_signer_entry_by_id(&conn, core_id).await?.unwrap();
    assert_eq!(core.x_only_pubkey, None);
    assert_eq!(core.bls_pubkey, None);
    assert_eq!(core.next_nonce, None);

    let contract_id = create_contract_signer(&conn, 1).await?;
    let contract = get_signer_entry_by_id(&conn, contract_id).await?.unwrap();
    assert_eq!(contract.x_only_pubkey, None);
    assert_eq!(contract.bls_pubkey, None);
    assert_eq!(contract.next_nonce, None);

    Ok(())
}

#[tokio::test]
async fn test_signer_rollback() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_block(&conn, 1).await?;
    setup_block(&conn, 2).await?;
    setup_block(&conn, 3).await?;

    let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
    let row = ensure_identity(&conn, pubkey, 1).await?;
    row.advance_nonce(&conn, 0, 2).await?;
    row.register_bls_key(&conn, &[1u8; 48], 3).await?;

    // Rollback to height 2 — should remove bls_key (height 3) but keep nonce (height 2)
    rollback_to_height(&conn, 2).await?;

    let entry = get_signer_entry_by_x_only_pubkey(&conn, pubkey)
        .await?
        .unwrap();
    assert_eq!(entry.bls_pubkey, None);
    assert_eq!(entry.next_nonce, Some(1));

    // Rollback to height 0 — should remove everything
    rollback_to_height(&conn, 0).await?;
    let entry = get_signer_entry_by_x_only_pubkey(&conn, pubkey).await?;
    assert!(entry.is_none());

    Ok(())
}

#[tokio::test]
async fn test_identity_dao() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_block(&conn, 1).await?;

    let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
    let identity = ensure_identity(&conn, pubkey, 1).await?;

    assert_eq!(identity.x_only_pubkey(&conn).await?, pubkey);
    assert_eq!(identity.bls_pubkey(&conn).await?, None);
    assert_eq!(identity.next_nonce(&conn).await?, 0);

    let bls_key = vec![1u8; 48];
    identity.register_bls_key(&conn, &bls_key, 1).await?;
    assert_eq!(identity.bls_pubkey(&conn).await?, Some(bls_key));

    identity.advance_nonce(&conn, 0, 1).await?;
    assert_eq!(identity.next_nonce(&conn).await?, 1);

    Ok(())
}

#[tokio::test]
async fn test_ensure_identity_idempotent() -> Result<()> {
    let (_, writer, _temp_dir) = new_test_db().await?;
    let conn = writer.connection();
    setup_block(&conn, 1).await?;
    setup_block(&conn, 2).await?;

    let pubkey = "aabbccdd00112233aabbccdd00112233aabbccdd00112233aabbccdd00112233";
    let id1 = ensure_identity(&conn, pubkey, 1).await?;
    let id2 = ensure_identity(&conn, pubkey, 2).await?;
    assert_eq!(id1.signer_id(), id2.signer_id());

    Ok(())
}
